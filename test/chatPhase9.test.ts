import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ChatController, resetChatControllerForTests } from '../src/realtime/ChatController';
import { WebSocketController } from '../src/realtime/WebSocketController';
import type { WebSocketFactory, WebSocketLike } from '../src/realtime/WebSocketClient';
import type { InboundEnvelope } from '../src/realtime/types';
import { newMessageId } from '../src/realtime/messageId';
import { encodeBase64Url } from '../src/crypto/base64url';

// ---------------------------------------------------------------------------
// Fakes (same shape as chatController.test.ts so behaviour is comparable)
// ---------------------------------------------------------------------------

class FakeSocket implements WebSocketLike {
  public readyState = 0;
  public sentFrames: string[] = [];
  public onopen: ((ev: Event) => void) | null = null;
  public onclose: ((ev: { code: number; reason: string }) => void) | null = null;
  public onerror: ((ev: Event) => void) | null = null;
  public onmessage: ((ev: { data: string }) => void) | null = null;
  constructor(public readonly url: string) {}
  send(data: string): void { this.sentFrames.push(data); }
  close(code = 1000, reason = ''): void { this.readyState = 3; this.onclose?.({ code, reason }); }
  _open(): void { this.readyState = 1; this.onopen?.(new Event('open')); }
  _receive(raw: string): void { this.onmessage?.({ data: raw }); }
  _close(code: number, reason: string): void { this.close(code, reason); }
}

function makeWsFactory() {
  const sockets: FakeSocket[] = [];
  return {
    factory: { create: (url: string) => { const s = new FakeSocket(url); sockets.push(s); return s; } } as WebSocketFactory,
    all: () => sockets.slice() as FakeSocket[],
    last: () => { const s = sockets[sockets.length - 1]; if (!s) throw new Error('no socket'); return s; },
  };
}

type AuthSnap = { authenticated: boolean; userId: string | null; identity: { kind: 'none' | 'locked' | 'unlocked' } };
type AuthListener = (snap: AuthSnap) => void;

function makeAuthStub(initial: { token: string | null; userId: string | null; identityKind?: AuthSnap['identity']['kind'] }) {
  let token = initial.token;
  let userId = initial.userId;
  let identityKind: AuthSnap['identity']['kind'] = initial.identityKind ?? (token ? 'unlocked' : 'none');
  const listeners = new Set<AuthListener>();
  const snap = (): AuthSnap => ({ authenticated: token !== null, userId, identity: { kind: identityKind } });
  return {
    getToken: () => token,
    getUserId: () => userId,
    getUnlockedIdentity: () => null as unknown as null,
    subscribe(listener: AuthListener) { listeners.add(listener); listener(snap()); return () => listeners.delete(listener); },
    setToken(next: string | null, nextUserId: string | null = userId) {
      token = next; userId = nextUserId;
      const s = snap(); for (const l of listeners) l(s);
    },
    setIdentityKind(kind: AuthSnap['identity']['kind']) {
      identityKind = kind;
      const s = snap(); for (const l of listeners) l(s);
    },
    _snap: snap,
  };
}

function makeController(opts?: { auth?: ReturnType<typeof makeAuthStub> }) {
  const auth = opts?.auth ?? makeAuthStub({ token: 'jwt', userId: 'alice', identityKind: 'unlocked' });
  const f = makeWsFactory();
  const ws = new WebSocketController({
    authController: auth as unknown as ConstructorParameters<typeof WebSocketController>[0]['authController'],
    url: 'wss://x/ws',
    factory: f.factory,
  });
  ws.connect();
  const ctrl = new ChatController({
    authController: auth as unknown as ConstructorParameters<typeof ChatController>[0]['authController'],
    webSocketController: ws,
  });
  // open the fake socket
  const s = f.all()[0]!; s._open();
  return { ctrl, ws, auth, sockets: f, socket: s };
}

function stubSession(overrides: Partial<{ encryptMessage: (pt: Uint8Array) => Promise<Uint8Array>; decryptMessage: (wire: Uint8Array) => Promise<Uint8Array>; wipe: () => void }> = {}) {
  return {
    encryptMessage: async (pt: Uint8Array) => {
      const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, pt);
      return new Uint8Array(ct);
    },
    decryptMessage: async () => new TextEncoder().encode('decrypted'),
    wipe: vi.fn(),
    ...overrides,
  };
}

function injectConversation(ctrl: ChatController, peer: string, session: unknown, extra?: Partial<{ messages: unknown[] }>) {
  (ctrl as unknown as { conversations: Map<string, unknown> }).conversations.set(peer, {
    peerUserId: peer,
    session,
    sessionState: { kind: 'ready', role: 'initiator' },
    messages: [],
    lastActivityAt: Date.now(),
    initiating: false,
    sending: false,
    ...extra,
  });
}

afterEach(() => resetChatControllerForTests());

// ---------------------------------------------------------------------------
// Phase 9 tests
// ---------------------------------------------------------------------------

describe('Phase 9: multiple conversations', () => {
  it('handles multiple peers cleanly with isolated message stores', async () => {
    const { ctrl, socket } = makeController();
    const sBob = stubSession();
    const sChar = stubSession();
    injectConversation(ctrl, 'bob', sBob);
    injectConversation(ctrl, 'charlie', sChar);
    socket.sentFrames.length = 0;

    const m1 = await ctrl.sendText('bob', 'hello bob');
    const m2 = await ctrl.sendText('charlie', 'hello charlie');

    expect(m1.plaintext).toBe('hello bob');
    expect(m2.plaintext).toBe('hello charlie');

    const snap = ctrl.getSnapshot();
    expect(snap.conversations.length).toBe(2);
    const bob = snap.conversations.find((c) => c.peerUserId === 'bob')!;
    const charlie = snap.conversations.find((c) => c.peerUserId === 'charlie')!;
    expect(bob.messages.length).toBe(1);
    expect(charlie.messages.length).toBe(1);
    expect(bob.messages[0]!.plaintext).toBe('hello bob');
    expect(charlie.messages[0]!.plaintext).toBe('hello charlie');
    // transport never saw plaintext
    for (const f of socket.sentFrames) {
      expect(f).not.toContain('hello bob');
      expect(f).not.toContain('hello charlie');
    }
    ctrl.dispose();
  });
});

describe('Phase 9: conversation switching does not destroy sessions', () => {
  it('switching active conversation does not clear unrelated sessions', async () => {
    const { ctrl } = makeController();
    const sBob = stubSession();
    const sChar = stubSession();
    injectConversation(ctrl, 'bob', sBob);
    injectConversation(ctrl, 'charlie', sChar);

    await ctrl.sendText('bob', 'msg1');
    // Simulate "switch" by reading snapshot for charlie - should not affect bob
    const before = ctrl.getSnapshot().find ?? null;
    void before;
    const snap = ctrl.getSnapshot();
    expect(snap.conversations.find((c) => c.peerUserId === 'bob')!.messages.length).toBe(1);
    expect(snap.conversations.find((c) => c.peerUserId === 'charlie')!.messages.length).toBe(0);
    // charlie session still present
    expect(snap.conversations.find((c) => c.peerUserId === 'charlie')!.session.kind).toBe('ready');
    ctrl.dispose();
  });
});

describe('Phase 9: per-peer session isolation', () => {
  it('decrypt failure in one conversation does not affect the other', async () => {
    const { ctrl, socket } = makeController();
    const sBob = stubSession({
      decryptMessage: async () => { throw Object.assign(new Error('bad'), { code: 'auth_failed' }); },
    });
    const sChar = stubSession();
    injectConversation(ctrl, 'bob', sBob);
    injectConversation(ctrl, 'charlie', sChar);

    const envBob: InboundEnvelope = { version: 1, id: newMessageId(), type: 'text', sender: 'bob', recipient: 'alice', timestamp: Date.now(), data: encodeBase64Url(new Uint8Array([1,2,3])) };
    socket._receive(JSON.stringify(envBob));
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));

    const snap = ctrl.getSnapshot();
    const bob = snap.conversations.find((c) => c.peerUserId === 'bob')!;
    const charlie = snap.conversations.find((c) => c.peerUserId === 'charlie')!;
    expect(bob.session.kind).toBe('error');
    expect(charlie.session.kind).toBe('ready');
    expect(bob.messages.length).toBe(0);
    ctrl.dispose();
  });
});

describe('Phase 9: outgoing message state', () => {
  it('empty and whitespace-only messages are rejected', async () => {
    const { ctrl } = makeController();
    injectConversation(ctrl, 'bob', stubSession());
    await expect(ctrl.sendText('bob', '')).rejects.toMatchObject({ code: 'send_failed' });
    await expect(ctrl.sendText('bob', '   ')).rejects.toMatchObject({ code: 'send_failed' });
    const snap = ctrl.getSnapshot();
    expect(snap.conversations.find((c) => c.peerUserId === 'bob')!.messages.length).toBe(0);
    ctrl.dispose();
  });

  it('failed encryption results in failed status and no transport send', async () => {
    const { ctrl, socket } = makeController();
    const s = stubSession({ encryptMessage: async () => { throw new Error('encrypt boom'); } });
    injectConversation(ctrl, 'bob', s);
    socket.sentFrames.length = 0;
    const msg = await ctrl.sendText('bob', 'hello');
    expect(msg.status).toBe('failed');
    // no text frame was sent
    const textFrames = socket.sentFrames.map((f) => JSON.parse(f)).filter((j: { type: string }) => j.type === 'text');
    expect(textFrames.length).toBe(0);
    const snap = ctrl.getSnapshot();
    expect(snap.conversations.find((c) => c.peerUserId === 'bob')!.messages[0]!.status).toBe('failed');
    ctrl.dispose();
  });

  it('prevents double-send while a send is in flight', async () => {
    const { ctrl } = makeController();
    let resolveEncrypt!: (v: Uint8Array) => void;
    const s = stubSession({
      encryptMessage: () => new Promise<Uint8Array>((res) => { resolveEncrypt = res; }),
    });
    injectConversation(ctrl, 'bob', s);
    const p1 = ctrl.sendText('bob', 'first');
    // Second immediate send should be rejected with sending guard
    await expect(ctrl.sendText('bob', 'second')).rejects.toMatchObject({ code: 'send_failed' });
    // Resolve first
    resolveEncrypt(new Uint8Array([1,2,3]));
    const m1 = await p1;
    expect(m1.status).toBe('sent');
    ctrl.dispose();
  });
});

describe('Phase 9: incoming message flows', () => {
  it('delivers to active and inactive conversations without losing', async () => {
    const { ctrl, socket } = makeController();
    injectConversation(ctrl, 'bob', stubSession());
    injectConversation(ctrl, 'charlie', stubSession());

    // Inactive conversation (charlie) receives a message
    const env: InboundEnvelope = { version: 1, id: newMessageId(), type: 'text', sender: 'charlie', recipient: 'alice', timestamp: Date.now(), data: encodeBase64Url(new Uint8Array([9,9,9])) };
    // stub charlie decrypt to return a known plaintext
    const charSess = (ctrl as unknown as { conversations: Map<string, { session: { decryptMessage: unknown } }> }).conversations.get('charlie')!.session as { decryptMessage: unknown };
    (charSess as { decryptMessage: (w: Uint8Array) => Promise<Uint8Array> }).decryptMessage = async () => new TextEncoder().encode('hi from charlie');

    socket._receive(JSON.stringify(env));
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));

    const snap = ctrl.getSnapshot();
    expect(snap.conversations.find((c) => c.peerUserId === 'charlie')!.messages.length).toBe(1);
    expect(snap.conversations.find((c) => c.peerUserId === 'charlie')!.messages[0]!.plaintext).toBe('hi from charlie');
    // bob unaffected
    expect(snap.conversations.find((c) => c.peerUserId === 'bob')!.messages.length).toBe(0);
    ctrl.dispose();
  });

  it('creates conversation for unknown sender on inbound', async () => {
    const { ctrl, socket } = makeController();
    // No prior conversation for dave, but we have no session, so it should create with error state
    const env: InboundEnvelope = { version: 1, id: newMessageId(), type: 'text', sender: 'dave', recipient: 'alice', timestamp: Date.now(), data: encodeBase64Url(new Uint8Array([1])) };
    socket._receive(JSON.stringify(env));
    await new Promise((r) => setImmediate(r));
    const snap = ctrl.getSnapshot();
    const dave = snap.conversations.find((c) => c.peerUserId === 'dave');
    expect(dave).toBeDefined();
    expect(dave!.messages.length).toBe(0);
    expect(dave!.session.kind).toBe('error');
    ctrl.dispose();
  });
});

describe('Phase 9: duplicate envelope protection', () => {
  it('drops duplicate envelope ids at application layer', async () => {
    const { ctrl, socket } = makeController();
    const s = stubSession();
    let decryptCalls = 0;
    (s as { decryptMessage: (w: Uint8Array) => Promise<Uint8Array> }).decryptMessage = async () => { decryptCalls += 1; return new TextEncoder().encode('once'); };
    injectConversation(ctrl, 'bob', s);
    const id = newMessageId();
    const env: InboundEnvelope = { version: 1, id, type: 'text', sender: 'bob', recipient: 'alice', timestamp: Date.now(), data: encodeBase64Url(new Uint8Array([5])) };
    socket._receive(JSON.stringify(env));
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
    // Duplicate with same id
    socket._receive(JSON.stringify({ ...env, timestamp: Date.now() + 1 }));
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
    expect(decryptCalls).toBe(1);
    const snap = ctrl.getSnapshot();
    expect(snap.conversations.find((c) => c.peerUserId === 'bob')!.messages.length).toBe(1);
    ctrl.dispose();
  });

  it('does not treat different ids as duplicates', async () => {
    const { ctrl, socket } = makeController();
    const s = stubSession();
    let decryptCalls = 0;
    (s as { decryptMessage: (w: Uint8Array) => Promise<Uint8Array> }).decryptMessage = async () => { decryptCalls += 1; return new TextEncoder().encode('msg'); };
    injectConversation(ctrl, 'bob', s);
    for (let i = 0; i < 2; i++) {
      const env: InboundEnvelope = { version: 1, id: newMessageId(), type: 'text', sender: 'bob', recipient: 'alice', timestamp: Date.now(), data: encodeBase64Url(new Uint8Array([7])) };
      socket._receive(JSON.stringify(env));
      await new Promise((r) => setImmediate(r));
      await new Promise((r) => setImmediate(r));
    }
    expect(decryptCalls).toBe(2);
    expect(ctrl.getSnapshot().find ? true : ctrl.getSnapshot().conversations.find((c) => c.peerUserId === 'bob')!.messages.length === 2).toBe(true);
    ctrl.dispose();
  });
});

describe('Phase 9: missing session and session reuse', () => {
  it('missing session: incoming text records error without crashing', async () => {
    const { ctrl, socket } = makeController();
    // No conversation at all
    const env: InboundEnvelope = { version: 1, id: newMessageId(), type: 'text', sender: 'erin', recipient: 'alice', timestamp: Date.now(), data: encodeBase64Url(new Uint8Array([1])) };
    socket._receive(JSON.stringify(env));
    await new Promise((r) => setImmediate(r));
    const snap = ctrl.getSnapshot();
    expect(snap.conversations.find((c) => c.peerUserId === 'erin')!.session.kind).toBe('error');
    ctrl.dispose();
  });

  it('session reuse: second openConversation when ready does not re-initiate', async () => {
    const { ctrl } = makeController();
    const s = stubSession();
    injectConversation(ctrl, 'bob', s);
    // openConversation should early-return when session already ready
    await expect(ctrl.openConversation('bob')).resolves.toBeUndefined();
    const snap = ctrl.getSnapshot();
    expect(snap.conversations.find((c) => c.peerUserId === 'bob')!.session.kind).toBe('ready');
    ctrl.dispose();
  });

  it('closeConversation wipes and removes without affecting others', async () => {
    const { ctrl } = makeController();
    const sBob = stubSession();
    const sChar = stubSession();
    injectConversation(ctrl, 'bob', sBob);
    injectConversation(ctrl, 'charlie', sChar);
    ctrl.closeConversation('bob');
    expect(sBob.wipe).toHaveBeenCalled();
    const snap = ctrl.getSnapshot();
    expect(snap.conversations.find((c) => c.peerUserId === 'bob')).toBeUndefined();
    expect(snap.conversations.find((c) => c.peerUserId === 'charlie')).toBeDefined();
    ctrl.dispose();
  });
});

describe('Phase 9: logout and identity lock clear', () => {
  it('logout clears all conversations and wipes sessions', async () => {
    const { ctrl, auth } = makeController();
    const s1 = stubSession();
    const s2 = stubSession();
    injectConversation(ctrl, 'bob', s1);
    injectConversation(ctrl, 'charlie', s2);
    expect(ctrl.getSnapshot().conversations.length).toBe(2);
    auth.setToken(null, null);
    await new Promise((r) => setImmediate(r));
    expect(ctrl.getSnapshot().conversations.length).toBe(0);
    expect(s1.wipe).toHaveBeenCalled();
    expect(s2.wipe).toHaveBeenCalled();
    // Navigating back must not expose old messages
    expect(ctrl.getSnapshot().conversations.find((c) => c.peerUserId === 'bob')).toBeUndefined();
    ctrl.dispose();
  });

  it('identity lock clears all conversations and wipes sessions', async () => {
    const auth = makeAuthStub({ token: 'jwt', userId: 'alice', identityKind: 'unlocked' });
    const { ctrl } = makeController({ auth });
    const s1 = stubSession();
    injectConversation(ctrl, 'bob', s1);
    expect(ctrl.getSnapshot().conversations.length).toBe(1);
    auth.setIdentityKind('locked');
    await new Promise((r) => setImmediate(r));
    expect(ctrl.getSnapshot().conversations.length).toBe(0);
    expect(s1.wipe).toHaveBeenCalled();
    ctrl.dispose();
  });

  it('WebSocket disconnects on identity lock', async () => {
    const auth = makeAuthStub({ token: 'jwt', userId: 'alice', identityKind: 'unlocked' });
    const { ws } = makeController({ auth });
    expect(ws.state).toBe('open');
    auth.setIdentityKind('locked');
    await new Promise((r) => setImmediate(r));
    expect(ws.state).toBe('closed');
    ws.dispose();
  });

  it('WebSocket does not reconnect after logout', async () => {
    const auth = makeAuthStub({ token: 'jwt', userId: 'alice', identityKind: 'unlocked' });
    const { ws } = makeController({ auth });
    expect(ws.state).toBe('open');
    auth.setToken(null, null);
    await new Promise((r) => setImmediate(r));
    expect(ws.state).toBe('closed');
    // Even if we wait, no reconnect should happen for 4001/logout paths
    await new Promise((r) => setTimeout(r, 20));
    expect(ws.state).toBe('closed');
    ws.dispose();
  });
});

describe('Phase 9: WebSocket reconnect does not duplicate', () => {
  it('does not duplicate listeners after reconnect', async () => {
    const auth = makeAuthStub({ token: 'jwt', userId: 'alice', identityKind: 'unlocked' });
    const f = makeWsFactory();
    const ws = new WebSocketController({
      authController: auth as unknown as ConstructorParameters<typeof WebSocketController>[0]['authController'],
      url: 'wss://x/ws',
      factory: f.factory,
    });
    const ctrl = new ChatController({
      authController: auth as unknown as ConstructorParameters<typeof ChatController>[0]['authController'],
      webSocketController: ws,
    });
    ws.connect();
    const s0 = f.all()[0]!; s0._open();
    const s = stubSession();
    injectConversation(ctrl, 'bob', s);
    let calls = 0;
    (s as { decryptMessage: (w: Uint8Array) => Promise<Uint8Array> }).decryptMessage = async () => { calls += 1; return new TextEncoder().encode('x'); };

    // Simulate disconnect + reconnect: close with retryable code (1013), ws will schedule reconnect
    // For deterministic test, manually trigger a new client by calling ws.connect after close
    s0._close(1013, 'capacity');
    await new Promise((r) => setTimeout(r, 15));
    // If still closed, force reconnect
    if (ws.state === 'closed') ws.connect();
    await new Promise((r) => setTimeout(r, 5));
    const s1 = f.all()[f.all().length - 1]!; if (s1.readyState !== 1) s1._open();

    const env: InboundEnvelope = { version: 1, id: newMessageId(), type: 'text', sender: 'bob', recipient: 'alice', timestamp: Date.now(), data: encodeBase64Url(new Uint8Array([1])) };
    s1._receive(JSON.stringify(env));
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
    expect(calls).toBe(1);
    ctrl.dispose(); ws.dispose();
  });

  it('does not duplicate messages after reconnect (dedup covers it)', async () => {
    const { ctrl, socket } = makeController();
    const s = stubSession();
    let calls = 0;
    (s as { decryptMessage: (w: Uint8Array) => Promise<Uint8Array> }).decryptMessage = async () => { calls += 1; return new TextEncoder().encode('y'); };
    injectConversation(ctrl, 'bob', s);
    const id = newMessageId();
    const env: InboundEnvelope = { version: 1, id, type: 'text', sender: 'bob', recipient: 'alice', timestamp: Date.now(), data: encodeBase64Url(new Uint8Array([2])) };
    socket._receive(JSON.stringify(env));
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
    // Same id after "reconnect"
    socket._receive(JSON.stringify(env));
    await new Promise((r) => setImmediate(r));
    expect(calls).toBe(1);
    expect(ctrl.getSnapshot().conversations.find((c) => c.peerUserId === 'bob')!.messages.length).toBe(1);
    ctrl.dispose();
  });
});

describe('Phase 9: empty / loading / error states', () => {
  it('empty conversation state is well-formed', () => {
    const { ctrl } = makeController();
    const snap = ctrl.getSnapshot();
    expect(snap.conversations).toEqual([]);
    expect(snap.selfUserId).toBe('alice');
    expect(snap.connected).toBe(true);
    ctrl.dispose();
  });

  it('unauthenticated snapshot hides conversations', () => {
    const auth = makeAuthStub({ token: null, userId: null, identityKind: 'none' });
    const f = makeWsFactory();
    const ws = new WebSocketController({
      authController: auth as unknown as ConstructorParameters<typeof WebSocketController>[0]['authController'],
      url: 'wss://x/ws',
      factory: f.factory,
    });
    const ctrl = new ChatController({
      authController: auth as unknown as ConstructorParameters<typeof ChatController>[0]['authController'],
      webSocketController: ws,
    });
    const s = stubSession();
    injectConversation(ctrl, 'bob', s);
    const snap = ctrl.getSnapshot();
    expect(snap.conversations).toEqual([]);
    expect(snap.selfUserId).toBeNull();
    ctrl.dispose();
    ws.dispose();
  });

  it('connection error state: WebSocket closed reflects in snapshot', async () => {
    const { ctrl, ws, socket } = makeController();
    expect(ctrl.getSnapshot().connected).toBe(true);
    // Close underlying socket with non-retryable
    socket._close(4001, 'auth');
    await new Promise((r) => setTimeout(r, 10));
    expect(ws.state).toBe('closed');
    expect(ctrl.getSnapshot().connected).toBe(false);
    ctrl.dispose(); ws.dispose();
  });

  it('authentication expiry clears sessions (401 path)', async () => {
    const { ctrl, auth } = makeController();
    injectConversation(ctrl, 'bob', stubSession());
    // Simulate 401 handler clearing token
    auth.setToken(null, null);
    await new Promise((r) => setImmediate(r));
    expect(ctrl.getSnapshot().conversations.length).toBe(0);
    ctrl.dispose();
  });

  it('invalid envelope is dropped without crashing', async () => {
    const { ctrl, socket } = makeController();
    injectConversation(ctrl, 'bob', stubSession());
    // Send something that is not valid JSON
    socket._receive('not json at all');
    await new Promise((r) => setImmediate(r));
    expect(ctrl.getSnapshot().conversations.find((c) => c.peerUserId === 'bob')!.messages.length).toBe(0);
    // Unsupported type should be ignored
    const env = { version: 1, id: newMessageId(), type: 'unknown_type', sender: 'bob', recipient: 'alice', timestamp: Date.now(), data: 'x' };
    socket._receive(JSON.stringify(env));
    await new Promise((r) => setImmediate(r));
    expect(ctrl.getSnapshot().conversations.find((c) => c.peerUserId === 'bob')!.messages.length).toBe(0);
    ctrl.dispose();
  });
});

describe('Phase 9: no plaintext persistence or transport', () => {
  it('does not persist plaintext in storage', async () => {
    const { ctrl } = makeController();
    const s = stubSession();
    injectConversation(ctrl, 'bob', s);
    const plaintext = 'super-secret-plaintext-' + Math.random().toString(36);
    await ctrl.sendText('bob', plaintext);
    // Check storages
    const storages: Array<Storage | null> = [];
    try { storages.push(window.localStorage); } catch { storages.push(null); }
    try { storages.push(window.sessionStorage); } catch { storages.push(null); }
    for (const st of storages) {
      if (!st) continue;
      for (let i = 0; i < st.length; i++) {
        const k = st.key(i); if (!k) continue;
        const v = st.getItem(k) ?? '';
        expect(v).not.toContain(plaintext);
      }
    }
    // IndexedDB is not checked directly here (would require idb), but plaintext
    // must not be stored there either by construction: ChatController never
    // writes to idb.
    ctrl.dispose();
  });

  it('transport never carries plaintext', async () => {
    const { ctrl, socket } = makeController();
    const s = stubSession();
    injectConversation(ctrl, 'bob', s);
    socket.sentFrames.length = 0;
    const plaintext = 'plaintext-should-not-appear-' + Date.now();
    await ctrl.sendText('bob', plaintext);
    const all = socket.sentFrames.join('\n');
    expect(all).not.toContain(plaintext);
    // Each frame's data field is opaque base64url, not plaintext
    for (const f of socket.sentFrames) {
      const parsed = JSON.parse(f) as { data?: string };
      if (parsed.data) expect(parsed.data).not.toContain(plaintext);
    }
    ctrl.dispose();
  });

  it('failed decryption never renders ciphertext as plaintext', async () => {
    const { ctrl, socket } = makeController();
    const s = stubSession({ decryptMessage: async () => { throw Object.assign(new Error('fail'), { code: 'auth_failed' }); } });
    injectConversation(ctrl, 'bob', s);
    const env: InboundEnvelope = { version: 1, id: newMessageId(), type: 'text', sender: 'bob', recipient: 'alice', timestamp: Date.now(), data: encodeBase64Url(new Uint8Array([0xFF, 0xFE])) };
    socket._receive(JSON.stringify(env));
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
    const snap = ctrl.getSnapshot();
    const msgs = snap.conversations.find((c) => c.peerUserId === 'bob')!.messages;
    expect(msgs.length).toBe(0);
    // No message should contain the raw data
    for (const m of msgs) expect(m.plaintext).not.toContain('FFFE');
    ctrl.dispose();
  });

  it('conversation switching does not leak plaintext into another peer', async () => {
    const { ctrl } = makeController();
    const sBob = stubSession();
    const sChar = stubSession();
    injectConversation(ctrl, 'bob', sBob);
    injectConversation(ctrl, 'charlie', sChar);
    await ctrl.sendText('bob', 'secret for bob only');
    const snap = ctrl.getSnapshot();
    const charMsgs = snap.conversations.find((c) => c.peerUserId === 'charlie')!.messages;
    expect(charMsgs.length).toBe(0);
    for (const m of charMsgs) expect(m.plaintext).not.toContain('secret for bob');
    ctrl.dispose();
  });
});

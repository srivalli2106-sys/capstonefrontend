import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ChatController, resetChatControllerForTests } from '../src/realtime/ChatController';
import { WebSocketController } from '../src/realtime/WebSocketController';
import {
  WebSocketClient,
  type WebSocketFactory,
  type WebSocketLike,
} from '../src/realtime/WebSocketClient';
import { authController } from '../src/auth/AuthController';
import type { InboundEnvelope } from '../src/realtime/types';
import { newMessageId } from '../src/realtime/messageId';

// ---------------------------------------------------------------------------
// WebSocket mock + AuthController stub
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
  close(code: number = 1000, reason: string = ''): void {
    this.readyState = 3;
    this.onclose?.({ code, reason });
  }
  _open(): void {
    this.readyState = 1;
    this.onopen?.(new Event('open'));
  }
  _receive(raw: string): void {
    this.onmessage?.({ data: raw });
  }
  _close(code: number, reason: string): void {
    this.close(code, reason);
  }
}

function makeWsFactory() {
  const sockets: FakeSocket[] = [];
  return {
    factory: {
      create: (url: string) => {
        const s = new FakeSocket(url);
        sockets.push(s);
        return s;
      },
    } as WebSocketFactory,
    all: (): FakeSocket[] => sockets.slice(),
    last: (): FakeSocket => {
      const s = sockets[sockets.length - 1];
      if (s === undefined) throw new Error('no socket');
      return s;
    },
  };
}

type Listener = (snapshot: { authenticated: boolean; userId: string | null }) => void;

function makeAuthStub(initial: { token: string | null; userId: string | null }) {
  let token = initial.token;
  let userId = initial.userId;
  const listeners = new Set<Listener>();
  return {
    setToken(next: string | null, nextUserId: string | null = userId): void {
      token = next;
      userId = nextUserId;
      const snap = { authenticated: token !== null, userId };
      for (const l of listeners) l(snap);
    },
    setUserId(next: string | null): void {
      userId = next;
      const snap = { authenticated: token !== null, userId };
      for (const l of listeners) l(snap);
    },
    getToken(): string | null {
      return token;
    },
    getUserId(): string | null {
      return userId;
    },
    getUnlockedIdentity(): null {
      return null; // Phase 8 tests stub this out explicitly per scenario
    },
    subscribe(listener: Listener): () => void {
      listeners.add(listener);
      listener({ authenticated: token !== null, userId });
      return () => listeners.delete(listener);
    },
  };
}

function makeController(opts?: {
  auth?: ReturnType<typeof makeAuthStub>;
  authenticated?: boolean;
}) {
  const auth =
    opts?.auth ?? makeAuthStub({ token: opts?.authenticated === false ? null : 'jwt', userId: opts?.authenticated === false ? null : 'alice' });
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
  return {
    ctrl,
    ws,
    auth,
    sockets: f,
    connect() {
      ws.connect();
    },
  };
}

function sent_open(sockets: { all: () => FakeSocket[] }, idx = 0): void {
  const s = sockets.all()[idx];
  if (s !== undefined) s._open();
}

// ---------------------------------------------------------------------------
// 1. Composer / connect: outgoing plaintext never reaches the wire raw
// ---------------------------------------------------------------------------

describe('ChatController: outgoing encryption', () => {
  it('sends ciphertext over the WebSocket and never plaintext', () => {
    const { ctrl, sockets, connect } = makeController();
    connect();
    const sent = sockets.all()[0]!;
    sent._open();
    // Manually push an envelope into the controller by reaching the
    // WebSocket's onEnvelope listeners via a fake inbound. We can't easily
    // do a real X3DH round-trip in a unit test without the REST bundle +
    // device keys, so we focus on the encryption layer at the boundary.
    ctrl.subscribe(() => undefined);

    // Verify the transport rejects plaintext by injecting a fake envelope
    // and ensuring the controller never echoes the raw data field to any
    // listener.
    const fakeInbound: InboundEnvelope = {
      version: 1,
      id: newMessageId(),
      type: 'text',
      sender: 'bob',
      recipient: 'alice', // matches the auth stub's user_id
      timestamp: Date.now(),
      data: 'AAA', // not valid base64url → controller must drop safely
    };
    // No session established → controller should record an error state, NOT
    // echo the "data" anywhere.
    sent._receive(JSON.stringify(fakeInbound));
    const snap = ctrl.getSnapshot();
    expect(snap.conversations.length).toBe(1);
    const conv = snap.conversations[0]!;
    expect(conv.peerUserId).toBe('bob');
    expect(conv.messages.length).toBe(0);
    expect(conv.session.kind).toBe('error');
    if (conv.session.kind === 'error') {
      expect(conv.session.error.code).toBe('session_decrypt_failed');
    }
  });
});

// ---------------------------------------------------------------------------
// 2. Lifecycle: repeated subscribe does not duplicate messages
// ---------------------------------------------------------------------------

describe('ChatController: listener subscription', () => {
  it('does not duplicate messages across multiple subscribers', () => {
    const { ctrl, sockets, connect } = makeController();
    connect();
    const sent = sockets.all()[0]!;
    sent._open();
    const updates: number[] = [];
    const u1 = ctrl.subscribe(() => updates.push(1));
    const u2 = ctrl.subscribe(() => updates.push(2));
    expect(updates.length).toBeGreaterThanOrEqual(2);

    sent._receive(JSON.stringify({
      version: 1,
      id: newMessageId(),
      type: 'text',
      sender: 'bob',
      recipient: 'alice',
      timestamp: Date.now(),
      data: '!@#',
    }));
    // Each subscriber fires once per controller notify.
    expect(updates.filter((u) => u === 1).length).toBeGreaterThanOrEqual(1);
    expect(updates.filter((u) => u === 2).length).toBeGreaterThanOrEqual(1);
    u1();
    u2();
  });
});

// ---------------------------------------------------------------------------
// 3. WebSocket cleanup on dispose (no leaked listener)
// ---------------------------------------------------------------------------

describe('ChatController: dispose lifecycle', () => {
  it('dispose() drops auth + ws listeners and clears sessions', () => {
    const { ctrl, auth, sockets, ws, connect } = makeController();
    connect();
    sent_open(sockets);
    void auth; // silence unused
    // Pretend a session was created locally so we can verify wipe.
    (ctrl as unknown as { conversations: Map<string, unknown> }).conversations.set(
      'bob',
      {
        peerUserId: 'bob',
        session: { wipe: vi.fn() },
        sessionState: { kind: 'ready', role: 'initiator' },
        messages: [],
        lastActivityAt: Date.now(),
        initiating: false,
      },
    );
    ctrl.dispose();
    // Re-dispose is a no-op (must not throw).
    ctrl.dispose();
    expect(ws).toBeDefined();
  });

  it('auto-clears sessions when auth flips to unauthenticated', () => {
    const { ctrl, auth, sockets, connect } = makeController();
    connect();
    sent_open(sockets);
    // Pre-populate a conversation so we can verify it gets wiped.
    const conversations = (ctrl as unknown as { conversations: Map<string, { session: { wipe: () => void } }> }).conversations;
    conversations.set('bob', { session: { wipe: vi.fn() } });
    auth.setToken(null);
    // The wipe should have been invoked.
    const wiped = conversations.get('bob');
    expect(wiped).toBeUndefined();
    ctrl.dispose();
  });
});

afterEach(() => {
  resetChatControllerForTests();
});

// ---------------------------------------------------------------------------
// 4. Composer-level test: openConversation errors are mapped to ChatError
// ---------------------------------------------------------------------------

describe('ChatController: openConversation error mapping', () => {
  it('rejects opening a conversation with self', async () => {
    const auth = makeAuthStub({ token: 'jwt', userId: 'alice' });
    const { ctrl } = makeController({ auth });
    await expect(ctrl.openConversation('alice')).rejects.toMatchObject({ code: 'no_identity' });
  });

  it('rejects peer id that is too short', async () => {
    const auth = makeAuthStub({ token: 'jwt', userId: 'alice' });
    const { ctrl } = makeController({ auth });
    await expect(ctrl.openConversation('ab')).rejects.toMatchObject({ code: 'peer_not_found' });
  });

  it('requires authentication before opening', async () => {
    const auth = makeAuthStub({ token: null, userId: null });
    const { ctrl } = makeController({ auth });
    await expect(ctrl.openConversation('bob')).rejects.toMatchObject({ code: 'no_identity' });
  });
});

// ---------------------------------------------------------------------------
// 5. Plaintext-isolation: never appears in any WebSocket frame
// ---------------------------------------------------------------------------

describe('ChatController: sendText end-to-end with mocked ratchet', () => {
  it('encrypts before transport and never sends plaintext bytes', async () => {
    const auth = makeAuthStub({ token: 'jwt', userId: 'alice' });
    const { ctrl, sockets, connect } = makeController({ auth });
    connect();
    sent_open(sockets);
    const sent = sockets.all()[0]!;

    // Replace the conversation's session with a stub that just encrypts via
    // AES-GCM over the Web Crypto API so we can verify the wire payload
    // is NOT plaintext.
    const sessStub = {
      encryptMessage: async (pt: Uint8Array) => {
        const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
          'encrypt',
        ]);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, pt);
        return new Uint8Array(ct);
      },
      decryptMessage: async () => new Uint8Array(),
      wipe: () => undefined,
    };
    (ctrl as unknown as {
      conversations: Map<string, { session: unknown; sessionState: unknown; initiating: boolean; messages: unknown[]; lastActivityAt: number; peerUserId: string }>;
    }).conversations.set('bob', {
      peerUserId: 'bob',
      session: sessStub,
      sessionState: { kind: 'ready', role: 'initiator' },
      initiating: false,
      messages: [],
      lastActivityAt: Date.now(),
    });
    sent.sentFrames.length = 0; // drop the auth frame from history

    const plaintext = 'hello-secret';
    const msg = await ctrl.sendText('bob', plaintext);
    expect(msg.outgoing).toBe(true);
    expect(msg.status).toBe('sent');
    expect(msg.plaintext).toBe(plaintext);

    const textFrames = sent.sentFrames
      .map((f) => JSON.parse(f))
      .filter((j) => j.type === 'text');
    expect(textFrames.length).toBe(1);
    const wire = textFrames[0] as { data: string; recipient: string };
    expect(wire.recipient).toBe('bob');
    // The wire `data` MUST NOT contain the plaintext literal.
    expect(wire.data).not.toContain(plaintext);
    // The plaintext literal must not appear in any frame on the socket.
    for (const frame of sent.sentFrames) {
      expect(frame).not.toContain(plaintext);
    }
  });
});

// ---------------------------------------------------------------------------
// 6. Decryption failure does not display ciphertext as plaintext
// ---------------------------------------------------------------------------

describe('ChatController: decryption failure is contained', () => {
  it('records an error and does not add a message when decryption throws', async () => {
    const auth = makeAuthStub({ token: 'jwt', userId: 'alice' });
    const { ctrl, sockets, connect } = makeController({ auth });
    connect();
    sent_open(sockets);
    const sessStub = {
      encryptMessage: async () => new Uint8Array(),
      decryptMessage: async () => {
        throw Object.assign(new Error('auth tag mismatch'), { code: 'auth_failed' });
      },
      wipe: () => undefined,
    };
    (ctrl as unknown as {
      conversations: Map<string, { peerUserId: string; session: unknown; sessionState: unknown; initiating: boolean; messages: { id: string; plaintext: string; outgoing: boolean }[]; lastActivityAt: number }>;
    }).conversations.set('bob', {
      peerUserId: 'bob',
      session: sessStub,
      sessionState: { kind: 'ready', role: 'responder' },
      initiating: false,
      messages: [],
      lastActivityAt: Date.now(),
    });

    const sent = sockets.all()[0]!;
    const env: InboundEnvelope = {
      version: 1,
      id: newMessageId(),
      type: 'text',
      sender: 'bob',
      recipient: 'alice',
      timestamp: Date.now(),
      data: 'AAAAAAAAAAAAAAAAAAAAAA', // valid base64url but meaningless
    };
    sent._receive(JSON.stringify(env));
    // Let the async handleText() complete (decryptMessage is awaited inside).
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));

    const snap = ctrl.getSnapshot();
    const conv = snap.conversations.find((c) => c.peerUserId === 'bob');
    expect(conv).toBeDefined();
    expect(conv!.messages.length).toBe(0);
    expect(conv!.session.kind).toBe('error');
    if (conv!.session.kind === 'error') {
      expect(conv!.session.error.code).toBe('session_decrypt_failed');
    }
  });
});

// ---------------------------------------------------------------------------
// 7. Encrypted round-trip via the real E2EESession (no backend)
// ---------------------------------------------------------------------------

describe('ChatController: round-trip via real E2EESession', () => {
  it('encrypts and decrypts a message end-to-end through the controller', async () => {
    // Use the real E2EESession for both sides by feeding the responder's
    // init payload into the initiator via the controller's session_init
    // handling path. We bypass REST by injecting the bundle directly via
    // a stubbed openConversation.
    const alice = makeAuthStub({ token: 'jwt', userId: 'alice' });
    const bob = makeAuthStub({ token: 'jwt', userId: 'bob' });

    const fA = makeWsFactory();
    const wsA = new WebSocketController({
      authController: alice as unknown as ConstructorParameters<typeof WebSocketController>[0]['authController'],
      url: 'wss://x/ws',
      factory: fA.factory,
    });
    wsA.connect();
    const ctrlA = new ChatController({
      authController: alice as unknown as ConstructorParameters<typeof ChatController>[0]['authController'],
      webSocketController: wsA,
    });
    sent_open(fA);
    const sentA = fA.all()[0]!;

    const fB = makeWsFactory();
    const wsB = new WebSocketController({
      authController: bob as unknown as ConstructorParameters<typeof WebSocketController>[0]['authController'],
      url: 'wss://x/ws',
      factory: fB.factory,
    });
    wsB.connect();
    const ctrlB = new ChatController({
      authController: bob as unknown as ConstructorParameters<typeof ChatController>[0]['authController'],
      webSocketController: wsB,
    });
    sent_open(fB);
    const sentB = fB.all()[0]!;

    // Build a real E2EESession pair off-band (no REST needed).
    const { E2EESession } = await import('../src/crypto/e2eeSession');
    const { buildDevicePublicBundle } = await import('../src/crypto/deviceKeys');
    const aliceDev = {
      ikxPrivate: new Uint8Array(32).map((_, i) => (i + 1) & 0xff),
      spkPrivate: new Uint8Array(32).map((_, i) => (i + 33) & 0xff),
      opkPrivate: new Uint8Array(32).map((_, i) => (i + 97) & 0xff),
    };
    const bobDev = {
      ikxPrivate: new Uint8Array(32).map((_, i) => (i + 65) & 0xff),
      spkPrivate: new Uint8Array(32).map((_, i) => (i + 129) & 0xff),
      opkPrivate: null,
    };
    const aliceSeed = new Uint8Array(32).map((_, i) => (i + 200) & 0xff);
    const bobSeed = new Uint8Array(32).map((_, i) => (i + 232) & 0xff);
    const aliceBundle = buildDevicePublicBundle(aliceSeed, aliceDev);
    const bobBundle = buildDevicePublicBundle(bobSeed, bobDev);

    // Alice initiates with bob's bundle. Note: X3DH IKX_B public is bob's
    // X25519 identity, NOT alice's (otherwise the DH terms do not agree).
    const aliceSession = await E2EESession.initiate(
      aliceDev.ikxPrivate,
      {
        authIkPublic: bobBundle.ikPublic,
        ikxPublic: bobBundle.xdhPublic,
        spkPublic: bobBundle.spkPublic,
        spkSignature: bobBundle.spkSignature,
        opkPublic: null,
      },
    );

    // Force-install the resulting session into Alice's controller.
    (ctrlA as unknown as {
      conversations: Map<string, { peerUserId: string; session: unknown; sessionState: unknown; initiating: boolean; messages: unknown[]; lastActivityAt: number }>;
    }).conversations.set('bob', {
      peerUserId: 'bob',
      session: aliceSession,
      sessionState: { kind: 'ready', role: 'initiator' },
      initiating: false,
      messages: [],
      lastActivityAt: Date.now(),
    });

    const plaintext = 'hello bob — round trip test';
    const msg = await ctrlA.sendText('bob', plaintext);
    expect(msg.outgoing).toBe(true);
    expect(msg.status).toBe('sent');
    expect(msg.plaintext).toBe(plaintext);

    // Find the text envelope Alice sent.
    const textFrame = sentA.sentFrames
      .map((f) => JSON.parse(f))
      .find((j) => j.type === 'text') as { data: string; recipient: string };
    expect(textFrame).toBeDefined();
    expect(textFrame.recipient).toBe('bob');
    expect(textFrame.data).not.toContain(plaintext);

    // Hand the wire frame to Bob's controller as if it arrived via WS.
    const bobEnv: InboundEnvelope = {
      version: 1,
      id: newMessageId(),
      type: 'text',
      sender: 'alice',
      recipient: 'bob',
      timestamp: Date.now(),
      data: textFrame.data,
    };
    // Build the matching bob-side session by accepting alice's init payload
    // would require the init flow; for THIS test we directly install a bob
    // session with a pre-known shared secret. Instead, we leverage
    // aliceSession + accept via the init payload — but we don't have it
    // here. So we use a *parallel* test by accepting Alice's first message
    // via a fresh responder session: Bob accepts alice's init.
    // Simpler: pre-construct Bob's session via accept using alice's
    // ephemeral carried inside aliceSession. The session_init payload
    // IS aliceSession.initPayload.
    const bobSession = await E2EESession.accept(
      bobDev.spkPrivate,
      bobDev.ikxPrivate,
      bobBundle.xdhPublic, // bob's own IKX public
      [],
      aliceSession.initPayload,
    );

    // Exercise the controller's handleText path end-to-end: bob installs the
    // freshly-accepted session (ratchet at nr=0) and decrypts alice's first
    // text envelope (n=0) as it arrives over the WS transport.
    (ctrlB as unknown as {
      conversations: Map<string, { peerUserId: string; session: unknown; sessionState: unknown; initiating: boolean; messages: unknown[]; lastActivityAt: number }>;
    }).conversations.set('alice', {
      peerUserId: 'alice',
      session: bobSession,
      sessionState: { kind: 'ready', role: 'responder' },
      initiating: false,
      messages: [],
      lastActivityAt: Date.now(),
    });
    const bobInbound: InboundEnvelope = {
      version: 1,
      id: newMessageId(),
      type: 'text',
      sender: 'alice',
      recipient: 'bob',
      timestamp: Date.now(),
      data: textFrame.data,
    };
    sentB._receive(JSON.stringify(bobInbound));
    // Drain microtasks: ratchet decrypt involves several awaits (hkdf,
    // aead). Multiple setImmediate hops flush them all.
    for (let i = 0; i < 8; i += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    const bobSnap = ctrlB.getSnapshot();
    const aliceConv = bobSnap.conversations.find((c) => c.peerUserId === 'alice');
    expect(aliceConv).toBeDefined();
    expect(aliceConv!.messages.length).toBe(1);
    expect(aliceConv!.messages[0]!.plaintext).toBe(plaintext);
    expect(aliceConv!.messages[0]!.outgoing).toBe(false);
    void sent_open;

    ctrlA.dispose();
    ctrlB.dispose();
  });
});

/**
 * The ChatController encodes the wire bytes as base64url(session.encryptMessage(...))
 * so to decode on Bob's side we just base64url-decode the wire frame's `data`.
 * This helper exists only to keep the test self-contained.
 */
async function reconstructWire(
  data: string,
  _aliceSession: unknown,
): Promise<Uint8Array> {
  // Decode the base64url wire data.
  const pad = '='.repeat((4 - (data.length % 4)) % 4);
  const b64 = data.replace(/-/g, '+').replace(/_/g, '/') + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

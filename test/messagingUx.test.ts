import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ChatController, resetChatControllerForTests } from '../src/realtime/ChatController';
import { WebSocketController } from '../src/realtime/WebSocketController';
import type { WebSocketFactory, WebSocketLike } from '../src/realtime/WebSocketClient';
import type { InboundEnvelope } from '../src/realtime/types';
import { newMessageId } from '../src/realtime/messageId';
import { encodeBase64Url } from '../src/crypto/base64url';
import { getPresence } from '../src/api/presence';
import type { ConversationSnapshot } from '../src/realtime/ChatController';
import { filterConversationsBySearch } from '../src/realtime/chatSearch';
import {
  formatConversationTimestamp,
  formatMessageTimestamp,
  formatMessageTimestampLong,
} from '../src/realtime/timeFormat';

// ---------------------------------------------------------------------------
// Fakes (same infrastructure as chatController.test.ts)
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
    factory: {
      create: (url: string) => { const s = new FakeSocket(url); sockets.push(s); return s; },
    } as WebSocketFactory,
    all: () => sockets.slice() as FakeSocket[],
  };
}

type AuthSnap = { authenticated: boolean; userId: string | null };
type AuthListener = (snap: AuthSnap) => void;

function makeAuthStub(initial: { token: string | null; userId: string | null }) {
  let token = initial.token;
  let userId = initial.userId;
  const listeners = new Set<AuthListener>();
  const snap = (): AuthSnap => ({ authenticated: token !== null, userId });
  return {
    getToken: () => token,
    getUserId: () => userId,
    getUnlockedIdentity: () => null as unknown as null,
    subscribe(listener: AuthListener) {
      listeners.add(listener); listener(snap()); return () => listeners.delete(listener);
    },
    _snap: snap,
  };
}

function makeController() {
  const auth = makeAuthStub({ token: 'jwt', userId: 'alice' });
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
  const s = f.all()[0]!;
  s._open();
  return { ctrl, ws, sockets: f, socket: s };
}

function stubSession(overrides: Partial<{
  encryptMessage: (pt: Uint8Array) => Promise<Uint8Array>;
  decryptMessage: (wire: Uint8Array) => Promise<Uint8Array>;
  wipe: () => void;
}> = {}) {
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

function injectConversation(ctrl: ChatController, peer: string, session: unknown) {
  (ctrl as unknown as { conversations: Map<string, unknown> }).conversations.set(peer, {
    peerUserId: peer,
    session,
    sessionState: { kind: 'ready', role: 'initiator' },
    messages: [],
    lastActivityAt: Date.now(),
    initiating: false,
    sending: false,
  });
}

function inbox(peer: string, type: string, data: string): InboundEnvelope {
  return {
    version: 1,
    id: newMessageId(),
    type: type as InboundEnvelope['type'],
    sender: peer,
    recipient: 'alice',
    timestamp: Date.now(),
    data,
  };
}

function frames(socket: FakeSocket) {
  return socket.sentFrames.map((f) => JSON.parse(f) as { type: string; data: string; recipient: string; id: string });
}

afterEach(() => resetChatControllerForTests());

// ---------------------------------------------------------------------------
// Delivery / read receipts
// ---------------------------------------------------------------------------

describe('Messaging UX: delivery / read receipts', () => {
  it('advances an outbound message only on observed receipts', async () => {
    const { ctrl, socket } = makeController();
    injectConversation(ctrl, 'bob', stubSession());
    socket.sentFrames.length = 0;

    const msg = await ctrl.sendText('bob', 'hello');
    expect(msg.status).toBe('sent');
    expect(msg.wireId).toBeTruthy();
    const wireId = msg.wireId as string;

    // delivery_receipt referencing the wire id flips the status to delivered.
    socket._receive(JSON.stringify(inbox('bob', 'delivery_receipt', wireId)));
    let snap = ctrl.getSnapshot();
    let bob = snap.conversations.find((c) => c.peerUserId === 'bob')!;
    expect(bob.messages[0]!.status).toBe('delivered');

    // read_receipt flips it to read.
    socket._receive(JSON.stringify(inbox('bob', 'read_receipt', wireId)));
    snap = ctrl.getSnapshot();
    bob = snap.conversations.find((c) => c.peerUserId === 'bob')!;
    expect(bob.messages[0]!.status).toBe('read');

    // A later (out-of-order) delivery receipt must NOT downgrade the status.
    socket._receive(JSON.stringify(inbox('bob', 'delivery_receipt', wireId)));
    snap = ctrl.getSnapshot();
    bob = snap.conversations.find((c) => c.peerUserId === 'bob')!;
    expect(bob.messages[0]!.status).toBe('read');
    ctrl.dispose();
  });

  it('ignores receipts referencing unknown wire ids without crashing', async () => {
    const { ctrl, socket } = makeController();
    injectConversation(ctrl, 'bob', stubSession());
    socket.sentFrames.length = 0;

    await ctrl.sendText('bob', 'hello');
    socket._receive(JSON.stringify(inbox('bob', 'read_receipt', 'does-not-exist')));
    const snap = ctrl.getSnapshot();
    const bob = snap.conversations.find((c) => c.peerUserId === 'bob')!;
    expect(bob.messages[0]!.status).toBe('sent');
    ctrl.dispose();
  });

  it('auto-emits delivery + read receipts when the conversation is active', async () => {
    const { ctrl, socket } = makeController();
    injectConversation(ctrl, 'bob', stubSession());
    socket.sentFrames.length = 0;
    ctrl.setActivePeer('bob');

    const body = encodeBase64Url(new Uint8Array([1, 2, 3]));
    const env = inbox('bob', 'text', body);
    socket._receive(JSON.stringify(env));
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));

    const emitted = frames(socket).filter((f) => f.type === 'delivery_receipt' || f.type === 'read_receipt');
    expect(emitted.filter((f) => f.type === 'delivery_receipt').map((f) => f.data)).toContain(env.id);
    expect(emitted.filter((f) => f.type === 'read_receipt').map((f) => f.data)).toContain(env.id);

    const snap = ctrl.getSnapshot();
    const bob = snap.conversations.find((c) => c.peerUserId === 'bob')!;
    expect(bob.messages.length).toBe(1);
    expect(bob.unreadCount).toBe(0);
    ctrl.dispose();
  });

  it('increments unread and defers read receipts when the conversation is not active', async () => {
    const { ctrl, socket } = makeController();
    injectConversation(ctrl, 'bob', stubSession());
    socket.sentFrames.length = 0;

    const env = inbox('bob', 'text', encodeBase64Url(new Uint8Array([9])));
    socket._receive(JSON.stringify(env));
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));

    const emitted = frames(socket).filter((f) => f.type === 'read_receipt');
    expect(emitted.length).toBe(0);

    let snap = ctrl.getSnapshot();
    let bob = snap.conversations.find((c) => c.peerUserId === 'bob')!;
    expect(bob.unreadCount).toBe(1);

    // Opening the conversation emits read receipts exactly once and resets.
    ctrl.setActivePeer('bob');
    snap = ctrl.getSnapshot();
    bob = snap.conversations.find((c) => c.peerUserId === 'bob')!;
    expect(bob.unreadCount).toBe(0);
    const readReceipts = frames(socket).filter((f) => f.type === 'read_receipt' && f.data === env.id);
    expect(readReceipts.length).toBe(1);

    // Re-acquiring the conversation must NOT re-emit for the same message.
    ctrl.setActivePeer('charlie');
    ctrl.setActivePeer('bob');
    const readReceiptsAfter = frames(socket).filter((f) => f.type === 'read_receipt' && f.data === env.id);
    expect(readReceiptsAfter.length).toBe(1);
    ctrl.dispose();
  });
});

// ---------------------------------------------------------------------------
// Typing indicator
// ---------------------------------------------------------------------------

describe('Messaging UX: typing indicator', () => {
  it('sendTyping emits opaque start/stop wire values', async () => {
    const { ctrl, socket } = makeController();
    injectConversation(ctrl, 'bob', stubSession());

    ctrl.sendTyping('bob', 'start');
    ctrl.sendTyping('bob', 'stop');

    const typing = frames(socket).filter((f) => f.type === 'typing');
    expect(typing.map((f) => f.data)).toEqual(['1', '0']);
    for (const f of typing) {
      expect(f.recipient).toBe('bob');
      expect(f.data.length).toBeLessThanOrEqual(1); // never plaintext
    }
    ctrl.dispose();
  });

  it('inbound typing toggles the conversation flag', () => {
    const { ctrl, socket } = makeController();
    injectConversation(ctrl, 'bob', stubSession());

    socket._receive(JSON.stringify(inbox('bob', 'typing', '1')));
    let snap = ctrl.getSnapshot();
    expect(snap.conversations.find((c) => c.peerUserId === 'bob')!.typing).toBe(true);

    socket._receive(JSON.stringify(inbox('bob', 'typing', '0')));
    snap = ctrl.getSnapshot();
    expect(snap.conversations.find((c) => c.peerUserId === 'bob')!.typing).toBe(false);
    ctrl.dispose();
  });

  it('auto-clears a stuck typing indicator after the timeout', () => {
    vi.useFakeTimers();
    try {
      const { ctrl, socket } = makeController();
      injectConversation(ctrl, 'bob', stubSession());

      socket._receive(JSON.stringify(inbox('bob', 'typing', '1')));
      expect(ctrl.getSnapshot().conversations.find((c) => c.peerUserId === 'bob')!.typing).toBe(true);

      vi.advanceTimersByTime(3001);
      expect(ctrl.getSnapshot().conversations.find((c) => c.peerUserId === 'bob')!.typing).toBe(false);
      ctrl.dispose();
    } finally {
      vi.useRealTimers();
    }
  });
});

// ---------------------------------------------------------------------------
// Presence
// ---------------------------------------------------------------------------

describe('Messaging UX: presence', () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
  });

  it('GET /presence sends the bearer token and parses the response', async () => {
    const fn = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ user_id: 'bob', online: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    vi.stubGlobal('fetch', fn);

    const { data } = await getPresence('bob', { authToken: 'jwt' });
    expect(data).toEqual({ user_id: 'bob', online: true });
    const [url, init] = fn.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/presence/bob');
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer jwt');
  });

  it('refreshPresence caches online/offline/unknown per conversation', async () => {
    const { ctrl } = makeController();
    injectConversation(ctrl, 'bob', stubSession());

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ user_id: 'bob', online: true }), { status: 200 }),
    ));
    await ctrl.refreshPresence('bob');
    expect(ctrl.getSnapshot().conversations.find((c) => c.peerUserId === 'bob')!.presence).toBe('online');

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ user_id: 'bob', online: false }), { status: 200 }),
    ));
    await ctrl.refreshPresence('bob');
    expect(ctrl.getSnapshot().conversations.find((c) => c.peerUserId === 'bob')!.presence).toBe('offline');

    // Storage/network failure degrades to unknown (presence is non-security).
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('network down')));
    await ctrl.refreshPresence('bob');
    expect(ctrl.getSnapshot().conversations.find((c) => c.peerUserId === 'bob')!.presence).toBe('unknown');
    ctrl.dispose();
  });
});

// ---------------------------------------------------------------------------
// Delete locally
// ---------------------------------------------------------------------------

describe('Messaging UX: delete message locally', () => {
  it('removes the message from local state and sends nothing', async () => {
    const { ctrl, socket } = makeController();
    injectConversation(ctrl, 'bob', stubSession());

    const msg = await ctrl.sendText('bob', 'hello');
    const framesBefore = socket.sentFrames.length;

    ctrl.deleteMessageLocally('bob', msg.id);
    const snap = ctrl.getSnapshot();
    const bob = snap.conversations.find((c) => c.peerUserId === 'bob')!;
    expect(bob.messages.length).toBe(0);
    // No wire traffic was generated by the deletion itself.
    expect(socket.sentFrames.length).toBe(framesBefore);
    ctrl.dispose();
  });

  it('is a no-op for unknown message ids', () => {
    const { ctrl } = makeController();
    injectConversation(ctrl, 'bob', stubSession());
    ctrl.deleteMessageLocally('bob', 'missing-id');
    expect(ctrl.getSnapshot().conversations.find((c) => c.peerUserId === 'bob')!.messages.length).toBe(0);
    ctrl.dispose();
  });
});

// ---------------------------------------------------------------------------
// Conversation search
// ---------------------------------------------------------------------------

describe('Messaging UX: conversation search', () => {
  it('matches peer user ids case-insensitively and trims the term', async () => {
    const { ctrl } = makeController();
    injectConversation(ctrl, 'alice-bob', stubSession());
    injectConversation(ctrl, 'Charlie', stubSession());
    const all = ctrl.getSnapshot().conversations;

    expect(filterConversationsBySearch(all, '')).toHaveLength(2);
    expect(filterConversationsBySearch(all, '   ')).toHaveLength(2);
    expect(filterConversationsBySearch(all, 'bob').map((c) => c.peerUserId)).toEqual(['alice-bob']);
    expect(filterConversationsBySearch(all, 'CHAR').map((c) => c.peerUserId)).toEqual(['Charlie']);
    expect(filterConversationsBySearch(all, 'zzz')).toHaveLength(0);
    ctrl.dispose();
  });
});

// ---------------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------------

describe('Messaging UX: timestamps', () => {
  it('formats relative message and conversation timestamps', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(2026, 8, 19, 12, 0, 0));
    try {
      const now = Date.now();
      const today = now - 3 * 60 * 60 * 1000;
      const yesterday = now - 24 * 60 * 60 * 1000 - 60 * 60 * 1000;
      const older = new Date(2025, 11, 31, 9, 5, 0).getTime();

      const todayLabel = formatMessageTimestamp(today);
      expect(todayLabel.length).toBeGreaterThan(0);
      expect(todayLabel).not.toContain('Yesterday');

      expect(formatMessageTimestamp(yesterday)).toContain('Yesterday');
      expect(formatMessageTimestamp(older).length).toBeGreaterThan(0);
      expect(formatMessageTimestamp(older)).not.toContain('Yesterday');

      expect(formatMessageTimestampLong(now).length).toBeGreaterThan(0);
      expect(formatConversationTimestamp(now - 30_000)).toBe('now');
      expect(formatConversationTimestamp(now - 90_000)).toBe('1m');
      expect(formatConversationTimestamp(yesterday)).toBe('Yesterday');
      expect(formatConversationTimestamp(older).length).toBeGreaterThan(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('returns empty strings for invalid timestamps', () => {
    expect(formatMessageTimestamp(0)).toBe('');
    expect(formatMessageTimestamp(NaN)).toBe('');
    expect(formatConversationTimestamp(0)).toBe('');
  });
});
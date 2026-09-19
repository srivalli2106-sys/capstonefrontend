import { afterEach, describe, expect, it, vi } from 'vitest';
import { ChatController, resetChatControllerForTests } from '../src/realtime/ChatController';
import { WebSocketController } from '../src/realtime/WebSocketController';
import type { WebSocketFactory, WebSocketLike } from '../src/realtime/WebSocketClient';
import type { ChatPersistence, PersistedConversation } from '../src/persistence/types';
import type { UnlockedIdentity } from '../src/crypto/identity';

// ---------------------------------------------------------------------------
// Fakes
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
  _receive(data: string): void {
    this.onmessage?.({ data });
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
    all: () => sockets.slice() as FakeSocket[],
  };
}

type AuthSnap = {
  authenticated: boolean;
  userId: string | null;
  identity?: { kind: string };
};

function makeAuthStub(initial: { token: string | null; userId: string | null }) {
  let token = initial.token;
  let userId = initial.userId;
  let unlocked: UnlockedIdentity | null = null;
  const listeners = new Set<(snap: AuthSnap) => void>();
  const snap = (): AuthSnap => ({
    authenticated: token !== null,
    userId,
    identity: unlocked === null ? { kind: 'locked' } : { kind: 'unlocked' },
  });
  return {
    getToken: () => token,
    getUserId: () => userId,
    getUnlockedIdentity: () => unlocked,
    _setUnlocked(next: UnlockedIdentity | null): void {
      unlocked = next;
      for (const listener of listeners) listener(snap());
    },
    _logout(): void {
      token = null;
      userId = null;
      unlocked = null;
      for (const listener of listeners) listener(snap());
    },
    subscribe(listener: (snap: AuthSnap) => void) {
      listeners.add(listener);
      listener(snap());
      return () => listeners.delete(listener);
    },
  };
}

function makeIdentity(ikxPrivate: Uint8Array): UnlockedIdentity {
  return {
    userId: 'alice',
    publicKeyHex: '00'.repeat(32),
    publicKeyShortId: 'abcdef',
    deviceKeys: {
      ikxPrivate,
      spkPrivate: new Uint8Array(32),
      opkPrivate: null,
    },
    exportRawSeed: () => new Uint8Array(32),
  } as unknown as UnlockedIdentity;
}

function makePersistence(loadResult: PersistedConversation[] = []) {
  let locked = true;
  let self: string | null = null;
  const save = vi.fn(async () => {});
  const remove = vi.fn(async () => {});
  const unlock = vi.fn(async (selfUserId: string) => {
    self = selfUserId;
    locked = false;
  });
  const lock = vi.fn(() => {
    locked = true;
    self = null;
  });
  return {
    save,
    remove,
    unlock,
    lock,
    get isUnlocked() { return !locked; },
    get selfUserId() { return self; },
    load: vi.fn(async (selfUserId: string) =>
      selfUserId === self && !locked ? loadResult : [],
    ),
  } as unknown as ChatPersistence & {
    save: ReturnType<typeof vi.fn>;
    remove: ReturnType<typeof vi.fn>;
    unlock: ReturnType<typeof vi.fn>;
    lock: ReturnType<typeof vi.fn>;
  };
}

function makeController(opts?: {
  ikx?: Uint8Array;
  persistence?: ReturnType<typeof makePersistence>;
}) {
  const auth = makeAuthStub({ token: 'jwt', userId: 'alice' });
  const f = makeWsFactory();
  const ws = new WebSocketController({
    authController: auth as unknown as ConstructorParameters<typeof WebSocketController>[0]['authController'],
    url: 'wss://x/ws',
    factory: f.factory,
  });
  ws.connect();
  const persistence =
    opts?.persistence ??
    (makePersistence() as unknown as ReturnType<typeof makePersistence>);
  const ctrl = new ChatController({
    authController: auth as unknown as ConstructorParameters<typeof ChatController>[0]['authController'],
    webSocketController: ws,
    persistence,
  });
  const socket = f.all()[0]!;
  socket._open();
  if (opts?.ikx !== undefined) {
    auth._setUnlocked(makeIdentity(opts.ikx));
  }
  return { ctrl, auth, webSocket: ws, persistence, socket };
}

function waitForSnapshot(
  ctrl: ChatController,
  predicate: (snap: ReturnType<ChatController['getSnapshot']>) => boolean,
): Promise<ReturnType<ChatController['getSnapshot']>> {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const poll = () => {
      const snap = ctrl.getSnapshot();
      if (predicate(snap)) return resolve(snap);
      if (Date.now() - started > 4000) return reject(new Error('snapshot wait timed out'));
      setTimeout(poll, 5);
    };
    poll();
  });
}

function sampleConversation(overrides: Partial<PersistedConversation> = {}): PersistedConversation {
  return {
    version: 1,
    peerUserId: 'bob',
    messages: [
      {
        id: 'm1',
        wireId: 'm1',
        senderUserId: 'bob',
        recipientUserId: 'alice',
        plaintext: 'hello from bob',
        createdAt: 1_700_000_000_000,
        outgoing: false,
        status: null,
        errorMessage: null,
        readAckSent: true,
      },
      {
        id: 'c-out-2',
        wireId: 'WIRERCV01',
        senderUserId: 'alice',
        recipientUserId: 'bob',
        plaintext: 'hi bob',
        createdAt: 1_700_000_001_000,
        outgoing: true,
        status: 'read',
        errorMessage: null,
        readAckSent: false,
      },
    ],
    lastActivityAt: 1_700_000_001_000,
    unreadCount: 0,
    ...overrides,
  };
}

function injectConversation(ctrl: ChatController, peer: string, messageIds: string[]) {
  const { conversations } = ctrl as unknown as {
    conversations: Map<string, { messages: Array<{ id: string }> }>;
  };
  const existing = conversations.get(peer) ?? {
    peerUserId: peer,
    session: null,
    sessionState: { kind: 'none' },
    messages: [],
    lastActivityAt: 0,
    initiating: false,
    sending: false,
    presence: 'unknown',
    peerTyping: false,
    typingTimer: null,
    unreadCount: 0,
  };
  existing.messages = messageIds.map((id, i) => ({
    id,
    wireId: id,
    senderUserId: 'bob',
    recipientUserId: 'alice',
    plaintext: 'existing',
    createdAt: 1_700_000_000_000 + i,
    outgoing: false,
    status: null,
    errorMessage: null,
    sessionReady: true,
    readAckSent: true,
  }));
  conversations.set(peer, existing);
}

afterEach(() => resetChatControllerForTests());

// ---------------------------------------------------------------------------
// Hydration
// ---------------------------------------------------------------------------

describe('ChatController local history: hydration', () => {
  it('restores persisted history once the identity is unlocked', async () => {
    const persistence = makePersistence([sampleConversation()]);
    const { ctrl } = makeController({
      ikx: new Uint8Array(32),
      persistence,
    });

    const snap = await waitForSnapshot(ctrl, (s) => s.historyLoaded === true);
    expect(snap.historyLoaded).toBe(true);
    expect(snap.conversations).toHaveLength(1);
    const conv = snap.conversations[0]!;
    expect(conv.peerUserId).toBe('bob');
    expect(conv.messages.map((m) => m.plaintext)).toEqual(['hello from bob', 'hi bob']);
    expect(conv.messages.map((m) => m.id)).toEqual(['m1', 'c-out-2']);
    // Preserved from the stored record.
    expect(conv.unreadCount).toBe(0);
    // Restored conversations never pretend to have a live session.
    expect(conv.session.kind).toBe('none');
    expect(persistence.unlock).toHaveBeenCalledWith('alice', expect.any(Uint8Array));
  });

  it('keeps historyLoaded false while the identity stays locked', () => {
    const { ctrl } = makeController();
    expect(ctrl.getSnapshot().historyLoaded).toBe(false);
    expect(ctrl.getSnapshot().conversations).toEqual([]);
  });

  it('does not duplicate message ids already present in memory on restore', async () => {
    const persistence = makePersistence([sampleConversation()]);
    const { ctrl } = makeController({
      ikx: new Uint8Array(32),
      persistence,
    });
    injectConversation(ctrl, 'bob', ['m1']);

    const snap = await waitForSnapshot(ctrl, (s) => s.historyLoaded === true);
    const conv = snap.conversations.find((c) => c.peerUserId === 'bob');
    expect(conv?.messages.map((m) => m.id).sort()).toEqual(['c-out-2', 'm1']);
  });

  it('restores an interrupted outbound send as failed, never as confirmed', async () => {
    const interrupted = sampleConversation({
      messages: [
        {
          id: 'c-interrupted',
          wireId: 'WIRE-INT',
          senderUserId: 'alice',
          recipientUserId: 'bob',
          plaintext: 'half sent',
          createdAt: 1_700_000_002_000,
          outgoing: true,
          status: 'sending',
          errorMessage: null,
          readAckSent: false,
        },
      ],
    });
    const persistence = makePersistence([interrupted]);
    const { ctrl } = makeController({ ikx: new Uint8Array(32), persistence });

    const snap = await waitForSnapshot(ctrl, (s) => s.historyLoaded === true);
    const restored = snap.conversations[0]!.messages[0]!;
    expect(restored.outgoing).toBe(true);
    expect(restored.status).toBe('failed');
    expect(restored.errorMessage).not.toBeNull();
  });

  it('snapshot ordering follows lastActivityAt from the store', async () => {
    const older = sampleConversation({ peerUserId: 'amy' });
    const newer = sampleConversation({
      peerUserId: 'zoe',
      lastActivityAt: 1_700_000_010_000,
    });
    const persistence = makePersistence([older, newer]);
    const { ctrl } = makeController({ ikx: new Uint8Array(32), persistence });

    const snap = await waitForSnapshot(ctrl, (s) => s.historyLoaded === true);
    expect(snap.conversations.map((c) => c.peerUserId)).toEqual(['zoe', 'amy']);
  });
});

// ---------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------

describe('ChatController local history: writes and deletes', () => {
  it('persists outgoing messages after the send completes', async () => {
    const persistence = makePersistence();
    const { ctrl } = makeController({ ikx: new Uint8Array(32), persistence });
    await waitForSnapshot(ctrl, (s) => s.historyLoaded === true);

    // Build a real initiator session with a valid SPK binding so sendText
    // can encrypt (mirrors the existing round-trip test approach).
    const { E2EESession } = await import('../src/crypto/e2eeSession');
    const { buildDevicePublicBundle } = await import('../src/crypto/deviceKeys');
    const aliceDev = {
      ikxPrivate: new Uint8Array(32).map((_, i) => (i + 1) & 0xff),
      spkPrivate: new Uint8Array(32).map((_, i) => (i + 33) & 0xff),
      opkPrivate: null,
    };
    const bobDev = {
      ikxPrivate: new Uint8Array(32).map((_, i) => (i + 65) & 0xff),
      spkPrivate: new Uint8Array(32).map((_, i) => (i + 129) & 0xff),
      opkPrivate: null,
    };
    const bobBundle = buildDevicePublicBundle(
      new Uint8Array(32).map((_, i) => (i + 232) & 0xff),
      bobDev,
    );
    const session = await E2EESession.initiate(aliceDev.ikxPrivate, {
      authIkPublic: bobBundle.ikPublic,
      ikxPublic: bobBundle.xdhPublic,
      spkPublic: bobBundle.spkPublic,
      spkSignature: bobBundle.spkSignature,
      opkPublic: null,
    });

    injectConversation(ctrl, 'bob', []);
    (ctrl as unknown as {
      conversations: Map<string, { session: unknown }>;
    }).conversations.get('bob')!.session = session;

    const sent = await ctrl.sendText('bob', 'persist me');
    expect(sent.status).toBe('sent');

    await vi.waitFor(() => expect(persistence.save).toHaveBeenCalled());
    const savedCall = persistence.save.mock.calls.find(
      (call) => call[1].peerUserId === 'bob',
    );
    expect(savedCall).toBeDefined();
    const saved = savedCall![1] as PersistedConversation;
    expect(saved.messages.some((m) => m.plaintext === 'persist me')).toBe(true);
    expect(saved.messages.find((m) => m.plaintext === 'persist me')?.status).toBe('sent');
  });

  it('persists receipt-driven status changes', async () => {
    const persistence = makePersistence([
      sampleConversation({
        messages: [
          {
            id: 'c-out-2',
            wireId: 'WIRERCV01',
            senderUserId: 'alice',
            recipientUserId: 'bob',
            plaintext: 'hi bob',
            createdAt: 1_700_000_001_000,
            outgoing: true,
            status: 'sent',
            errorMessage: null,
            readAckSent: false,
          },
        ],
      }),
    ]);
    const { ctrl, socket } = makeController({ ikx: new Uint8Array(32), persistence });
    await waitForSnapshot(ctrl, (s) => s.historyLoaded === true);

    // Drive the receipt through the wire path (WebSocket parse → onEnvelope).
    const { newMessageId } = await import('../src/realtime/messageId');
    socket._receive(
      JSON.stringify({
        version: 1,
        id: newMessageId(),
        type: 'read_receipt',
        sender: 'bob',
        recipient: 'alice',
        timestamp: Date.now(),
        data: 'WIRERCV01',
      }),
    );

    await vi.waitFor(() => expect(persistence.save).toHaveBeenCalled());
    const saved = persistence.save.mock.calls[persistence.save.mock.calls.length - 1]![1] as PersistedConversation;
    expect(saved.messages[0]!.status).toBe('read');
  });

  it('delete-conversation removes the record from the store and closes in memory', async () => {
    const persistence = makePersistence([sampleConversation()]);
    const { ctrl } = makeController({ ikx: new Uint8Array(32), persistence });
    await waitForSnapshot(ctrl, (s) => s.historyLoaded === true);
    expect(ctrl.getSnapshot().conversations).toHaveLength(1);

    await ctrl.deleteConversation('bob');

    expect(ctrl.getSnapshot().conversations).toHaveLength(0);
    await vi.waitFor(() => expect(persistence.remove).toHaveBeenCalledWith('alice', 'bob'));
  });

  it('logout flushes the history BEFORE wiping and locks the store', async () => {
    const persistence = makePersistence([sampleConversation()]);
    const { ctrl, auth } = makeController({ ikx: new Uint8Array(32), persistence });
    await waitForSnapshot(ctrl, (s) => s.historyLoaded === true);

    auth._logout();

    await vi.waitFor(() => expect(persistence.save).toHaveBeenCalled());
    // The store key is dropped on logout/lock.
    expect(persistence.lock).toHaveBeenCalled();
    expect(ctrl.getSnapshot().conversations).toHaveLength(0);
    expect(ctrl.getSnapshot().historyLoaded).toBe(false);
  });
});
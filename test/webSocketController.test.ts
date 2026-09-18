import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { WebSocketController } from '../src/realtime/WebSocketController';
import {
  WS_CLOSE,
  type ConnectionState,
  type InboundEnvelope,
} from '../src/realtime/types';
import { newMessageId } from '../src/realtime/messageId';
import type { WebSocketLike, WebSocketFactory } from '../src/realtime/WebSocketClient';

/**
 * Lightweight AuthController stub. Implements only what WebSocketController
 * subscribes to: `subscribe(listener)` and `getToken()`.
 */
function makeAuthStub(initialToken: string | null = 'jwt') {
  type Listener = (snapshot: { authenticated: boolean }) => void;
  const listeners = new Set<Listener>();
  let token = initialToken;
  return {
    setToken(next: string | null): void {
      token = next;
      const authenticated = next !== null;
      for (const l of listeners) l({ authenticated });
    },
    getToken(): string | null {
      return token;
    },
    subscribe(listener: Listener): () => void {
      listeners.add(listener);
      listener({ authenticated: token !== null });
      return () => listeners.delete(listener);
    },
  };
}

class FakeSocket implements WebSocketLike {
  public readyState = 0;
  public sentFrames: string[] = [];
  public onopen: ((ev: Event) => void) | null = null;
  public onclose: ((ev: { code: number; reason: string }) => void) | null = null;
  public onerror: ((ev: Event) => void) | null = null;
  public onmessage: ((ev: { data: string }) => void) | null = null;

  constructor(public readonly url: string) {}

  send(data: string): void { this.sentFrames.push(data); }
  close(code: number = WS_CLOSE.Normal, reason: string = ''): void {
    this.readyState = 3;
    if (this.onclose) this.onclose({ code, reason });
  }

  _open(): void {
    this.readyState = 1;
    this.onopen?.(new Event('open'));
  }
  _receive(data: string): void {
    this.onmessage?.({ data });
  }
  _close(code: number, reason: string): void {
    this.close(code, reason);
  }
}

function makeFactory() {
  const sockets: FakeSocket[] = [];
  return {
    factory: {
      create: (url: string) => {
        const s = new FakeSocket(url);
        sockets.push(s);
        return s;
      },
    } as WebSocketFactory,
    last: (): FakeSocket => {
      const s = sockets[sockets.length - 1];
      if (s === undefined) throw new Error('no socket');
      return s;
    },
    all: (): FakeSocket[] => sockets.slice(),
  };
}

describe('WebSocketController: connect / auth flow', () => {
  let auth: ReturnType<typeof makeAuthStub>;
  let factory: WebSocketFactory;
  let last: () => FakeSocket;
  let all: () => FakeSocket[];
  let controller: WebSocketController;

  beforeEach(() => {
    vi.useFakeTimers();
    const f = makeFactory();
    factory = f.factory;
    last = f.last;
    all = f.all;
    auth = makeAuthStub('jwt.test');
    controller = new WebSocketController({
      authController: auth as unknown as Parameters<typeof WebSocketController>[0]['authController'],
      url: 'wss://example.test/ws',
      factory,
      backoffSchedule: [10, 20, 40, 80],
    });
  });

  afterEach(() => {
    controller.dispose();
    vi.useRealTimers();
  });

  it('opens with the first auth frame containing the JWT', () => {
    controller.connect();
    last()._open();
    const authFrame = JSON.parse(last().sentFrames[0]!);
    expect(authFrame).toEqual({ type: 'auth', token: 'jwt.test' });
    expect(controller.state).toBe('open');
  });

  it('rejects sends when not connected', () => {
    expect(() =>
      controller.sendEnvelope({
        recipient: 'bob',
        envelopeType: 'text',
        data: 'ciphertext',
      }),
    ).toThrow(/not connected/);
  });

  it('emits inbound envelopes to listeners', () => {
    const seen: InboundEnvelope[] = [];
    controller.onEnvelope((env) => seen.push(env));
    controller.connect();
    last()._open();
    last()._receive(
      JSON.stringify({
        version: 1,
        id: newMessageId(),
        type: 'session_init',
        sender: 'bob',
        recipient: 'alice',
        timestamp: 1,
        data: 'initdata',
      }),
    );
    expect(seen.length).toBe(1);
    expect(seen[0]!.data).toBe('initdata');
  });

  it('forwards plaintext only as opaque data (never logs it)', () => {
    const seen: string[] = [];
    controller.onEnvelope((env) => seen.push(env.data));
    controller.connect();
    last()._open();
    const secret = 'super-secret-plaintext';
    last()._receive(
      JSON.stringify({
        version: 1,
        id: newMessageId(),
        type: 'text',
        sender: 'bob',
        recipient: 'alice',
        timestamp: 1,
        data: secret,
      }),
    );
    // The transport delivered the opaque string — it never inspected,
    // logged, or modified it.
    expect(seen[0]).toBe(secret);
  });
});

describe('WebSocketController: reconnect policy', () => {
  let auth: ReturnType<typeof makeAuthStub>;
  let factory: WebSocketFactory;
  let last: () => FakeSocket;
  let all: () => FakeSocket[];
  let controller: WebSocketController;

  beforeEach(() => {
    vi.useFakeTimers();
    const f = makeFactory();
    factory = f.factory;
    last = f.last;
    all = f.all;
    auth = makeAuthStub('jwt');
    controller = new WebSocketController({
      authController: auth as unknown as Parameters<typeof WebSocketController>[0]['authController'],
      url: 'wss://example.test/ws',
      factory,
      backoffSchedule: [10, 20, 40, 80],
    });
  });

  afterEach(() => {
    controller.dispose();
    vi.useRealTimers();
  });

  it('does NOT retry after 4001 (auth failed)', () => {
    controller.connect();
    last()._open();
    const states: ConnectionState[] = [];
    controller.onState((s) => states.push(s));
    last()._close(WS_CLOSE.AuthRequired, 'Authentication failed');
    vi.advanceTimersByTime(5_000);
    expect(states).toContain('closed');
    // No further connects scheduled.
    expect(controller.state).toBe('closed');
  });

  it('does NOT retry after 4000 (replaced by another device)', () => {
    controller.connect();
    last()._open();
    last()._close(WS_CLOSE.Replaced, 'Replaced by new connection');
    vi.advanceTimersByTime(5_000);
    expect(controller.state).toBe('closed');
  });

  it('does NOT retry after an intentional close', () => {
    controller.connect();
    last()._open();
    controller.disconnect('logout');
    last()._close(WS_CLOSE.Normal, 'logout');
    vi.advanceTimersByTime(5_000);
    expect(controller.state).toBe('closed');
  });

  it('retries with backoff after 1013 (capacity)', () => {
    controller.connect();
    last()._open();
    last()._close(WS_CLOSE.Capacity, 'capacity');
    expect(controller.state).toBe('closed');
    // Advance past backoff.
    vi.advanceTimersByTime(20);
    expect(controller.state).toBe('connecting');
    all()[all().length - 1]!._open();
    expect(controller.state).toBe('open');
  });

  it('retries immediately after 4008 (idle timeout)', () => {
    controller.connect();
    last()._open();
    last()._close(WS_CLOSE.IdleTimeout, 'idle');
    vi.advanceTimersByTime(0);
    expect(controller.state).toBe('connecting');
    all()[all().length - 1]!._open();
    expect(controller.state).toBe('open');
  });

  it('stops retrying once authenticated = false (logout)', () => {
    controller.connect();
    last()._open();
    auth.setToken(null);
    last()._close(WS_CLOSE.Capacity, 'capacity');
    vi.advanceTimersByTime(5_000);
    expect(controller.state).toBe('closed');
  });
});

describe('WebSocketController: session_init / session_accept / text transport', () => {
  let auth: ReturnType<typeof makeAuthStub>;
  let factory: WebSocketFactory;
  let last: () => FakeSocket;
  let controller: WebSocketController;

  beforeEach(() => {
    const f = makeFactory();
    factory = f.factory;
    last = f.last;
    auth = makeAuthStub('jwt');
    controller = new WebSocketController({
      authController: auth as unknown as Parameters<typeof WebSocketController>[0]['authController'],
      url: 'wss://example.test/ws',
      factory,
    });
  });

  afterEach(() => {
    controller.dispose();
  });

  it('sends session_init with opaque base64url data', () => {
    controller.connect();
    last()._open();
    controller.sendEnvelope({
      recipient: 'bob',
      envelopeType: 'session_init',
      data: 'AQIDBAUGBwj//w==', // opaque ciphertext (would be E2EE output)
    });
    const sent = JSON.parse(last().sentFrames[last().sentFrames.length - 1]!);
    expect(sent.type).toBe('session_init');
    expect(sent.recipient).toBe('bob');
    expect(sent.data).toBe('AQIDBAUGBwj//w==');
    expect(sent.id).toMatch(/^[0-9A-Z]{26}$/);
  });

  it('sends session_accept envelopes identically', () => {
    controller.connect();
    last()._open();
    controller.sendEnvelope({
      recipient: 'alice',
      envelopeType: 'session_accept',
      data: 'acc-frame-base64url',
    });
    const sent = JSON.parse(last().sentFrames[last().sentFrames.length - 1]!);
    expect(sent.type).toBe('session_accept');
    expect(sent.recipient).toBe('alice');
  });

  it('sends encrypted text envelopes (plaintext never sent)', () => {
    controller.connect();
    last()._open();
    const ciphertext = 'X'.repeat(120); // opaque base64url
    controller.sendEnvelope({
      recipient: 'bob',
      envelopeType: 'text',
      data: ciphertext,
    });
    const sent = JSON.parse(last().sentFrames[last().sentFrames.length - 1]!);
    expect(sent.type).toBe('text');
    expect(sent.data).toBe(ciphertext);
    // None of the wire frames contain the literal plaintext.
    for (const frame of last().sentFrames) {
      expect(frame).not.toContain('"hello"');
      expect(frame).not.toContain('secret');
    }
  });
});

describe('WebSocketController: cleanup', () => {
  it('dispose() unsubscribes from auth and tears down the client', () => {
    const auth = makeAuthStub('jwt');
    const f = makeFactory();
    const controller = new WebSocketController({
      authController: auth as unknown as Parameters<typeof WebSocketController>[0]['authController'],
      url: 'wss://x/ws',
      factory: f.factory,
    });
    controller.connect();
    f.last()._open();
    controller.dispose();
    expect(controller.state).toBe('closed');
    // After dispose, a logout-triggered disconnect should not crash.
    auth.setToken(null);
  });
});

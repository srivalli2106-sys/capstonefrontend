import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  WebSocketClient,
  type WebSocketFactory,
  type WebSocketLike,
} from '../src/realtime/WebSocketClient';
import {
  AUTH_FRAME_TYPE,
  MAX_DATA_CHARS,
  MAX_FRAME_CHARS,
  WS_CLOSE,
  type InboundEnvelope,
} from '../src/realtime/types';
import { newMessageId } from '../src/realtime/messageId';

/**
 * Programmable mock that mirrors the subset of the browser WebSocket API
 * the client uses. Tests "drive" the handshake / messages / close from JS
 * code so no real socket is ever opened.
 */
class MockSocket implements WebSocketLike {
  public readyState = 0; // CONNECTING
  public sentFrames: string[] = [];
  public closed = false;
  public onopen: ((ev: Event) => void) | null = null;
  public onclose: ((ev: { code: number; reason: string }) => void) | null = null;
  public onerror: ((ev: Event) => void) | null = null;
  public onmessage: ((ev: { data: string }) => void) | null = null;

  constructor(public readonly url: string) {}

  send(data: string): void {
    this.sentFrames.push(data);
  }

  close(code: number = WS_CLOSE.Normal, reason: string = ''): void {
    this.closed = true;
    this.readyState = 3; // CLOSED
    if (this.onclose) this.onclose({ code, reason });
  }

  // Test driver helpers (not part of the WebSocket interface).
  _open(): void {
    this.readyState = 1; // OPEN
    if (this.onopen) this.onopen(new Event('open'));
  }

  _receive(data: string): void {
    if (this.onmessage) this.onmessage({ data });
  }

  _error(): void {
    if (this.onerror) this.onerror(new Event('error'));
  }
}

function makeFactory(): { factory: WebSocketFactory; last: () => MockSocket } {
  let socket: MockSocket | null = null;
  return {
    factory: {
      create: (url) => {
        socket = new MockSocket(url);
        return socket;
      },
    },
    last: () => {
      if (socket === null) throw new Error('no socket yet');
      return socket;
    },
  };
}

describe('WebSocketClient: handshake + first-frame auth', () => {
  let factory: WebSocketFactory;
  let last: () => MockSocket;
  let client: WebSocketClient;

  beforeEach(() => {
    const f = makeFactory();
    factory = f.factory;
    last = f.last;
    client = new WebSocketClient({
      url: 'wss://example.test/ws',
      token: 'jwt.test.token',
      factory,
    });
  });

  afterEach(() => {
    client.close();
  });

  it('connects and sends the auth frame on open', () => {
    client.connect();
    expect(last().sentFrames.length).toBe(0);
    last()._open();
    expect(last().sentFrames.length).toBe(1);
    const auth = JSON.parse(last().sentFrames[0]!);
    expect(auth.type).toBe(AUTH_FRAME_TYPE);
    expect(auth.token).toBe('jwt.test.token');
    expect(client.didSendAuthFrame).toBe(true);
    expect(client.currentState).toBe('open');
  });

  it('rejects sends before open', () => {
    expect(() =>
      client.send({
        id: newMessageId(),
        type: 'text',
        recipient: 'bob',
        data: 'abcd',
      }),
    ).toThrow(/not open/);
  });

  it('rejects sends with bad message id', () => {
    client.connect();
    last()._open();
    expect(() =>
      client.send({
        id: 'short',
        type: 'text',
        recipient: 'bob',
        data: 'abcd',
      }),
    ).toThrow(/invalid message id/);
  });

  it('rejects unsupported envelope types', () => {
    client.connect();
    last()._open();
    expect(() =>
      client.send({
        id: newMessageId(),
        // @ts-expect-error - intentionally invalid
        type: 'bogus',
        recipient: 'bob',
        data: 'abcd',
      }),
    ).toThrow(/unsupported type/);
  });

  it('rejects oversized recipients and data', () => {
    client.connect();
    last()._open();
    expect(() =>
      client.send({
        id: newMessageId(),
        type: 'text',
        recipient: 'x'.repeat(65),
        data: 'abcd',
      }),
    ).toThrow(/invalid recipient/);
    expect(() =>
      client.send({
        id: newMessageId(),
        type: 'text',
        recipient: 'bob',
        data: 'x'.repeat(MAX_DATA_CHARS + 1),
      }),
    ).toThrow(/invalid data/);
  });

  it('sends well-formed envelopes as compact JSON', () => {
    client.connect();
    last()._open();
    const id = newMessageId();
    client.send({
      id,
      type: 'session_init',
      recipient: 'bob',
      data: 'AbCdEf',
    });
    const sent = JSON.parse(last().sentFrames[last().sentFrames.length - 1]!);
    expect(sent).toEqual({ id, type: 'session_init', recipient: 'bob', data: 'AbCdEf' });
  });
});

describe('WebSocketClient: inbound validation', () => {
  let last: () => MockSocket;
  let client: WebSocketClient;

  beforeEach(() => {
    const f = makeFactory();
    client = new WebSocketClient({
      url: 'wss://example.test/ws',
      token: 'jwt',
      factory: f.factory,
    });
    last = f.last;
  });

  it('parses valid envelopes and dispatches to listeners', () => {
    const seen: InboundEnvelope[] = [];
    client.onEnvelope((env) => seen.push(env));
    client.connect();
    last()._open();

    last()._receive(
      JSON.stringify({
        version: 1,
        id: newMessageId(),
        type: 'text',
        sender: 'bob',
        recipient: 'alice',
        timestamp: 1750000000000,
        data: 'ciphertext',
      }),
    );
    expect(seen.length).toBe(1);
    expect(seen[0]!.sender).toBe('bob');
    expect(seen[0]!.data).toBe('ciphertext');
  });

  it('drops malformed envelopes silently (mirrors backend)', () => {
    const seen: InboundEnvelope[] = [];
    client.onEnvelope((env) => seen.push(env));
    client.connect();
    last()._open();

    last()._receive('not-json');
    last()._receive(JSON.stringify({}));
    last()._receive(
      JSON.stringify({
        version: 99, // bad version
        id: newMessageId(),
        type: 'text',
        sender: 'bob',
        recipient: 'alice',
        timestamp: 1,
        data: 'x',
      }),
    );
    last()._receive(
      JSON.stringify({
        version: 1,
        id: 'short', // bad id
        type: 'text',
        sender: 'bob',
        recipient: 'alice',
        timestamp: 1,
        data: 'x',
      }),
    );
    last()._receive(
      JSON.stringify({
        version: 1,
        id: newMessageId(),
        type: 'foo', // unsupported
        sender: 'bob',
        recipient: 'alice',
        timestamp: 1,
        data: 'x',
      }),
    );
    expect(seen.length).toBe(0);
  });

  it('closes on inbound frame larger than the transport bound', () => {
    const closeCodes: number[] = [];
    client.onState((state, info) => {
      if (state === 'closed' && info && 'code' in info) {
        closeCodes.push((info as { code: number }).code);
      }
    });
    client.connect();
    last()._open();
    const oversized = 'x'.repeat(MAX_FRAME_CHARS + 10);
    last()._receive(oversized);
    expect(closeCodes).toContain(WS_CLOSE.PolicyViolation);
    expect(client.currentState).toBe('closed');
  });
});

describe('WebSocketClient: state transitions + close', () => {
  let last: () => MockSocket;
  let client: WebSocketClient;

  beforeEach(() => {
    const f = makeFactory();
    client = new WebSocketClient({ url: 'wss://x/ws', token: 't', factory: f.factory });
    last = f.last;
  });

  it('transitions idle → connecting → authenticating → open → closed', () => {
    const states: string[] = [];
    client.onState((s) => states.push(s));
    client.connect();
    expect(states).toContain('connecting');
    last()._open();
    expect(states).toContain('authenticating');
    expect(states).toContain('open');
    last().close(WS_CLOSE.Normal, '');
    expect(states).toContain('closed');
  });

  it('marks intentional close so the controller can skip reconnect', () => {
    client.connect();
    last()._open();
    client.close(WS_CLOSE.Normal, 'logout');
    expect(client.didIntentionalClose).toBe(true);
  });

  it('marks non-intentional close on server-initiated close', () => {
    client.connect();
    last()._open();
    last().close(WS_CLOSE.IdleTimeout, '');
    expect(client.didIntentionalClose).toBe(false);
  });
});

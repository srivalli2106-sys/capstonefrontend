/**
 * Thin, dependency-free wrapper around the browser WebSocket API.
 *
 * Responsibilities (no crypto, no app logic):
 *   * open with a first-frame auth message ``{"type":"auth","token":"<JWT>"}``
 *   * send outbound envelopes (validated, size-bounded)
 *   * parse inbound envelopes (validated; server-authoritative fields trusted)
 *   * heartbeat: respond to server pings with pongs (browser handles this
 *     automatically, but we expose hooks for tests)
 *   * emit state / envelope / error listeners
 *   * close cleanly on demand
 *
 * The transport does NOT touch IndexedDB, key material, or plaintext. Plain
 * content is provided as opaque strings (base64url-encoded E2EE ciphertext)
 * by the caller.
 */

import {
  AUTH_FRAME_TYPE,
  ENVELOPE_VERSION,
  MAX_FRAME_CHARS,
  MAX_DATA_CHARS,
  MAX_USER_ID_LENGTH,
  WS_CLOSE,
  isSupportedEnvelopeType,
  type AuthFrame,
  type CloseInfo,
  type ConnectionError,
  type ConnectionState,
  type EnvelopeListener,
  type InboundEnvelope,
  type OutboundEnvelope,
  type StateListener,
} from './types';
import { isValidMessageId } from './messageId';

/**
 * WebSocket constructor shape; declared as an interface so tests can inject
 * a mock without touching globalThis.
 */
export interface WebSocketLike {
  readonly readyState: number;
  send(data: string): void;
  close(code?: number, reason?: string): void;
  onopen: ((ev: Event) => void) | null;
  onclose: ((ev: { code: number; reason: string }) => void) | null;
  onerror: ((ev: Event) => void) | null;
  onmessage: ((ev: { data: string }) => void) | null;
}

export interface WebSocketFactory {
  create(url: string): WebSocketLike;
}

const DEFAULT_FACTORY: WebSocketFactory = {
  create(url) {
    return new globalThis.WebSocket(url) as unknown as WebSocketLike;
  },
};

export interface WebSocketClientOptions {
  url: string;
  token: string;
  factory?: WebSocketFactory;
}

export class WebSocketClient {
  private readonly url: string;
  private readonly token: string;
  private readonly factory: WebSocketFactory;
  private ws: WebSocketLike | null = null;
  private state: ConnectionState = 'idle';
  private envelopeListeners: Set<EnvelopeListener> = new Set();
  private stateListeners: Set<StateListener> = new Set();
  private authFrameSent = false;
  private intentionalClose = false;

  constructor(options: WebSocketClientOptions) {
    this.url = options.url;
    this.token = options.token;
    this.factory = options.factory ?? DEFAULT_FACTORY;
  }

  public get currentState(): ConnectionState {
    return this.state;
  }

  public onEnvelope(listener: EnvelopeListener): () => void {
    this.envelopeListeners.add(listener);
    return () => this.envelopeListeners.delete(listener);
  }

  public onState(listener: StateListener): () => void {
    this.stateListeners.add(listener);
    // Replay current state.
    listener(this.state);
    return () => this.stateListeners.delete(listener);
  }

  public connect(): void {
    if (this.ws !== null) {
      // Re-entry while connected: no-op (caller can call disconnect first).
      return;
    }
    this.intentionalClose = false;
    this.authFrameSent = false;
    this.setState('connecting');
    const ws = this.factory.create(this.url);
    this.ws = ws;

    ws.onopen = () => {
      this.setState('authenticating');
      const frame: AuthFrame = { type: AUTH_FRAME_TYPE, token: this.token };
      ws.send(JSON.stringify(frame));
      this.authFrameSent = true;
      this.setState('open');
    };

    ws.onmessage = (ev) => {
      if (typeof ev.data !== 'string') {
        // Binary frames are dropped (per backend policy).
        return;
      }
      const parsed = this.parseIncoming(ev.data);
      if (parsed === 'invalid') {
        // Backend drops malformed frames silently — same here.
        return;
      }
      if (parsed === 'too_large') {
        this.failWith({
          code: 'too_large',
          message: 'inbound frame too large',
        } as ConnectionError);
        this.close(WS_CLOSE.PolicyViolation, 'inbound frame too large');
        return;
      }
      for (const listener of this.envelopeListeners) {
        listener(parsed);
      }
    };

    ws.onerror = () => {
      // The accompanying onclose carries the close code; surface a generic
      // error event so subscribers can react before close.
      this.notifyError(new Error('websocket error'));
    };

    ws.onclose = (ev) => {
      const info: CloseInfo = { code: ev.code, reason: ev.reason };
      this.ws = null;
      this.setState('closed', info);
    };
  }

  /**
   * Send one envelope. Caller supplies an authenticated, validated envelope.
   * The transport does NOT inspect ``data`` (always opaque ciphertext).
   */
  public send(envelope: OutboundEnvelope): void {
    if (this.state !== 'open') {
      throw new Error(`WebSocketClient.send: not open (state=${this.state})`);
    }
    if (!isValidMessageId(envelope.id)) {
      throw new Error('WebSocketClient.send: invalid message id');
    }
    if (!isSupportedEnvelopeType(envelope.type)) {
      throw new Error(`WebSocketClient.send: unsupported type ${envelope.type}`);
    }
    if (!envelope.recipient || envelope.recipient.length > MAX_USER_ID_LENGTH) {
      throw new Error('WebSocketClient.send: invalid recipient');
    }
    if (!envelope.data || envelope.data.length > MAX_DATA_CHARS) {
      throw new Error('WebSocketClient.send: invalid data');
    }
    const json = JSON.stringify(envelope);
    if (json.length > MAX_FRAME_CHARS) {
      throw new Error('WebSocketClient.send: frame too large');
    }
    (this.ws as unknown as { send(data: string): void }).send(json);
  }

  public close(code: number = WS_CLOSE.Normal, reason: string = ''): void {
    if (this.ws === null) {
      return;
    }
    this.intentionalClose = true;
    this.setState('closing');
    try {
      this.ws.close(code, reason);
    } catch {
      // Best-effort close; the onclose handler will run.
    }
  }

  /** True iff close() was invoked (as opposed to a server-initiated close). */
  public get didIntentionalClose(): boolean {
    return this.intentionalClose;
  }

  /** True iff the auth frame has been sent on the active connection. */
  public get didSendAuthFrame(): boolean {
    return this.authFrameSent;
  }

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  private parseIncoming(raw: string): InboundEnvelope | 'invalid' | 'too_large' {
    if (raw.length > MAX_FRAME_CHARS) return 'too_large';
    let obj: unknown;
    try {
      obj = JSON.parse(raw);
    } catch {
      return 'invalid';
    }
    if (!obj || typeof obj !== 'object') return 'invalid';
    const env = obj as Record<string, unknown>;
    if (env['version'] !== ENVELOPE_VERSION) return 'invalid';
    if (!isValidMessageId(env['id'])) return 'invalid';
    if (!isSupportedEnvelopeType(env['type'])) return 'invalid';
    if (typeof env['sender'] !== 'string' || !env['sender']) return 'invalid';
    if (typeof env['recipient'] !== 'string' || !env['recipient']) return 'invalid';
    if (env['recipient'].length > MAX_USER_ID_LENGTH) return 'invalid';
    if (typeof env['data'] !== 'string' || !env['data']) return 'invalid';
    if (env['data'].length > MAX_DATA_CHARS) return 'invalid';
    if (typeof env['timestamp'] !== 'number' || !Number.isFinite(env['timestamp'])) {
      return 'invalid';
    }
    return {
      version: ENVELOPE_VERSION,
      id: env['id'] as string,
      type: env['type'] as InboundEnvelope['type'],
      sender: env['sender'] as string,
      recipient: env['recipient'] as string,
      timestamp: env['timestamp'] as number,
      data: env['data'] as string,
    };
  }

  private setState(state: ConnectionState, info?: CloseInfo | Error): void {
    this.state = state;
    for (const listener of this.stateListeners) {
      listener(state, info);
    }
  }

  private failWith(err: ConnectionError): void {
    for (const listener of this.stateListeners) {
      listener(this.state, err);
    }
  }

  private notifyError(err: Error): void {
    for (const listener of this.stateListeners) {
      listener(this.state, err);
    }
  }
}

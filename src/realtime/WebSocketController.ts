/**
 * WebSocketController — high-level transport controller.
 *
 * Wraps a `WebSocketClient` with:
 *   * JWT provisioning from the existing AuthController (read-only — never
 *     stores tokens on its own).
 *   * Bounded exponential backoff for reconnection (only after network
 *     failures or non-auth close codes; never after 4001 / intentional close).
 *   * Session lifecycle integration: `connect()` on unlock + login,
 *     `disconnect()` on lock / logout / identity wipe.
 *   * Hooks for sending encrypted text/session_init/session_accept envelopes
 *     (the transport never sees plaintext — callers supply ciphertext).
 *
 * Reconnect policy:
 *   * 4001 (auth failed / revoked) — do NOT retry. Caller must re-login.
 *   * 4000 (replaced) — stop; another device took over.
 *   * 4003 (policy) — do NOT retry.
 *   * 1009 / 1013 — backoff then retry.
 *   * 1001 / network failure — backoff then retry.
 *   * 4008 (idle) — retry immediately.
 *   * Intentional close — no retry.
 */

import { authController as defaultAuthController } from '../auth/AuthController';
import {
  WebSocketClient,
  type WebSocketFactory,
  type WebSocketLike,
} from './WebSocketClient';
import {
  type ConnectionState,
  type EnvelopeListener,
  type InboundEnvelope,
  WS_CLOSE,
} from './types';
import { config } from '../config/env';

export type AuthControllerLike = typeof defaultAuthController;

export interface WebSocketControllerOptions {
  authController: AuthControllerLike;
  url?: string;
  factory?: WebSocketFactory;
  /** Backoff schedule in milliseconds (defaults below). */
  backoffSchedule?: number[];
}

const DEFAULT_BACKOFF = [1_000, 2_000, 4_000, 8_000, 15_000, 30_000];

export interface SendEncryptedOptions {
  recipient: string;
  envelopeType: 'session_init' | 'session_accept' | 'text' | 'file' | 'delivery_receipt' | 'read_receipt' | 'typing';
  /** Opaque base64url ciphertext (E2EE produced). The transport NEVER inspects it. */
  data: string;
}

export class WebSocketController {
  private readonly authController: AuthControllerLike;
  private readonly url: string;
  private readonly factory: WebSocketFactory;
  private readonly backoff: number[];
  private client: WebSocketClient | null = null;
  private retryAttempt = 0;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private unsubscribeAuth: (() => void) | null = null;
  private envelopeBuffer: InboundEnvelope[] = [];
  private envelopeListeners: Set<EnvelopeListener> = new Set();
  private stateListeners: Set<(state: ConnectionState, info?: unknown) => void> = new Set();
  private lastState: ConnectionState = 'idle';

  constructor(options: WebSocketControllerOptions) {
    this.authController = options.authController;
    this.url = options.url ?? `${config.wsBaseUrl}/ws`;
    this.factory = options.factory ?? {
      create: (url) => new globalThis.WebSocket(url) as unknown as WebSocketLike,
    };
    this.backoff = options.backoffSchedule ?? DEFAULT_BACKOFF;
    this.unsubscribeAuth = this.authController.subscribe(
      (snap: { authenticated: boolean; identity?: { kind: string } }) => {
        if (!snap.authenticated) {
          this.disconnect('logout');
          return;
        }
        // Spec §9: identity lock must disconnect transport and disable reconnect.
        const identity = (snap as { identity?: { kind: string } }).identity;
        if (identity !== undefined && identity.kind === 'locked') {
          this.disconnect('lock');
          return;
        }
        // Authenticated and identity is not locked — ensure the transport is
        // open. connect() is a no-op when the client is already open or
        // connecting, and returns silently when no JWT is held yet; the next
        // auth transition will retry.
        this.connect();
      },
    );
  }


  public getAuthController(): AuthControllerLike {
    return this.authController;
  }

  public dispose(): void {
    if (this.unsubscribeAuth !== null) {
      this.unsubscribeAuth();
      this.unsubscribeAuth = null;
    }
    this.clearRetry();
    this.disconnect('dispose');
  }

  /**
   * Open the transport. No-op if already open/connecting. Re-entry is safe
   * (caller may invoke after auth-state transitions).
   */
  public connect(): void {
    if (this.client !== null) {
      return;
    }
    const token = this.authController.getToken();
    if (token === null) {
      return; // Not authenticated; silently wait for auth state.
    }
    this.openClient(token);
  }

  /**
   * Close the transport. `reason` is one of:
   *   * 'logout' / 'lock' — explicit caller intent (never reconnects).
   *   * 'dispose'          — controller teardown.
   *   * 'manual'           — generic user disconnect (still doesn't reconnect).
   */
  public disconnect(reason: 'logout' | 'lock' | 'dispose' | 'manual' = 'manual'): void {
    this.clearRetry();
    if (this.client === null) return;
    this.client.close(WS_CLOSE.Normal, reason);
    this.lastState = 'closed';
    for (const listener of this.stateListeners) {
      listener('closed', { code: WS_CLOSE.Normal, reason });
    }
    this.client = null;
  }

  public get state(): ConnectionState {
    return this.client?.currentState ?? this.lastState;
  }

  public onEnvelope(listener: EnvelopeListener): () => void {
    this.envelopeListeners.add(listener);
    // Drain any envelopes buffered while no listener was attached (so a
    // late-attaching UI hook still gets the message — but only if it's
    // still relevant; the caller is responsible for ordering).
    if (this.envelopeBuffer.length > 0) {
      const drained = this.envelopeBuffer.splice(0);
      for (const env of drained) listener(env);
    }
    return () => this.envelopeListeners.delete(listener);
  }

  public onState(listener: (state: ConnectionState, info?: unknown) => void): () => void {
    this.stateListeners.add(listener);
    listener(this.state);
    return () => this.stateListeners.delete(listener);
  }

  public sendEnvelope(opts: SendEncryptedOptions): void {
    if (this.client === null || this.client.currentState !== 'open') {
      throw new Error('WebSocketController.sendEnvelope: not connected');
    }
    // The transport only ever sees opaque base64url strings; it never
    // inspects the application data field.
    this.client.send({
      id: newMessageId(),
      type: opts.envelopeType,
      recipient: opts.recipient,
      data: opts.data,
    });
  }

  /**
   * Send an already-built envelope (e.g. for tests or when the caller has
   * their own id generator). Same rules as sendEnvelope.
   */
  public sendRaw(envelope: { id: string; type: SendEncryptedOptions['envelopeType']; recipient: string; data: string }): void {
    if (this.client === null || this.client.currentState !== 'open') {
      throw new Error('WebSocketController.sendRaw: not connected');
    }
    this.client.send({
      id: envelope.id,
      type: envelope.type,
      recipient: envelope.recipient,
      data: envelope.data,
    });
  }

  // ---------------------------------------------------------------------------
  // Internal: client lifecycle
  // ---------------------------------------------------------------------------

  private openClient(token: string): void {
    const client = new WebSocketClient({
      url: this.url,
      token,
      factory: this.factory,
    });
    this.client = client;

    client.onEnvelope((env) => this.dispatchEnvelope(env));

    client.onState((state, info) => {
      this.lastState = state;
      for (const listener of this.stateListeners) {
        listener(state, info);
      }
      if (state === 'open') {
        this.retryAttempt = 0;
        return;
      }
      if (state !== 'closed') {
        return;
      }
      // Drop the client reference so scheduleReconnect can proceed; the
      // WebSocketClient's own internal socket has already been cleared.
      this.client = null;
      // Decide whether to reconnect.
      const closeInfo = (info && 'code' in info ? (info as { code: number; reason?: string }) : null);
      const code = closeInfo?.code ?? WS_CLOSE.Normal;
      if (client.didIntentionalClose) return;
      const decision = this.classifyClose(code);
      if (decision === 'stop') return;
      if (decision === 'immediate') {
        this.scheduleReconnect(0);
        return;
      }
      this.scheduleReconnect(this.nextDelay());
    });

    client.connect();
  }

  private classifyClose(code: number): 'retry' | 'immediate' | 'stop' {
    switch (code) {
      case WS_CLOSE.AuthRequired: // 4001
      case WS_CLOSE.Replaced: // 4000
      case WS_CLOSE.PolicyViolation: // 4003
      case WS_CLOSE.Normal: // 1000
      case WS_CLOSE.GoingAway: // 1001 from intentional close — already filtered above
        return 'stop';
      case WS_CLOSE.IdleTimeout: // 4008
        return 'immediate';
      case WS_CLOSE.TooLarge: // 1009
      case WS_CLOSE.Capacity: // 1013
      case WS_CLOSE.GoingAway: // 1001
      default:
        return 'retry';
    }
  }

  private nextDelay(): number {
    const idx = Math.min(this.retryAttempt, this.backoff.length - 1);
    const base = this.backoff[idx] ?? 30_000;
    this.retryAttempt += 1;
    // Full jitter (± 25%) to avoid thundering herd.
    const jitter = base * (0.75 + Math.random() * 0.5);
    return Math.round(jitter);
  }

  private scheduleReconnect(delayMs: number): void {
    this.clearRetry();
    if (this.client !== null) return; // someone else already connected
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      this.connect();
    }, Math.max(0, delayMs));
  }

  private clearRetry(): void {
    if (this.retryTimer !== null) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
  }

  private dispatchEnvelope(env: InboundEnvelope): void {
    if (this.envelopeListeners.size === 0) {
      // Buffer the envelope for a late-joining listener (bounded).
      this.envelopeBuffer.push(env);
      if (this.envelopeBuffer.length > 256) {
        this.envelopeBuffer.shift();
      }
      return;
    }
    for (const listener of this.envelopeListeners) {
      listener(env);
    }
  }
}

// Imported here to avoid a circular dependency at the top.
import { newMessageId } from './messageId';

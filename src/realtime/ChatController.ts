/**
 * ChatController — in-memory E2EE session store + WebSocket bridge (Phase 8).
 *
 * Architecture:
 *
 *   ChatPage  ──uses──▶  ChatController  ──uses──▶  E2EESession (crypto)
 *                              │
 *                              └──uses──▶  WebSocketController (transport)
 *                              │
 *                              └──uses──▶  WebSocketClient
 *
 * Responsibilities:
 *
 *   * Maintain one E2EESession per peer (in-memory only — Phase 6 export is
 *     available but NOT wired into persistent storage for this phase; the
 *     rule is "don't persist crypto material unless required" and the
 *     backend has no message-history API to reconcile against).
 *   * Establish sessions on demand (Alice side: fetch bundle + X3DH initiate
 *     + send `session_init`). On incoming `session_init`, accept X3DH and
 *     build the responder session. Send an empty `session_accept` envelope
 *     as a UI-visible confirmation receipt (the server treats both as opaque).
 *   * Encrypt outgoing plaintext (UTF-8 → wire bytes via the ratchet session)
 *     and dispatch the opaque ciphertext through `WebSocketController` as a
 *     `text` envelope. The transport NEVER sees plaintext.
 *   * Decrypt incoming `text` ciphertext using the matching session.
 *   * Route incoming envelopes to handlers (incoming messages, session
 *     errors).
 *   * Clear ALL sessions + disconnect transport on identity lock / logout /
 *     controller dispose.
 *
 * What this module deliberately does NOT do:
 *   * Persist ratchet state.
 *   * Show "delivered" / "read" indicators (backend does not support them).
 *   * Buffer undelivered outbound messages while disconnected (the UI shows
 *     them as 'failed' and the user retries — matches the backend's actual
 *     behavior; queueing would imply persistence).
 *   * Build the application chat UI — that lives in `pages/ChatPage.tsx`.
 */

import { type HttpRequestOptions } from '../api/http';
import { ApiError } from '../api/http';
import { getKeyBundle } from '../api/keys';
import { parseRemoteKeyBundle, KeyBundleError, type RemoteKeyBundle } from '../crypto/keyBundle';
import {
  E2EESession,
  SessionError,
} from '../crypto/e2eeSession';
import type { DeviceKeysPrivate } from '../crypto/deviceKeys';
import { x25519PublicFromPrivate } from '../crypto/x25519';
import { decodeBase64Url, encodeBase64Url } from '../crypto/base64url';
import {
  WebSocketController,
  type AuthControllerLike,
} from './WebSocketController';
import { type InboundEnvelope } from './types';
import { hexToBytes } from '../crypto/hex';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type ChatErrorCode =
  | 'no_identity'
  | 'no_jwt'
  | 'peer_not_found'
  | 'invalid_bundle'
  | 'backend_blocker'
  | 'session_init_failed'
  | 'session_decrypt_failed'
  | 'send_failed'
  | 'unknown';

export interface ChatError {
  code: ChatErrorCode;
  message: string;
  requestId: string | null;
}

/** Status of an outbound message — kept minimal & honest. */
export type OutboundStatus = 'sending' | 'sent' | 'failed';

export interface OutboundMessage {
  /** Stable client id so the UI can correlate retries and renders. */
  readonly id: string;
  readonly recipientUserId: string;
  readonly plaintext: string;
  readonly createdAt: number;
  status: OutboundStatus;
  errorMessage: string | null;
}

/** Decrypted message that the UI will render. */
export interface DisplayMessage {
  readonly id: string;
  readonly senderUserId: string;
  readonly recipientUserId: string;
  readonly plaintext: string;
  readonly createdAt: number; // server-authoritative timestamp when available
  readonly outgoing: boolean;
  /** Mutable only on outbound messages (`sending` → `sent` / `failed`). */
  status: OutboundStatus | null;
  /** Mutable only on outbound messages. */
  errorMessage: string | null;
  readonly sessionReady: boolean;
}

export type SessionState =
  | { kind: 'none' }
  | { kind: 'initiating' }
  | { kind: 'ready'; role: 'initiator' | 'responder' }
  | { kind: 'error'; error: ChatError };

export interface ConversationSnapshot {
  peerUserId: string;
  session: SessionState;
  messages: DisplayMessage[];
  /** Most recent activity timestamp (epoch ms) — drives the sidebar ordering. */
  lastActivityAt: number;
}

export interface ChatSnapshot {
  connected: boolean;
  /** The current authenticated user id (may be null briefly during logout). */
  selfUserId: string | null;
  conversations: ConversationSnapshot[];
}

/** Listener for snapshot updates from the ChatController. */
export type ChatListener = (snapshot: ChatSnapshot) => void;

// ---------------------------------------------------------------------------
// ChatController
// ---------------------------------------------------------------------------

export interface ChatControllerOptions {
  authController: AuthControllerLike;
  webSocketController: WebSocketController;
}

/** Throttle for client message-id generation (avoids ULID collisions on bursts). */
let outboundIdCursor = 0;
function newOutboundId(): string {
  outboundIdCursor += 1;
  return `c-${Date.now().toString(36)}-${outboundIdCursor.toString(36)}`;
}

function encodeChatError(code: ChatErrorCode, message: string, requestId: string | null = null): ChatError {
  return { code, message, requestId };
}

function chatErrorFromUnknown(err: unknown, fallback: ChatErrorCode = 'unknown'): ChatError {
  if (err instanceof ApiError) {
    if (err.status === 404) {
      return encodeChatError('peer_not_found', 'Recipient has no registered key bundle.', err.requestId);
    }
    if (err.status === 0) {
      return encodeChatError('send_failed', 'Unable to reach the backend.', err.requestId);
    }
    return encodeChatError('backend_blocker', err.message, err.requestId);
  }
  if (err instanceof KeyBundleError) {
    return encodeChatError('invalid_bundle', err.message);
  }
  if (err instanceof SessionError) {
    return encodeChatError('session_init_failed', err.message);
  }
  if (err && typeof err === 'object' && 'code' in err) {
    // X3dhError or RatchetError — surface a safe diagnostic only.
    const code = String((err as { code: string }).code);
    return encodeChatError('session_decrypt_failed', `Crypto failure (${code})`);
  }
  const message = err instanceof Error ? err.message : 'Unexpected error.';
  return encodeChatError(fallback, message);
}

interface Conversation {
  peerUserId: string;
  session: E2EESession | null;
  sessionState: SessionState;
  messages: DisplayMessage[];
  lastActivityAt: number;
  /** True while the X3DH session establishment is in flight. */
  initiating: boolean;
  /** True while an outbound send is in progress (prevents double-sends). */
  sending: boolean;
}

export class ChatController {
  private readonly authController: AuthControllerLike;
  private readonly webSocket: WebSocketController;
  private readonly conversations: Map<string, Conversation> = new Map();
  private listeners: Set<ChatListener> = new Set();
  private unsubscribeAuth: (() => void) | null = null;
  private unsubscribeWs: (() => void) | null = null;
  private readonly textDecoder = new TextDecoder();
  private readonly textEncoder = new TextEncoder();
  /** Monotonic ids for messages we put on the wire. */
  private readonly outboundMessageIds: Set<string> = new Set();
  /** Dedup: envelope ids already processed (bounded ring). */
  private readonly receivedMessageIds: Set<string> = new Set();
  private static readonly MAX_RECEIVED_IDS = 2048;

  constructor(options: ChatControllerOptions) {
    this.authController = options.authController;
    this.webSocket = options.webSocketController;
    this.unsubscribeAuth = this.authController.subscribe((snap) => {
      // Clear sensitive in-memory sessions on logout OR identity lock.
      // Spec §9 / §13: logout/lock must wipe material and clear state.
      const identity = (snap as { identity?: { kind: string } }).identity;
      if (!snap.authenticated || (identity !== undefined && identity.kind === 'locked')) {
        this.clearAllSessions();
      }
      this.notify();
    });
    this.unsubscribeWs = this.webSocket.onEnvelope((env) => {
      this.handleInbound(env);
    });
  }

  /** Dispose all listeners + sessions; safe to call multiple times. */
  public dispose(): void {
    if (this.unsubscribeAuth !== null) {
      this.unsubscribeAuth();
      this.unsubscribeAuth = null;
    }
    if (this.unsubscribeWs !== null) {
      this.unsubscribeWs();
      this.unsubscribeWs = null;
    }
    this.clearAllSessions();
    this.listeners.clear();
  }

  public subscribe(listener: ChatListener): () => void {
    this.listeners.add(listener);
    listener(this.getSnapshot());
    return () => {
      this.listeners.delete(listener);
    };
  }

  public getSnapshot(): ChatSnapshot {
    const authed = this.authController.getToken();
    const self = this.authController.getUserId();
    if (authed === null || self === null) {
      return { connected: this.webSocket.state === 'open', selfUserId: null, conversations: [] };
    }
    const conversations = Array.from(this.conversations.values())
      .map((c) => this.toSnapshot(c))
      .sort((a, b) => b.lastActivityAt - a.lastActivityAt);
    return {
      connected: this.webSocket.state === 'open',
      selfUserId: self,
      conversations,
    };
  }

  /**
   * Open (or re-open) a conversation with the given peer. Idempotent.
   * Establishes the X3DH session on demand; does not connect the transport
   * here (the WebSocketController handles its own lifecycle).
   */
  public async openConversation(peerUserId: string): Promise<void> {
    const peer = peerUserId.trim();
    if (peer.length < 3 || peer.length > 64) {
      throw encodeChatError('peer_not_found', 'Recipient user_id must be 3..64 characters.');
    }
    const self = this.authController.getUserId();
    if (self === null || self === peer) {
      throw encodeChatError('no_identity', 'Cannot open a conversation with yourself or while unauthenticated.');
    }
    const conv = this.ensureConversation(peer);
    conv.lastActivityAt = Date.now();
    this.notify();
    if (conv.session !== null || conv.initiating) {
      return;
    }
    conv.initiating = true;
    conv.sessionState = { kind: 'initiating' };
    this.notify();

    try {
      const session = await this.establishInitiatorSession(peer);
      conv.session = session;
      conv.sessionState = { kind: 'ready', role: 'initiator' };
      conv.initiating = false;
      // Send session_init envelope with the base64url(initPayload). This is
      // the canonical X3DH handshake over the existing WebSocket transport.
      const initB64 = session.encodeInitPayloadBase64Url();
      this.webSocket.sendEnvelope({
        recipient: peer,
        envelopeType: 'session_init',
        data: initB64,
      });
      conv.lastActivityAt = Date.now();
    } catch (err) {
      conv.initiating = false;
      conv.sessionState = {
        kind: 'error',
        error: chatErrorFromUnknown(err, 'session_init_failed'),
      };
    }
    this.notify();
  }

  /**
   * Send one plaintext message. The plaintext is encrypted inside the
   * matching E2EESession and ONLY the resulting ciphertext leaves the
   * controller — `WebSocketController.sendEnvelope` is given opaque base64url.
   * Throws if the session isn't ready (the UI should disable the composer
   * in that state, but we throw defensively).
   */
  public async sendText(peerUserId: string, plaintext: string): Promise<DisplayMessage> {
    const conv = this.ensureConversation(peerUserId);
    if (conv.session === null) {
      throw encodeChatError(
        'session_init_failed',
        'Secure session is not ready. Open the conversation first.',
      );
    }
    const trimmed = plaintext.trim();
    if (trimmed.length === 0) {
      throw encodeChatError('send_failed', 'Empty messages are not sent.');
    }
    if (conv.sending) {
      throw encodeChatError('send_failed', 'A message is already being sent. Please wait.');
    }
    conv.sending = true;
    const id = newOutboundId();
    this.outboundMessageIds.add(id);
    const createdAt = Date.now();
    const outbound: DisplayMessage = {
      id,
      senderUserId: this.authController.getUserId() ?? '',
      recipientUserId: peerUserId,
      plaintext,
      createdAt,
      outgoing: true,
      status: 'sending',
      errorMessage: null,
      sessionReady: true,
    };
    conv.messages.push(outbound);
    conv.lastActivityAt = createdAt;
    this.notify();

    try {
      const ciphertext = await conv.session.encryptMessage(
        this.textEncoder.encode(plaintext),
        new Uint8Array(0),
      );
      const data = encodeBase64Url(ciphertext);
      this.webSocket.sendEnvelope({
        recipient: peerUserId,
        envelopeType: 'text',
        data,
      });
      outbound.status = 'sent';
    } catch (err) {
      outbound.status = 'failed';
      outbound.errorMessage =
        err instanceof Error ? err.message : 'Encryption or send failed.';
      // Record a safe diagnostic in the snapshot; do NOT log the plaintext.
      conv.sessionState = {
        kind: 'error',
        error: chatErrorFromUnknown(err, 'send_failed'),
      };
    } finally {
      conv.sending = false;
    }
    this.notify();
    return outbound;
  }

  /**
   * Remove a conversation from the in-memory store. Wipes its session.
   * Does NOT send anything over the wire.
   */
  public closeConversation(peerUserId: string): void {
    const conv = this.conversations.get(peerUserId);
    if (conv === undefined) return;
    if (conv.session !== null) {
      conv.session.wipe();
    }
    this.conversations.delete(peerUserId);
    this.notify();
  }

  // ---------------------------------------------------------------------------
  // Internal: session establishment
  // ---------------------------------------------------------------------------

  private async establishInitiatorSession(peerUserId: string): Promise<E2EESession> {
    const identity = this.authController.getUnlockedIdentity();
    if (identity === null) {
      throw encodeChatError(
        'no_identity',
        'Identity is locked. Unlock it in Settings before starting a conversation.',
      );
    }
    const deviceKeys = identity.deviceKeys;
    if (deviceKeys === null) {
      throw encodeChatError(
        'no_identity',
        'Device keys are missing on this identity. Re-create the local identity to provision them.',
      );
    }
    const token = this.authController.getToken();
    if (token === null) {
      throw encodeChatError('no_jwt', 'Authentication required.');
    }
    const bundleResponse = await this.fetchBundle(peerUserId, token);
    const remote = parseRemoteKeyBundle(bundleResponse);
    return this.buildInitiatorSession(deviceKeys, remote);
  }

  private async fetchBundle(
    peerUserId: string,
    token: string,
  ): Promise<Awaited<ReturnType<typeof getKeyBundle>>['data']> {
    const opts: HttpRequestOptions = { authToken: token };
    const result = await getKeyBundle(peerUserId, opts);
    return result.data;
  }

  private async buildInitiatorSession(
    deviceKeys: DeviceKeysPrivate,
    remote: RemoteKeyBundle,
  ): Promise<E2EESession> {
    try {
      return await E2EESession.initiate(
        deviceKeys.ikxPrivate,
        {
          authIkPublic: hexToBytes(remote.ikPublicHex),
          ikxPublic: remote.ikxPublicHex === null ? null : hexToBytes(remote.ikxPublicHex),
          spkPublic: hexToBytes(remote.spkPublicHex),
          spkSignature: hexToBytes(remote.spkSignatureHex),
          opkPublic: remote.opkPublicHex === null ? null : hexToBytes(remote.opkPublicHex),
        },
      );
    } catch (err) {
      // Backend BLOCKER 2: REST bundle does not serve xdh_public, so the
      // Phase 6 X3DH refuses to initiate with `missing_ikx`. Surface this as
      // a controlled diagnostic — do NOT fabricate or substitute keys.
      if (err && typeof err === 'object' && 'code' in err && (err as { code: string }).code === 'missing_ikx') {
        throw encodeChatError(
          'backend_blocker',
          'Recipient bundle does not include the X3DH identity (IKX). End-to-end session cannot be established until the backend exposes it. Live E2EE remains blocked.',
        );
      }
      throw chatErrorFromUnknown(err, 'session_init_failed');
    }
  }

  // ---------------------------------------------------------------------------
  // Internal: inbound envelope routing
  // ---------------------------------------------------------------------------

  private handleInbound(env: InboundEnvelope): void {
    const self = this.authController.getUserId();
    if (self === null) return; // logged out
    if (env.recipient !== self) return; // not addressed to us

    switch (env.type) {
      case 'session_init':
        void this.handleSessionInit(env);
        return;
      case 'session_accept':
        this.handleSessionAccept(env);
        return;
      case 'text':
        void this.handleText(env);
        return;
      case 'file':
      case 'delivery_receipt':
      case 'read_receipt':
      case 'typing':
      case 'unknown' as never:
        return;
    }
  }

  private async handleSessionInit(env: InboundEnvelope): Promise<void> {
    // Dedup: skip if this envelope was already processed.
    if (this.receivedMessageIds.has(env.id)) return;
    this.receivedMessageIds.add(env.id);

    const identity = this.authController.getUnlockedIdentity();
    if (identity === null || identity.deviceKeys === null) {
      this.recordSessionError(
        env.sender,
        encodeChatError(
          'no_identity',
          'Received session_init but the local identity is locked or has no device keys.',
        ),
      );
      return;
    }
    let initPayload: Uint8Array;
    try {
      initPayload = decodeBase64Url(env.data);
    } catch {
      this.recordSessionError(
        env.sender,
        encodeChatError('invalid_bundle', 'session_init payload is not valid base64url.'),
      );
      return;
    }
    const conv = this.ensureConversation(env.sender);
    conv.lastActivityAt = Date.now();
    let session: E2EESession;
    try {
      session = await E2EESession.accept(
        identity.deviceKeys.spkPrivate,
        identity.deviceKeys.ikxPrivate,
        x25519PublicFromPrivate(identity.deviceKeys.ikxPrivate),
        identity.deviceKeys.opkPrivate === null ? [] : [identity.deviceKeys.opkPrivate],
        initPayload,
      );
    } catch (err) {
      this.recordSessionError(
        env.sender,
        chatErrorFromUnknown(err, 'session_init_failed'),
      );
      return;
    }
    conv.session = session;
    conv.sessionState = { kind: 'ready', role: 'responder' };
    // Confirm receipt with an empty session_accept envelope. The server
    // treats the payload as opaque.
    try {
      this.webSocket.sendEnvelope({
        recipient: env.sender,
        envelopeType: 'session_accept',
        data: '',
      });
    } catch {
      // Connection state may have changed; the session is still ready for
      // future text envelopes.
    }
    this.notify();
  }

  private handleSessionAccept(env: InboundEnvelope): void {
    if (this.receivedMessageIds.has(env.id)) return;
    this.receivedMessageIds.add(env.id);

    const conv = this.conversations.get(env.sender);
    if (conv === undefined) return;
    conv.lastActivityAt = Date.now();
    // The X3DH acceptor doesn't strictly need a response payload; treat the
    // session_accept as a UI-visible confirmation that the responder has
    // built its side. No-op beyond the activity timestamp.
    this.notify();
  }

  private async handleText(env: InboundEnvelope): Promise<void> {
    // Dedup: skip if this envelope was already processed.
    if (this.receivedMessageIds.has(env.id)) return;
    this.receivedMessageIds.add(env.id);
    if (this.receivedMessageIds.size > ChatController.MAX_RECEIVED_IDS) {
      const ids = Array.from(this.receivedMessageIds);
      this.receivedMessageIds.clear();
      for (const id of ids.slice(-ChatController.MAX_RECEIVED_IDS / 2)) {
        this.receivedMessageIds.add(id);
      }
    }

    const conv = this.ensureConversation(env.sender);
    conv.lastActivityAt = Date.now();
    if (conv.session === null) {
      conv.sessionState = {
        kind: 'error',
        error: encodeChatError(
          'session_decrypt_failed',
          'Encrypted message arrived without an established session. Drop.',
        ),
      };
      this.notify();
      return;
    }
    let wire: Uint8Array;
    try {
      wire = decodeBase64Url(env.data);
    } catch {
      this.recordSessionError(env.sender, encodeChatError('invalid_bundle', 'text payload is not valid base64url.'));
      return;
    }
    try {
      const plaintextBytes = await conv.session.decryptMessage(wire, new Uint8Array(0));
      const plaintext = this.textDecoder.decode(plaintextBytes);
      const message: DisplayMessage = {
        id: env.id,
        senderUserId: env.sender,
        recipientUserId: env.recipient,
        plaintext,
        createdAt: env.timestamp,
        outgoing: false,
        status: null,
        errorMessage: null,
        sessionReady: true,
      };
      conv.messages.push(message);
    } catch (err) {
      const code =
        err && typeof err === 'object' && 'code' in err
          ? String((err as { code: string }).code)
          : 'unknown';
      conv.sessionState = {
        kind: 'error',
        error: encodeChatError(
          'session_decrypt_failed',
          `Decryption failed (${code}).`,
        ),
      };
    }
    this.notify();
  }

  private recordSessionError(peerUserId: string, error: ChatError): void {
    const conv = this.ensureConversation(peerUserId);
    conv.lastActivityAt = Date.now();
    conv.sessionState = { kind: 'error', error };
    this.notify();
  }

  // ---------------------------------------------------------------------------
  // Internal: lifecycle
  // ---------------------------------------------------------------------------

  private ensureConversation(peerUserId: string): Conversation {
    let conv = this.conversations.get(peerUserId);
    if (conv === undefined) {
      conv = {
        peerUserId,
        session: null,
        sessionState: { kind: 'none' },
        messages: [],
        lastActivityAt: Date.now(),
        initiating: false,
        sending: false,
      };
      this.conversations.set(peerUserId, conv);
    }
    return conv;
  }

  private clearAllSessions(): void {
    for (const conv of this.conversations.values()) {
      if (conv.session !== null) {
        try {
          conv.session.wipe();
        } catch {
          // Best-effort.
        }
      }
    }
    this.conversations.clear();
    this.outboundMessageIds.clear();
    this.receivedMessageIds.clear();
  }

  private toSnapshot(conv: Conversation): ConversationSnapshot {
    return {
      peerUserId: conv.peerUserId,
      session: conv.sessionState,
      messages: conv.messages.slice(),
      lastActivityAt: conv.lastActivityAt,
    };
  }

  private notify(): void {
    const snap = this.getSnapshot();
    for (const listener of this.listeners) {
      try {
        listener(snap);
      } catch {
        // Listener errors must not break the loop.
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Singleton plumbing
// ---------------------------------------------------------------------------

let singleton: ChatController | null = null;

/**
 * Build (or return) the process-singleton ChatController. Constructed lazily
 * so that the WebSocketController dependency can be set up by
 * `realtime/setup.ts` before any React component renders.
 */
export function getOrCreateChatController(deps?: {
  webSocketController?: WebSocketController;
  authController?: AuthControllerLike;
}): ChatController {
  if (singleton === null) {
    const ws = deps?.webSocketController;
    const auth = deps?.authController;
    if (ws === undefined || auth === undefined) {
      throw new Error(
        'ChatController not initialised. Call setRealtimeTransport first.',
      );
    }
    singleton = new ChatController({ authController: auth, webSocketController: ws });
  }
  return singleton;
}

/**
 * Test-only helper: dispose + drop the singleton so the next test gets a
 * fresh instance.
 */
export function resetChatControllerForTests(): void {
  if (singleton !== null) {
    singleton.dispose();
    singleton = null;
  }
}

/**
 * Default export for production code. The proxy throws if accessed before
 * `setRealtimeTransport()` has wired the singleton — a programmer-error
 * guard, not a runtime concern (UI code goes through `useChat`).
 */
export const chatController: ChatController = new Proxy({} as ChatController, {
  get(): never {
    throw new Error(
      'chatController accessed before setRealtimeTransport(); subscribe via useChat() instead.',
    );
  },
});

/**
 * Wire types for the real-time WebSocket transport (Phase 7).
 *
 * Mirror `server/envelope.py` exactly: the server is authoritative over
 * `version`, `sender`, and `timestamp`. The client NEVER sends those fields
 * (a spoofed `sender` is overwritten).
 */

export const ENVELOPE_VERSION = 1;
export const MAX_DATA_CHARS = 65_520;
export const MAX_USER_ID_LENGTH = 64;
export const MAX_FRAME_CHARS = 65_536;

export const ENVELOPE_TYPES = [
  'text',
  'file',
  'session_init',
  'session_accept',
  'delivery_receipt',
  'read_receipt',
  'typing',
] as const;

export type EnvelopeType = (typeof ENVELOPE_TYPES)[number];

const ENVELOPE_TYPE_SET = new Set<string>(ENVELOPE_TYPES);

export function isSupportedEnvelopeType(value: unknown): value is EnvelopeType {
  return typeof value === 'string' && ENVELOPE_TYPE_SET.has(value);
}

/** Server -> client (server-authoritative). */
export interface InboundEnvelope {
  version: number;
  id: string;
  type: EnvelopeType;
  sender: string;
  recipient: string;
  timestamp: number;
  data: string;
}

/** Client -> server (the only fields the client supplies). */
export interface OutboundEnvelope {
  id: string;
  type: EnvelopeType;
  recipient: string;
  data: string;
}

/**
 * Close codes from the backend (`server/ws_auth.py` + `docs/WEBSOCKET.md`).
 * The numeric value alone is the source of truth.
 */
export const WS_CLOSE = {
  Normal: 1000,
  GoingAway: 1001,
  TooLarge: 1009,
  Capacity: 1013,
  Replaced: 4000,
  AuthRequired: 4001,
  PolicyViolation: 4003,
  IdleTimeout: 4008,
} as const;

export type WsCloseCode = (typeof WS_CLOSE)[keyof typeof WS_CLOSE];

export type ConnectionState =
  | 'idle'
  | 'connecting'
  | 'authenticating'
  | 'open'
  | 'closing'
  | 'closed';

export interface CloseInfo {
  code: number;
  reason: string;
}

export interface ConnectionError extends Error {
  code?: 'auth' | 'capacity' | 'too_large' | 'policy' | 'replaced' | 'idle' | 'unknown';
  httpStatus?: number;
}

/**
 * Authoritative first-frame auth message (per `server/ws_auth.parse_auth_frame`).
 */
export const AUTH_FRAME_TYPE = 'auth';

export interface AuthFrame {
  type: 'auth';
  token: string;
}

/** Listener for inbound envelopes. */
export type EnvelopeListener = (envelope: InboundEnvelope) => void;

/** Listener for connection state transitions. */
export type StateListener = (state: ConnectionState, info?: CloseInfo | Error) => void;

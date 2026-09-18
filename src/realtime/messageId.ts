/**
 * ULID-style 26-character message id (Crockford base32).
 *
 * Mirrors the backend `server.message_id.new_message_id()` layout:
 *   * 10 chars: 48-bit ms timestamp (big-endian, base32 encoded)
 *   * 16 chars: 80 random bits (cryptographic randomness)
 *
 * Used as the `id` field on every outbound WebSocket envelope. The backend
 * uses the timestamp prefix for sort/dedup; the random suffix doubles as a
 * per-message nonce seed on the client.
 */

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const BASE = ALPHABET.length;
const ENCODED_LENGTH = 26;
const TIMESTAMP_CHARS = 10;
const RANDOM_CHARS = 16;

function encode(value: number, length: number): string {
  let out = '';
  for (let i = 0; i < length; i += 1) {
    out = ALPHABET[value % BASE] + out;
    value = Math.floor(value / BASE);
  }
  return out;
}

let lastTimestampMs = 0;

export function newMessageId(): string {
  const now = Date.now();
  lastTimestampMs = now > lastTimestampMs ? now : lastTimestampMs;
  const randomness = new Uint8Array(10);
  globalThis.crypto.getRandomValues(randomness);
  let r = 0;
  for (let i = 0; i < 10; i += 1) {
    r = r * 256 + (randomness[i] ?? 0);
  }
  return encode(lastTimestampMs, TIMESTAMP_CHARS) + encode(r, RANDOM_CHARS);
}

const VALID_CHARS = new Set(ALPHABET.split('').concat(ALPHABET.toLowerCase().split('')));

export function isValidMessageId(value: unknown): boolean {
  if (typeof value !== 'string' || value.length !== ENCODED_LENGTH) return false;
  for (let i = 0; i < value.length; i += 1) {
    if (!VALID_CHARS.has(value[i] ?? '')) return false;
  }
  return true;
}

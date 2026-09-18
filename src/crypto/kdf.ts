/**
 * Passphrase-derived AES key (PBKDF2-SHA256 via Web Crypto).
 *
 * Why PBKDF2:
 *   - Implemented natively by `crypto.subtle` (no extra dependency).
 *   - OWASP 2023 recommends PBKDF2-SHA256 with ≥ 600 000 iterations for
 *     password-based key derivation.
 *   - Output is 256 bits → suitable as AES-256 key material.
 *
 * Why NOT a faster KDF:
 *   - Argon2id is more memory-hard but requires a WASM dep; out of scope
 *     for Phase 3.
 *   - HKDF or plain SHA-256 are NOT appropriate for low-entropy
 *     passphrases.
 *
 * Salt is 16 random bytes per identity record, IV is 12 random bytes per
 * encryption (set by `aead.ts`). Nothing here is constant.
 */

export const PBKDF2_ITERATIONS = 600_000;
export const PBKDF2_HASH = 'SHA-256' as const;
export const PBKDF2_KEY_BITS = 256;
export const PBKDF2_SALT_BYTES = 16;

export interface DerivedAesKey {
  /** Raw 32-byte AES-256 key. */
  rawKey: Uint8Array;
  /** Non-extractable CryptoKey handle for use with subtle.encrypt/decrypt. */
  subtleKey: CryptoKey;
}

const subtle: SubtleCrypto = (() => {
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.subtle) {
    return globalThis.crypto.subtle;
  }
  throw new Error('Web Crypto SubtleCrypto is unavailable in this environment.');
})();

function utf8Encode(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/**
 * Cast helper: TS 5.6 widened `Uint8Array` to be generic over the buffer
 * (ArrayBuffer or SharedArrayBuffer). `BufferSource` requires
 * `ArrayBufferView<ArrayBuffer>`. Since none of our byte sources are shared
 * memory, the cast is safe.
 */
function asBufferSource(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

export function randomSalt(): Uint8Array {
  const out = new Uint8Array(PBKDF2_SALT_BYTES);
  globalThis.crypto.getRandomValues(out);
  return out;
}

export async function deriveAesKey(
  passphrase: string,
  salt: Uint8Array,
  iterations: number = PBKDF2_ITERATIONS,
): Promise<DerivedAesKey> {
  if (salt.length === 0) {
    throw new Error('salt must be non-empty');
  }
  if (iterations < 1) {
    throw new Error('iterations must be >= 1');
  }

  const baseKey = await subtle.importKey(
    'raw',
    asBufferSource(utf8Encode(passphrase)),
    'PBKDF2',
    false,
    ['deriveBits'],
  );

  const bits = await subtle.deriveBits(
    {
      name: 'PBKDF2',
      hash: PBKDF2_HASH,
      salt: asBufferSource(salt),
      iterations,
    },
    baseKey,
    PBKDF2_KEY_BITS,
  );

  const rawKey = new Uint8Array(bits);
  const subtleKey = await subtle.importKey(
    'raw',
    asBufferSource(rawKey),
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt'],
  );

  return { rawKey, subtleKey };
}
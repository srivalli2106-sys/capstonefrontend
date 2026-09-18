/**
 * AES-256-GCM authenticated encryption (Web Crypto).
 *
 * Why AES-256-GCM:
 *   - AEAD: confidentiality + integrity in one primitive.
 *   - Native to Web Crypto; no extra dependency.
 *   - 12-byte IV is the standard GCM nonce length and is supplied fresh
 *     per encryption.
 *
 * Layout of an AEAD output (`EncryptedBlob`):
 *   - `iv`: 12-byte random nonce (hex-encoded)
 *   - `ciphertext`: plaintext || 16-byte auth tag (the Web Crypto ciphertext
 *     includes the tag)
 *
 * The associated data (`ad`) is bound into the AEAD authentication tag.
 * Use a constant domain-separator string when there is no other context to
 * bind.
 */

import { bytesToHex, hexToBytes } from './hex';

export const AES_KEY_BYTES = 32;
export const AES_IV_BYTES = 12;
export const AES_TAG_BYTES = 16;

export interface EncryptedBlob {
  ivHex: string;
  ciphertextHex: string;
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

export function randomIv(): Uint8Array {
  const out = new Uint8Array(AES_IV_BYTES);
  globalThis.crypto.getRandomValues(out);
  return out;
}

export async function encrypt(
  subtleKey: CryptoKey,
  plaintext: Uint8Array,
  ad: Uint8Array,
  iv?: Uint8Array,
): Promise<EncryptedBlob> {
  const ivBytes = iv ?? randomIv();
  const params: AesGcmParams = {
    name: 'AES-GCM',
    iv: asBufferSource(ivBytes),
    additionalData: asBufferSource(ad),
    tagLength: 128,
  };
  const ciphertext = await globalThis.crypto.subtle.encrypt(
    params,
    subtleKey,
    asBufferSource(plaintext),
  );
  return {
    ivHex: bytesToHex(ivBytes),
    ciphertextHex: bytesToHex(new Uint8Array(ciphertext)),
  };
}

/**
 * Throws if the tag does not verify. The backend never sees plaintext;
 * callers must surface the failure safely.
 */
export async function decrypt(
  subtleKey: CryptoKey,
  blob: EncryptedBlob,
  ad: Uint8Array,
): Promise<Uint8Array> {
  const ivBytes = hexToBytes(blob.ivHex);
  const ciphertext = hexToBytes(blob.ciphertextHex);
  if (ivBytes.length !== AES_IV_BYTES) {
    throw new Error('invalid IV length');
  }
  const params: AesGcmParams = {
    name: 'AES-GCM',
    iv: asBufferSource(ivBytes),
    additionalData: asBufferSource(ad),
    tagLength: 128,
  };
  const plaintext = await globalThis.crypto.subtle.decrypt(
    params,
    subtleKey,
    asBufferSource(ciphertext),
  );
  return new Uint8Array(plaintext);
}

// ---------------------------------------------------------------------------
// Raw-key helpers (used by the Double Ratchet; the message key is one-shot
// raw 32 bytes derived from the chain step).
// ---------------------------------------------------------------------------

async function importRawAesKey(rawKey: Uint8Array): Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey(
    'raw',
    asBufferSource(rawKey),
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * AES-GCM encrypt with a raw 32-byte key + caller-supplied 12-byte nonce.
 * Returns the raw ciphertext (which already includes the 16-byte tag at the end).
 */
export async function encryptWithRawKey(
  rawKey: Uint8Array,
  plaintext: Uint8Array,
  nonce: Uint8Array,
  ad: Uint8Array,
): Promise<Uint8Array> {
  if (rawKey.length !== AES_KEY_BYTES) {
    throw new Error('AES key must be 32 bytes');
  }
  if (nonce.length !== AES_IV_BYTES) {
    throw new Error('AES-GCM nonce must be 12 bytes');
  }
  const key = await importRawAesKey(rawKey);
  const params: AesGcmParams = {
    name: 'AES-GCM',
    iv: asBufferSource(nonce),
    additionalData: asBufferSource(ad),
    tagLength: 128,
  };
  const ct = await globalThis.crypto.subtle.encrypt(
    params,
    key,
    asBufferSource(plaintext),
  );
  return new Uint8Array(ct);
}

/**
 * AES-GCM decrypt with a raw 32-byte key + caller-supplied 12-byte nonce.
 * Throws if the AEAD tag does not verify.
 */
export async function decryptWithRawKey(
  rawKey: Uint8Array,
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  ad: Uint8Array,
): Promise<Uint8Array> {
  if (rawKey.length !== AES_KEY_BYTES) {
    throw new Error('AES key must be 32 bytes');
  }
  if (nonce.length !== AES_IV_BYTES) {
    throw new Error('AES-GCM nonce must be 12 bytes');
  }
  const key = await importRawAesKey(rawKey);
  const params: AesGcmParams = {
    name: 'AES-GCM',
    iv: asBufferSource(nonce),
    additionalData: asBufferSource(ad),
    tagLength: 128,
  };
  const pt = await globalThis.crypto.subtle.decrypt(
    params,
    key,
    asBufferSource(ciphertext),
  );
  return new Uint8Array(pt);
}
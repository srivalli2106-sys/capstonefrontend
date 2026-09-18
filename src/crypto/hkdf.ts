/**
 * HKDF-SHA256 wrapper around Web Crypto.
 *
 * The backend protocol package uses the same primitive (`cryptography.hazmat.
 * primitives.kdf.hkdf.HKDF`, SHA-256, length=32, salt=b""). RFC 5869 specifies
 * that an empty salt is equivalent to HashLen zeros; Web Crypto's HKDF applies
 * the same treatment when the supplied salt buffer is empty, so this helper
 * is byte-compatible with the backend for `salt = ""`.
 */

const HKDF_HASH = 'SHA-256';

export async function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array | null,
  info: string | Uint8Array,
  lengthBytes: number = 32,
): Promise<Uint8Array> {
  if (lengthBytes <= 0 || lengthBytes > 255 * 32) {
    throw new Error('hkdf length must be in (0, 255*HashLen]');
  }
  const ikmKey = await crypto.subtle.importKey(
    'raw',
    toBufferSource(ikm),
    'HKDF',
    false,
    ['deriveBits'],
  );
  const infoBytes = typeof info === 'string' ? new TextEncoder().encode(info) : info;
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: HKDF_HASH,
      salt: toBufferSource(salt ?? new Uint8Array(0)),
      info: toBufferSource(infoBytes),
    },
    ikmKey,
    lengthBytes * 8,
  );
  return new Uint8Array(bits);
}

function toBufferSource(input: Uint8Array): BufferSource {
  // Copy into a freshly-allocated ArrayBuffer to satisfy the strict
  // BufferSource type (which excludes SharedArrayBuffer views).
  const copy = new Uint8Array(input.byteLength);
  copy.set(input);
  return copy;
}
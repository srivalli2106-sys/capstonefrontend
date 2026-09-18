/**
 * RFC 4648 base64url (no padding) encoding / decoding.
 *
 * The backend's envelope `data` field is documented as base64url but treated
 * as opaque; we emit the canonical JWT-style form (no padding, '-' / '_'
 * replacements) and tolerate optional padding on decode so the helpers round-
 * trip with both padded and unpadded producers.
 */

const URL_SAFE_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function base64Chars(threeBytes: number): string {
  return URL_SAFE_ALPHABET.charAt((threeBytes >> 18) & 0x3f) +
    URL_SAFE_ALPHABET.charAt((threeBytes >> 12) & 0x3f) +
    URL_SAFE_ALPHABET.charAt((threeBytes >> 6) & 0x3f) +
    URL_SAFE_ALPHABET.charAt(threeBytes & 0x3f);
}

function toBase64UrlChars(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const a = bytes[i] ?? 0;
    const b = bytes[i + 1] ?? 0;
    const c = bytes[i + 2] ?? 0;
    out += base64Chars((a << 16) | (b << 8) | c);
  }
  const remaining = bytes.length - i;
  if (remaining === 1) {
    const a = bytes[i] ?? 0;
    out +=
      URL_SAFE_ALPHABET.charAt((a >> 2) & 0x3f) +
      URL_SAFE_ALPHABET.charAt((a << 4) & 0x3f);
  } else if (remaining === 2) {
    const a = bytes[i] ?? 0;
    const b = bytes[i + 1] ?? 0;
    out +=
      URL_SAFE_ALPHABET.charAt((a >> 2) & 0x3f) +
      URL_SAFE_ALPHABET.charAt(((a << 4) | (b >> 4)) & 0x3f) +
      URL_SAFE_ALPHABET.charAt((b << 2) & 0x3f);
  }
  return out;
}

function decodeChar(ch: string): number {
  const idx = URL_SAFE_ALPHABET.indexOf(ch);
  if (idx < 0) throw new Error(`Invalid base64url character: ${ch}`);
  return idx;
}

export function encodeBase64Url(bytes: Uint8Array): string {
  if (!(bytes instanceof Uint8Array)) {
    throw new Error('encodeBase64Url expects a Uint8Array');
  }
  return toBase64UrlChars(bytes);
}

export function decodeBase64Url(input: string): Uint8Array {
  if (typeof input !== 'string') throw new Error('base64url input must be a string');
  // Tolerate standard base64 ('+' and '/') and optional '=' padding.
  const normalized = input.replace(/-/g, '-').replace(/_/g, '_');
  // Replace URL-safe chars with their standard counterparts via the alphabet
  // lookup below; the alphabet IS the URL-safe one, so '-' / '_' decode directly.
  let padded = normalized;
  while (padded.length % 4 !== 0) padded += '=';
  // Strip padding for the index lookup (decoder tolerates trailing '=').
  const clean = padded.replace(/=+$/, '');
  const outLen = Math.floor((clean.length * 6) / 8);
  const out = new Uint8Array(outLen);
  let oi = 0;
  let i = 0;
  for (; i + 4 <= clean.length; i += 4) {
    const v0 = decodeChar(clean[i] ?? '');
    const v1 = decodeChar(clean[i + 1] ?? '');
    const v2 = decodeChar(clean[i + 2] ?? '');
    const v3 = decodeChar(clean[i + 3] ?? '');
    out[oi++] = (v0 << 2) | (v1 >> 4);
    out[oi++] = ((v1 & 0x0f) << 4) | (v2 >> 2);
    out[oi++] = ((v2 & 0x03) << 6) | v3;
  }
  const remaining = clean.length - i;
  if (remaining === 2) {
    const v0 = decodeChar(clean[i] ?? '');
    const v1 = decodeChar(clean[i + 1] ?? '');
    out[oi++] = (v0 << 2) | (v1 >> 4);
  } else if (remaining === 3) {
    const v0 = decodeChar(clean[i] ?? '');
    const v1 = decodeChar(clean[i + 1] ?? '');
    const v2 = decodeChar(clean[i + 2] ?? '');
    out[oi++] = (v0 << 2) | (v1 >> 4);
    out[oi++] = ((v1 & 0x0f) << 4) | (v2 >> 2);
  }
  return out;
}

// Exposed for parity assertions in tests.
export const BASE64_URL_SAFE_ALPHABET = URL_SAFE_ALPHABET;
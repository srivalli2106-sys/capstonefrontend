/**
 * Hex / byte conversion helpers.
 *
 * The backend wire format requires lowercase hexadecimal encoding of fixed-
 * length raw byte sequences:
 *   - `ik_public`  : 32 bytes → 64 lowercase hex chars
 *   - signatures   : 64 bytes → 128 lowercase hex chars
 *   - challenge nonce: 32 bytes → 64 lowercase hex chars
 *
 * Backend `bytes.fromhex` accepts both cases, but we emit lowercase to keep
 * log lines consistent.
 */

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) {
    const byte = bytes[i];
    if (byte === undefined) continue;
    out += byte.toString(16).padStart(2, '0');
  }
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('hex string must have even length');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    const slice = hex.slice(i * 2, i * 2 + 2);
    const byte = Number.parseInt(slice, 16);
    if (Number.isNaN(byte)) {
      throw new Error('hex string contains non-hex characters');
    }
    out[i] = byte;
  }
  return out;
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}
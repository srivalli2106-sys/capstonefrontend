import { describe, expect, it } from 'vitest';
import { decodeBase64Url, encodeBase64Url } from '../src/crypto/base64url';
import { bytesToHex, hexToBytes } from '../src/crypto/hex';

describe('base64url (RFC 4648, unpadded)', () => {
  it('round-trips every byte length 0..15', () => {
    for (let n = 0; n < 16; n += 1) {
      const buf = new Uint8Array(n);
      for (let i = 0; i < n; i += 1) buf[i] = (i * 37 + 11) & 0xff;
      const encoded = encodeBase64Url(buf);
      const decoded = decodeBase64Url(encoded);
      expect(Array.from(decoded)).toEqual(Array.from(buf));
    }
  });

  it('produces only URL-safe alphabet characters (no padding)', () => {
    for (let n = 0; n < 16; n += 1) {
      const buf = new Uint8Array(n).map((_, i) => (i * 17 + 3) & 0xff);
      const enc = encodeBase64Url(buf);
      expect(enc).toMatch(/^[A-Za-z0-9_-]*$/);
    }
  });

  it('handles a 66-byte X3DH init payload → 88-char output', () => {
    // The X3DH init frame has 66 bytes -> exactly 22 base64 triplets -> 88 chars.
    const payload = new Uint8Array(66);
    for (let i = 0; i < 66; i += 1) payload[i] = (i * 23 + 5) & 0xff;
    const enc = encodeBase64Url(payload);
    expect(enc.length).toBe(88);
    expect(decodeBase64Url(enc)).toEqual(payload);
  });

  it('matches the 128-hex init payload (with-OPK pinned)', () => {
    const hex =
      '0107a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c' +
      '883186b800b41d5cf0429695da9b3cc4f328ebcd184a6e482fa578c103f06c7700';
    const bytes = hexToBytes(hex);
    expect(bytes.length).toBe(66);
    const enc = encodeBase64Url(bytes);
    expect(decodeBase64Url(enc)).toEqual(bytes);
    expect(bytesToHex(decodeBase64Url(enc))).toBe(hex);
  });

  it('tolerates standard base64 (+/) input on decode', () => {
    const payload = new Uint8Array(64).map((_, i) => i);
    // Replace alphabet via +/->-_ mapping.
    const std = Buffer.from(payload).toString('base64');
    const urlSafe = std.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    expect(decodeBase64Url(urlSafe)).toEqual(payload);
  });
});
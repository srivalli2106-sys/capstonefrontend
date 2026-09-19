/**
 * Tests for the v2 (hybrid) X3DH INIT wire format and hybrid session
 * init/accept flows.
 */

import { describe, expect, it } from 'vitest';
import {
  buildInitPayloadV2,
  detectInitVersion,
  INIT_V2_PAYLOAD_BYTES,
  ML_KEM_768_CIPHERTEXT_BYTES,
  ML_KEM_768_PUBLIC_KEY_BYTES,
  parseInitPayloadV2,
} from '../src/crypto/x3dh';

const enc = new TextEncoder();

describe('v2 INIT wire format', () => {
  it('packs and unpacks a v2 payload', () => {
    const ikxA = new Uint8Array(32).fill(1);
    const kemCt = new Uint8Array(ML_KEM_768_CIPHERTEXT_BYTES).fill(2);
    const alicePqKem = new Uint8Array(ML_KEM_768_PUBLIC_KEY_BYTES).fill(3);
    const ekA = new Uint8Array(32).fill(4);
    const payload = buildInitPayloadV2(ikxA, kemCt, alicePqKem, ekA, 0);
    expect(payload.length).toBe(INIT_V2_PAYLOAD_BYTES);
    expect(payload[0]).toBe(2);
    const parsed = parseInitPayloadV2(payload);
    expect(parsed.version).toBe(2);
    expect(toEqual(parsed.ikxPublicA, ikxA)).toBe(true);
    expect(toEqual(parsed.kemCiphertext, kemCt)).toBe(true);
    expect(toEqual(parsed.alicePqKemPublic, alicePqKem)).toBe(true);
    expect(toEqual(parsed.ekPublicA, ekA)).toBe(true);
    expect(parsed.opkIndex).toBe(0);
  });

  it('encodes opk_index=null as 0xff', () => {
    const ikxA = new Uint8Array(32).fill(1);
    const kemCt = new Uint8Array(ML_KEM_768_CIPHERTEXT_BYTES).fill(2);
    const alicePqKem = new Uint8Array(ML_KEM_768_PUBLIC_KEY_BYTES).fill(3);
    const ekA = new Uint8Array(32).fill(4);
    const payload = buildInitPayloadV2(ikxA, kemCt, alicePqKem, ekA, null);
    const parsed = parseInitPayloadV2(payload);
    expect(parsed.opkIndex).toBeNull();
  });

  it('rejects wrong-size kem_ciphertext', () => {
    expect(() =>
      buildInitPayloadV2(
        new Uint8Array(32),
        new Uint8Array(ML_KEM_768_CIPHERTEXT_BYTES - 1),
        new Uint8Array(ML_KEM_768_PUBLIC_KEY_BYTES),
        new Uint8Array(32),
        null,
      ),
    ).toThrow();
  });

  it('rejects wrong-size alice_pq_kem_public', () => {
    expect(() =>
      buildInitPayloadV2(
        new Uint8Array(32),
        new Uint8Array(ML_KEM_768_CIPHERTEXT_BYTES),
        new Uint8Array(ML_KEM_768_PUBLIC_KEY_BYTES - 1),
        new Uint8Array(32),
        null,
      ),
    ).toThrow();
  });

  it('rejects wrong-total-length payloads on unpack', () => {
    expect(() =>
      parseInitPayloadV2(new Uint8Array(INIT_V2_PAYLOAD_BYTES - 1)),
    ).toThrow();
  });

  it('detectInitVersion returns 2 for v2 payloads', () => {
    expect(detectInitVersion(new Uint8Array([2, 0, 0]))).toBe(2);
  });
});

function toEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

void enc;

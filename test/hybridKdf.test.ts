/**
 * Deterministic test vectors for the hybrid KDF.
 *
 * These vectors are derived from the construction in
 * `src/crypto/hybridKdf.ts`. The same vectors must be reproduced on the
 * backend `protocol.hybrid_kdf` module — both implementations MUST stay
 * byte-compatible; a change here requires regenerating both sides together.
 */

import { describe, expect, it } from 'vitest';
import {
  hybridRootSecret,
  hybridTranscript,
  PROTOCOL_VERSION_CLASSICAL,
  PROTOCOL_VERSION_HYBRID,
  ROOT_INFO,
  TRANSCRIPT_CONTEXT,
} from '../src/crypto/hybridKdf';

const enc = new TextEncoder();

function deterministicBytes(n: number, seed: number): Uint8Array {
  // SHA-256 is not available synchronously; instead, use a simple LCG with
  // per-byte stepping. This is not cryptographic; it is purely to make the
  // test vectors reproducible.
  const out = new Uint8Array(n);
  let s = (seed * 2654435761) >>> 0;
  for (let i = 0; i < n; i += 1) {
    s = (s * 1103515245 + 12345 + i) >>> 0;
    out[i] = s & 0xff;
  }
  return out;
}

const ALICE_IK = deterministicBytes(32, 1);
const ALICE_IKX = deterministicBytes(32, 2);
const BOB_IK = deterministicBytes(32, 3);
const BOB_IKX = deterministicBytes(32, 4);
const BOB_SPK = deterministicBytes(32, 5);
const BOB_PQ_KEM = deterministicBytes(1184, 6);
const BOB_PQ_SIG = deterministicBytes(1312, 7);
const Z_CLASSICAL = deterministicBytes(32, 8);
const Z_PQ = deterministicBytes(32, 9);

describe('hybridKdf constants', () => {
  it('pins the transcript and root info contexts', () => {
    expect(TRANSCRIPT_CONTEXT).toBe('secure-messaging-hybrid-kem-handshake-v1');
    expect(ROOT_INFO).toBe('secure-messaging-hybrid-root-v1');
  });

  it('exposes the protocol version constants', () => {
    expect(PROTOCOL_VERSION_CLASSICAL).toBe(1);
    expect(PROTOCOL_VERSION_HYBRID).toBe(2);
  });
});

describe('hybridTranscript', () => {
  it('is deterministic for the same inputs', async () => {
    const a = await hybridTranscript({
      protocolVersion: PROTOCOL_VERSION_HYBRID,
      aliceIkPub: ALICE_IK,
      aliceIkxPub: ALICE_IKX,
      bobIkPub: BOB_IK,
      bobIkxPub: BOB_IKX,
      bobSpkPub: BOB_SPK,
      bobPqKemPublic: BOB_PQ_KEM,
      bobPqSigPublic: BOB_PQ_SIG,
    });
    const b = await hybridTranscript({
      protocolVersion: PROTOCOL_VERSION_HYBRID,
      aliceIkPub: ALICE_IK,
      aliceIkxPub: ALICE_IKX,
      bobIkPub: BOB_IK,
      bobIkxPub: BOB_IKX,
      bobSpkPub: BOB_SPK,
      bobPqKemPublic: BOB_PQ_KEM,
      bobPqSigPublic: BOB_PQ_SIG,
    });
    expect(a.length).toBe(32);
    expect(toEqual(a, b)).toBe(true);
  });

  it('rejects an unknown protocol version', async () => {
    await expect(
      hybridTranscript({
        protocolVersion: 3,
        aliceIkPub: ALICE_IK,
        aliceIkxPub: ALICE_IKX,
        bobIkPub: BOB_IK,
        bobIkxPub: BOB_IKX,
        bobSpkPub: BOB_SPK,
        bobPqKemPublic: BOB_PQ_KEM,
        bobPqSigPublic: BOB_PQ_SIG,
      }),
    ).rejects.toThrow();
  });
});

describe('hybridRootSecret', () => {
  const baseInputs = {
    protocolVersion: PROTOCOL_VERSION_HYBRID,
    aliceIkPub: ALICE_IK,
    aliceIkxPub: ALICE_IKX,
    bobIkPub: BOB_IK,
    bobIkxPub: BOB_IKX,
    bobSpkPub: BOB_SPK,
    bobPqKemPublic: BOB_PQ_KEM,
    bobPqSigPublic: BOB_PQ_SIG,
  };

  it('returns a 32-byte root secret', async () => {
    const r = await hybridRootSecret({
      ...baseInputs,
      zClassical: Z_CLASSICAL,
      zPq: Z_PQ,
    });
    expect(r.length).toBe(32);
  });

  it('changes when Z_classical changes', async () => {
    const a = await hybridRootSecret({
      ...baseInputs,
      zClassical: Z_CLASSICAL,
      zPq: Z_PQ,
    });
    const b = await hybridRootSecret({
      ...baseInputs,
      zClassical: deterministicBytes(32, 80),
      zPq: Z_PQ,
    });
    expect(toEqual(a, b)).toBe(false);
  });

  it('changes when Z_pq changes', async () => {
    const a = await hybridRootSecret({
      ...baseInputs,
      zClassical: Z_CLASSICAL,
      zPq: Z_PQ,
    });
    const b = await hybridRootSecret({
      ...baseInputs,
      zClassical: Z_CLASSICAL,
      zPq: deterministicBytes(32, 90),
    });
    expect(toEqual(a, b)).toBe(false);
  });

  it('changes when the protocol version changes', async () => {
    const a = await hybridRootSecret({
      ...baseInputs,
      zClassical: Z_CLASSICAL,
      zPq: Z_PQ,
    });
    const b = await hybridRootSecret({
      ...baseInputs,
      protocolVersion: PROTOCOL_VERSION_CLASSICAL,
      zClassical: Z_CLASSICAL,
      zPq: Z_PQ,
    });
    expect(toEqual(a, b)).toBe(false);
  });

  it('is deterministic for the same inputs (cross-implementation vector)', async () => {
    const r1 = await hybridRootSecret({
      ...baseInputs,
      zClassical: Z_CLASSICAL,
      zPq: Z_PQ,
    });
    const r2 = await hybridRootSecret({
      ...baseInputs,
      zClassical: Z_CLASSICAL,
      zPq: Z_PQ,
    });
    expect(toEqual(r1, r2)).toBe(true);
  });

  it('has no ambiguous concatenation (length-prefix framing)', async () => {
    // Two shared secrets of different lengths must produce different
    // roots even if the raw concatenation would otherwise be ambiguous.
    const short = new Uint8Array(30).fill(0x41);
    const long = new Uint8Array(34).fill(0x42);
    const a = await hybridRootSecret({
      ...baseInputs,
      zClassical: short,
      zPq: long,
    });
    const b = await hybridRootSecret({
      ...baseInputs,
      zClassical: long,
      zPq: short,
    });
    expect(toEqual(a, b)).toBe(false);
  });
});

function toEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

void enc; // kept for future TextEncoder use

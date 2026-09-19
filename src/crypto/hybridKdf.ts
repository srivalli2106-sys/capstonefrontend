/**
 * Domain-separated hybrid KDF (classical X3DH + ML-KEM-768).
 *
 * MUST stay byte-compatible with the backend `protocol.hybrid_kdf` module.
 * Deterministic test vectors pin both implementations; a change here
 * requires regenerating both sides together.
 *
 * Construction:
 *
 *     transcript = SHA-256(
 *         "secure-messaging-hybrid-kem-handshake-v1"
 *         || version_tag
 *         || alice_ik_pub
 *         || alice_ikx_pub
 *         || bob_ik_pub
 *         || bob_ikx_pub
 *         || bob_spk_pub
 *         || bob_pq_kem_public
 *         || bob_pq_sig_public,
 *     )
 *
 *     ikm = transcript
 *           || LP(Z_classical) || Z_classical
 *           || LP(Z_pq)       || Z_pq
 *
 *     root_secret = HKDF-SHA256(
 *         ikm,
 *         info = "secure-messaging-hybrid-root-v1",
 *         length = 32,
 *     )
 *
 * ``LP(x)`` is the 2-byte big-endian length prefix; it stops a naive
 * concatenation of two 32-byte shared secrets from ever being ambiguous.
 */

import { hkdfSha256 } from './hkdf';

export const TRANSCRIPT_CONTEXT = 'secure-messaging-hybrid-kem-handshake-v1';
export const ROOT_INFO = 'secure-messaging-hybrid-root-v1';

export const PROTOCOL_VERSION_CLASSICAL = 1;
export const PROTOCOL_VERSION_HYBRID = 2;

const TRANSCRIPT_CONTEXT_BYTES = new TextEncoder().encode(TRANSCRIPT_CONTEXT);
const ROOT_INFO_BYTES = new TextEncoder().encode(ROOT_INFO);

export interface HybridTranscriptInputs {
  protocolVersion: number;
  aliceIkPub: Uint8Array;
  aliceIkxPub: Uint8Array;
  bobIkPub: Uint8Array;
  bobIkxPub: Uint8Array;
  bobSpkPub: Uint8Array;
  bobPqKemPublic: Uint8Array;
  bobPqSigPublic: Uint8Array;
}

export async function hybridTranscript(
  inputs: HybridTranscriptInputs,
): Promise<Uint8Array> {
  if (
    inputs.protocolVersion !== PROTOCOL_VERSION_CLASSICAL &&
    inputs.protocolVersion !== PROTOCOL_VERSION_HYBRID
  ) {
    throw new Error(
      `protocolVersion must be ${PROTOCOL_VERSION_CLASSICAL} or ${PROTOCOL_VERSION_HYBRID}, got ${inputs.protocolVersion}`,
    );
  }
  // Web Crypto digest: SHA-256.
  const data = concatBytes(
    TRANSCRIPT_CONTEXT_BYTES,
    new Uint8Array([inputs.protocolVersion]),
    inputs.aliceIkPub,
    inputs.aliceIkxPub,
    inputs.bobIkPub,
    inputs.bobIkxPub,
    inputs.bobSpkPub,
    inputs.bobPqKemPublic,
    inputs.bobPqSigPublic,
  );
  // Copy into a plain ArrayBuffer-backed Uint8Array to satisfy the strict
  // BufferSource type that excludes SharedArrayBuffer views.
  const buffer = new Uint8Array(data.byteLength);
  buffer.set(data);
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  return new Uint8Array(digest);
}

export interface HybridRootInputs extends HybridTranscriptInputs {
  zClassical: Uint8Array;
  zPq: Uint8Array;
}

export async function hybridRootSecret(
  inputs: HybridRootInputs,
): Promise<Uint8Array> {
  const transcript = await hybridTranscript(inputs);
  const ikm = concatBytes(
    transcript,
    encodeLp(inputs.zClassical.length),
    inputs.zClassical,
    encodeLp(inputs.zPq.length),
    inputs.zPq,
  );
  return hkdfSha256(ikm, new Uint8Array(0), ROOT_INFO_BYTES, 32);
}

function encodeLp(length: number): Uint8Array {
  if (length < 0 || length > 0xffff) {
    throw new Error(`shared-secret length out of range: ${length}`);
  }
  const out = new Uint8Array(2);
  // Big-endian 2-byte length prefix.
  out[0] = (length >>> 8) & 0xff;
  out[1] = length & 0xff;
  return out;
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

/**
 * Key-bundle parsing and validation (Phase 4 / Phase 14 hybrid).
 *
 * Converts the REST `KeyBundleResponse` (`src/types/keys.ts`) into a
 * validated, domain-friendly bundle and verifies BOTH the classical Ed25519
 * SPK signature AND (when present) the ML-DSA-44 binding signature.
 *
 * REST contract facts (verified against `server/routes/keys.py`,
 * `server/services/key_service.py`):
 *
 *   - `ik_public`     : 32-byte Ed25519 auth public (64-hex)
 *   - `xdh_public`    : 32-byte X25519 X3DH identity IKX (64-hex)
 *   - `spk_public`    : 32-byte X25519 signed prekey (64-hex)
 *   - `spk_sig`       : 64-byte Ed25519 signature (128-hex)
 *   - `opk_public`    : 32-byte X25519 OPK (64-hex) or null; single-use
 *   - `pq_kem_public` : 1184-byte ML-KEM-768 public key (2368-hex) or null
 *   - `pq_sig_public` : 1312-byte ML-DSA-44 public key (2624-hex) or null
 *   - `pq_binding_sig`: 2420-byte ML-DSA-44 signature (4840-hex) or null
 *   - `protocol_version`: 1 = classical, 2 = hybrid
 */

import { hexToBytes } from './hex';
import { x25519PublicFromHex } from './x25519';
import { verifySignedPrekey } from './deviceKeys';
import {
  verifyHybridBindingSignature,
  HYBRID_BIND_CONTEXT_BYTES,
} from './deviceKeys';
import { ML_KEM_768_PUBLIC_KEY_BYTES, ML_DSA_44_PUBLIC_KEY_BYTES, ML_DSA_44_SIGNATURE_BYTES } from './pq';
import type { KeyBundleResponse } from '../types/keys';

export const SPK_SIGNATURE_HEX_LENGTH = 128; // 64-byte Ed25519 signature
export const X25519_PUBLIC_HEX_LENGTH = 64; // 32-byte X25519 public key
export const ED25519_PUBLIC_HEX_LENGTH = 64; // 32-byte Ed25519 public key
export const ML_KEM_768_PUBLIC_KEY_HEX_LENGTH = 2368;
export const ML_DSA_44_PUBLIC_KEY_HEX_LENGTH = 2624;
export const ML_DSA_44_SIGNATURE_HEX_LENGTH = 4840;

export const PROTOCOL_VERSION_CLASSICAL = 1;
export const PROTOCOL_VERSION_HYBRID = 2;

export class KeyBundleError extends Error {
  public readonly code:
    | 'invalid_hex'
    | 'invalid_length'
    | 'invalid_signature'
    | 'incomplete_hybrid';
  constructor(
    code: 'invalid_hex' | 'invalid_length' | 'invalid_signature' | 'incomplete_hybrid',
    message: string,
  ) {
    super(message);
    this.name = 'KeyBundleError';
    this.code = code;
  }
}

/**
 * A validated remote peer key bundle, derived from the REST response.
 * `ikxPublicHex` is the peer's X25519 X3DH identity (IKX) served by the
 * backend as `xdh_public`.
 */
export interface RemoteKeyBundle {
  userId: string;
  /** Ed25519 auth identity (64-hex) — verifies the SPK signature. */
  ikPublicHex: string;
  /** X25519 X3DH identity (64-hex). */
  ikxPublicHex: string;
  /** X25519 signed prekey (64-hex). */
  spkPublicHex: string;
  /** SPK signature hex (protocol format: 128 hex / 64 bytes). */
  spkSignatureHex: string;
  /** X25519 one-time prekey (64-hex) once — consumed server-side. */
  opkPublicHex: string | null;
  version: number;
  /** ML-KEM-768 public key (hex), or null for classical bundles. */
  pqKemPublicHex: string | null;
  /** ML-DSA-44 public key (hex), or null for classical bundles. */
  pqSigPublicHex: string | null;
  /** ML-DSA-44 binding signature over the hybrid context (hex). */
  pqBindingSigHex: string | null;
  /** Protocol version: 1 = classical, 2 = hybrid. */
  protocolVersion: number;
}

/**
 * Parse + validate a REST bundle response.
 *
 * Verifies BOTH:
 *   * the classical Ed25519 SPK signature against `ik_public`; AND
 *   * when `protocol_version === 2`, the ML-DSA-44 binding signature over
 *     the canonical hybrid context.
 *
 * Throws `KeyBundleError` when a key is not valid hex of the right length,
 * when the SPK signature does not verify against `ik_public`, or when the
 * response is missing required fields. A hybrid bundle that omits any of
 * the PQ fields or the binding signature is rejected.
 */
export function parseRemoteKeyBundle(response: KeyBundleResponse): RemoteKeyBundle {
  const userId = response.user_id;
  if (typeof userId !== 'string' || userId.length === 0) {
    throw new KeyBundleError('invalid_length', 'bundle missing user_id');
  }

  const ikPublicHex = requireHex(response.ik_public, 'ik_public', ED25519_PUBLIC_HEX_LENGTH);
  const ikxPublicHex = requireHex(response.xdh_public, 'xdh_public', X25519_PUBLIC_HEX_LENGTH);
  const spkPublicHex = requireHex(response.spk_public, 'spk_public', X25519_PUBLIC_HEX_LENGTH);
  const spkSignatureHex = requireHex(response.spk_sig, 'spk_sig', SPK_SIGNATURE_HEX_LENGTH);

  let opkPublicHex: string | null = null;
  if (response.opk_public !== null) {
    opkPublicHex = requireHex(response.opk_public, 'opk_public', X25519_PUBLIC_HEX_LENGTH);
  }

  const protocolVersion = response.protocol_version ?? PROTOCOL_VERSION_CLASSICAL;

  let pqKemPublicHex: string | null = null;
  let pqSigPublicHex: string | null = null;
  let pqBindingSigHex: string | null = null;
  if (protocolVersion === PROTOCOL_VERSION_HYBRID) {
    if (response.pq_kem_public === null) {
      throw new KeyBundleError('incomplete_hybrid', 'hybrid bundle missing pq_kem_public');
    }
    if (response.pq_sig_public === null) {
      throw new KeyBundleError('incomplete_hybrid', 'hybrid bundle missing pq_sig_public');
    }
    if (response.pq_binding_sig === null) {
      throw new KeyBundleError('incomplete_hybrid', 'hybrid bundle missing pq_binding_sig');
    }
    pqKemPublicHex = requireHex(response.pq_kem_public, 'pq_kem_public', ML_KEM_768_PUBLIC_KEY_HEX_LENGTH);
    pqSigPublicHex = requireHex(response.pq_sig_public, 'pq_sig_public', ML_DSA_44_PUBLIC_KEY_HEX_LENGTH);
    pqBindingSigHex = requireHex(response.pq_binding_sig, 'pq_binding_sig', ML_DSA_44_SIGNATURE_HEX_LENGTH);
  } else if (protocolVersion !== PROTOCOL_VERSION_CLASSICAL) {
    throw new KeyBundleError(
      'invalid_length',
      `unsupported protocol_version ${protocolVersion}`,
    );
  }

  // SPK binding must verify against the peer's registered auth identity.
  const ok = verifySignedPrekey(
    hexToBytes(ikPublicHex),
    hexToBytes(spkPublicHex),
    hexToBytes(spkSignatureHex),
  );
  if (!ok) {
    throw new KeyBundleError(
      'invalid_signature',
      'signed prekey signature does not verify against ik_public',
    );
  }

  if (protocolVersion === PROTOCOL_VERSION_HYBRID) {
    const mldsaOk = verifyHybridBindingSignature(
      hexToBytes(pqBindingSigHex as string),
      hexToBytes(ikPublicHex),
      hexToBytes(ikxPublicHex),
      hexToBytes(spkPublicHex),
      hexToBytes(pqKemPublicHex as string),
      hexToBytes(pqSigPublicHex as string),
    );
    if (!mldsaOk) {
      throw new KeyBundleError(
        'invalid_signature',
        'ML-DSA binding signature does not verify against the hybrid context',
      );
    }
  }

  return {
    userId,
    ikPublicHex,
    ikxPublicHex,
    spkPublicHex,
    spkSignatureHex,
    opkPublicHex,
    version: response.version,
    pqKemPublicHex,
    pqSigPublicHex,
    pqBindingSigHex,
    protocolVersion,
  };
}

function requireHex(
  value: unknown,
  field: string,
  expectedChars: number,
): string {
  if (typeof value !== 'string') {
    throw new KeyBundleError('invalid_hex', `${field} must be a hex string`);
  }
  let bytes: Uint8Array;
  try {
    bytes = hexToBytes(value);
  } catch {
    throw new KeyBundleError('invalid_hex', `${field} is not valid hex`);
  }
  // Re-encode through the strict X25519/Ed25519 decoders for exact length.
  if (value.length !== expectedChars) {
    throw new KeyBundleError(
      'invalid_length',
      `${field} must decode to ${expectedChars / 2} bytes; got ${bytes.length}`,
    );
  }
  // Validate opacity of bytes (only 32-byte vs 64-byte signatures here).
  if (expectedChars === ED25519_PUBLIC_HEX_LENGTH) {
    x25519PublicFromHex(value); // 32-byte length check
  }
  // Surface length errors specifically for PQ material.
  if (
    expectedChars === ML_KEM_768_PUBLIC_KEY_HEX_LENGTH &&
    bytes.length !== ML_KEM_768_PUBLIC_KEY_BYTES
  ) {
    throw new KeyBundleError(
      'invalid_length',
      `pq_kem_public must decode to ${ML_KEM_768_PUBLIC_KEY_BYTES} bytes; got ${bytes.length}`,
    );
  }
  if (
    expectedChars === ML_DSA_44_PUBLIC_KEY_HEX_LENGTH &&
    bytes.length !== ML_DSA_44_PUBLIC_KEY_BYTES
  ) {
    throw new KeyBundleError(
      'invalid_length',
      `pq_sig_public must decode to ${ML_DSA_44_PUBLIC_KEY_BYTES} bytes; got ${bytes.length}`,
    );
  }
  if (
    expectedChars === ML_DSA_44_SIGNATURE_HEX_LENGTH &&
    bytes.length !== ML_DSA_44_SIGNATURE_BYTES
  ) {
    throw new KeyBundleError(
      'invalid_length',
      `pq_binding_sig must decode to ${ML_DSA_44_SIGNATURE_BYTES} bytes; got ${bytes.length}`,
    );
  }
  return value;
}

void HYBRID_BIND_CONTEXT_BYTES; // exported for testing the context
/**
 * Key-bundle parsing and validation (Phase 4).
 *
 * Converts the REST `KeyBundleResponse` (`src/types/keys.ts`) into a
 * validated, domain-friendly bundle and verifies the signed prekey binding.
 *
 * REST contract facts (verified against `server/routes/keys.py`,
 * `server/services/key_service.py`):
 *
 *   - `ik_public`   : 32-byte Ed25519 auth public (64-hex)
 *   - `xdh_public`  : 32-byte X25519 X3DH identity IKX (64-hex)
 *   - `spk_public`  : 32-byte X25519 signed prekey (64-hex)
 *   - `spk_sig`     : 64-byte Ed25519 signature (128-hex)
 *   - `opk_public`  : 32-byte X25519 OPK (64-hex) or null; single-use
 *   - `version`     : int, bumped on every upload
 */

import { hexToBytes } from './hex';
import { x25519PublicFromHex } from './x25519';
import { verifySignedPrekey } from './deviceKeys';
import type { KeyBundleResponse } from '../types/keys';

export const SPK_SIGNATURE_HEX_LENGTH = 128; // 64-byte Ed25519 signature
export const X25519_PUBLIC_HEX_LENGTH = 64; // 32-byte X25519 public key
export const ED25519_PUBLIC_HEX_LENGTH = 64; // 32-byte Ed25519 public key

export class KeyBundleError extends Error {
  public readonly code: 'invalid_hex' | 'invalid_length' | 'invalid_signature';
  constructor(
    code: 'invalid_hex' | 'invalid_length' | 'invalid_signature',
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
}

/**
 * Parse + validate a REST bundle response.
 *
 * Throws `KeyBundleError` when a key is not valid hex of the right length,
 * when the SPK signature does not verify against `ik_public`, or when the
 * response is missing required fields.
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

  return {
    userId,
    ikPublicHex,
    ikxPublicHex,
    spkPublicHex,
    spkSignatureHex,
    opkPublicHex,
    version: response.version,
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
  return value;
}
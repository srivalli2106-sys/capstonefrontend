/**
 * X25519 key-agreement primitives (Phase 4).
 *
 * The X3DH identity (`IKX`), signed prekey (`SPK`), and one-time prekeys
 * (`OPK`) are all X25519 keys: 32-byte private scalars and 32-byte public
 * u-coordinates, encoded on the wire as 64 lowercase hex characters — exactly
 * the key format the backend `protocol/keys.py` uses with `cryptography`.
 *
 * Implementation: `@noble/curves` `x25519` (RFC 7748, pure JS, constant-time).
 * We deliberately do not implement any Montgomery-ladder primitive ourselves.
 *
 * IMPORTANT: X25519 and Ed25519 are DIFFERENT key domains. An Ed25519 seed is
 * never used as an X25519 private key here; each domain keeps independently
 * generated keys. The backend protocol likewise keeps `IK` (Ed25519 auth) and
 * `IKX` (X25519 X3DH) separate.
 */

import { x25519 } from '@noble/curves/ed25519';
import { bytesToHex, hexToBytes } from './hex';

export const X25519_KEY_BYTES = 32;
export const X25519_SHARED_SECRET_BYTES = 32;

export interface X25519Keypair {
  /** 32-byte private scalar (raw). Must never leave the device unencrypted. */
  privateKey: Uint8Array;
  /** 32-byte public u-coordinate. */
  publicKey: Uint8Array;
}

export function generateX25519Keypair(): X25519Keypair {
  const privateKey = x25519.utils.randomSecretKey();
  const publicKey = x25519.getPublicKey(privateKey);
  if (
    privateKey.length !== X25519_KEY_BYTES ||
    publicKey.length !== X25519_KEY_BYTES
  ) {
    throw new Error('unexpected X25519 key length from noble/curves');
  }
  return { privateKey, publicKey };
}

export function x25519PublicFromPrivate(privateKey: Uint8Array): Uint8Array {
  requireKeyLength(privateKey, 'X25519 private key');
  const publicKey = x25519.getPublicKey(privateKey);
  if (publicKey.length !== X25519_KEY_BYTES) {
    throw new Error('unexpected X25519 public key length');
  }
  return publicKey;
}

/**
 * Raw X25519 DH (`priv.exchange(peerPublic)` in the backend). Returns the
 * 32-byte shared secret. Both sides of a DH use scalar + public u-coordinate;
 * the result is symmetric.
 */
export function dhX25519(
  privateKey: Uint8Array,
  peerPublicKey: Uint8Array,
): Uint8Array {
  requireKeyLength(privateKey, 'X25519 private key');
  requireKeyLength(peerPublicKey, 'X25519 peer public key');
  const shared = x25519.getSharedSecret(privateKey, peerPublicKey);
  if (shared.length !== X25519_SHARED_SECRET_BYTES) {
    throw new Error('unexpected X25519 shared secret length');
  }
  return shared;
}

export function x25519PublicToHex(publicKey: Uint8Array): string {
  requireKeyLength(publicKey, 'X25519 public key');
  return bytesToHex(publicKey);
}

export function x25519PublicFromHex(hex: string): Uint8Array {
  const bytes = hexToBytes(hex);
  requireKeyLength(bytes, 'X25519 public key');
  return bytes;
}

export function x25519PrivateFromHex(hex: string): Uint8Array {
  const bytes = hexToBytes(hex);
  requireKeyLength(bytes, 'X25519 private key');
  return bytes;
}

function requireKeyLength(bytes: Uint8Array, what: string): void {
  if (bytes.length !== X25519_KEY_BYTES) {
    throw new Error(
      `${what} must be ${X25519_KEY_BYTES} bytes; got ${bytes.length}.`,
    );
  }
}
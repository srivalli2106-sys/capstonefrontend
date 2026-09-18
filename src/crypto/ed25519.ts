/**
 * Ed25519 identity primitives.
 *
 * Contract (derived from `capstonebackend/server/protocol/keys.py` and
 * `server/auth_service.py`):
 *
 *  - The Ed25519 public key is 32 raw bytes, encoded as 64 lowercase hex
 *    characters on the wire (`ik_public`).
 *  - Ed25519 signatures are 64 raw bytes, encoded as 128 lowercase hex
 *    characters.
 *  - The proof-of-possession input is the **raw 32-byte nonce** (i.e.
 *    `bytes.fromhex(nonce_hex)`), NOT the ASCII/UTF-8 of the hex string.
 *  - Verification is RFC 8032 standard Ed25519.
 *
 * Implementation: `@noble/curves/ed25519` (audited, pure JS, constant-time).
 * We deliberately do not roll our own.
 */

import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, hexToBytes } from './hex';

export const ED25519_PUBLIC_KEY_BYTES = 32;
export const ED25519_PRIVATE_SEED_BYTES = 32;
export const ED25519_SIGNATURE_BYTES = 64;

export interface Ed25519Keypair {
  /** 32-byte seed (Ed25519 private key in noble's representation). */
  privateSeed: Uint8Array;
  /** 32-byte compressed public key (RFC 8032). */
  publicKey: Uint8Array;
}

export function generateEd25519Keypair(): Ed25519Keypair {
  const seed = ed25519.utils.randomSecretKey();
  const publicKey = ed25519.getPublicKey(seed);
  if (
    seed.length !== ED25519_PRIVATE_SEED_BYTES ||
    publicKey.length !== ED25519_PUBLIC_KEY_BYTES
  ) {
    throw new Error('unexpected Ed25519 key length from noble/curves');
  }
  return { privateSeed: seed, publicKey };
}

export function publicKeyFromPrivateSeed(seed: Uint8Array): Uint8Array {
  if (seed.length !== ED25519_PRIVATE_SEED_BYTES) {
    throw new Error(
      `Ed25519 seed must be ${ED25519_PRIVATE_SEED_BYTES} bytes; got ${seed.length}.`,
    );
  }
  return ed25519.getPublicKey(seed);
}

export function signRaw(
  message: Uint8Array,
  privateSeed: Uint8Array,
): Uint8Array {
  if (privateSeed.length !== ED25519_PRIVATE_SEED_BYTES) {
    throw new Error(
      `Ed25519 seed must be ${ED25519_PRIVATE_SEED_BYTES} bytes; got ${privateSeed.length}.`,
    );
  }
  const sig = ed25519.sign(message, privateSeed);
  if (sig.length !== ED25519_SIGNATURE_BYTES) {
    throw new Error('unexpected Ed25519 signature length');
  }
  return sig;
}

export function verifyRaw(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  if (publicKey.length !== ED25519_PUBLIC_KEY_BYTES) return false;
  if (signature.length !== ED25519_SIGNATURE_BYTES) return false;
  return ed25519.verify(signature, message, publicKey);
}

/**
 * Hex helpers for the backend wire format.
 */
export function publicKeyToHex(publicKey: Uint8Array): string {
  if (publicKey.length !== ED25519_PUBLIC_KEY_BYTES) {
    throw new Error(
      `public key must be ${ED25519_PUBLIC_KEY_BYTES} bytes; got ${publicKey.length}.`,
    );
  }
  return bytesToHex(publicKey);
}

export function publicKeyFromHex(hex: string): Uint8Array {
  const bytes = hexToBytes(hex);
  if (bytes.length !== ED25519_PUBLIC_KEY_BYTES) {
    throw new Error(
      `public key hex must decode to ${ED25519_PUBLIC_KEY_BYTES} bytes; got ${bytes.length}.`,
    );
  }
  return bytes;
}

export function signatureToHex(signature: Uint8Array): string {
  if (signature.length !== ED25519_SIGNATURE_BYTES) {
    throw new Error(
      `signature must be ${ED25519_SIGNATURE_BYTES} bytes; got ${signature.length}.`,
    );
  }
  return bytesToHex(signature);
}

export function signatureFromHex(hex: string): Uint8Array {
  const bytes = hexToBytes(hex);
  if (bytes.length !== ED25519_SIGNATURE_BYTES) {
    throw new Error(
      `signature hex must decode to ${ED25519_SIGNATURE_BYTES} bytes; got ${bytes.length}.`,
    );
  }
  return bytes;
}

/**
 * Hex short-id for UI display only. Never used for identification or auth.
 */
export function publicKeyShortId(publicKey: Uint8Array): string {
  return publicKeyToHex(publicKey).slice(0, 12);
}
/**
 * Post-quantum primitives for the hybrid E2EE phase.
 *
 * Wraps `@noble/post-quantum` (pure JS, NIST FIPS 203 / FIPS 204) so the
 * rest of the codebase talks in named, audited operations instead of
 * raw byte arrays.
 *
 * Conventions (NIST FIPS 203 / FIPS 204, mirrored on the backend `protocol`
 * Python module via the deterministic test vectors):
 *
 *   * ML-KEM-768 public key:  1184 bytes
 *   * ML-KEM-768 ciphertext:  1088 bytes
 *   * ML-KEM-768 shared secret: 32 bytes
 *   * ML-DSA-44 public key:   1312 bytes
 *   * ML-DSA-44 signature:    2420 bytes
 *
 * All keys and signatures stay on-device. The backend never sees them.
 */

import {
  ml_kem768,
} from '@noble/post-quantum/ml-kem.js';
import { ml_dsa44 as mlDsa44Module } from '@noble/post-quantum/ml-dsa.js';

// Sizes are locked by NIST and mirrored in the backend.
// If these change, both repos must regenerate the deterministic
// cross-implementation test vectors.
export const ML_KEM_768_PUBLIC_KEY_BYTES = 1184;
export const ML_KEM_768_CIPHERTEXT_BYTES = 1088;
export const ML_KEM_768_SHARED_SECRET_BYTES = 32;
export const ML_DSA_44_PUBLIC_KEY_BYTES = 1312;
export const ML_DSA_44_SIGNATURE_BYTES = 2420;

// ---------------- ML-KEM-768 ----------------

export interface MlKem768Keypair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export function generateMlKem768Keypair(): MlKem768Keypair {
  const k = ml_kem768.keygen();
  assertLength(k.publicKey, ML_KEM_768_PUBLIC_KEY_BYTES, 'ml_kem768.publicKey');
  assertLength(k.secretKey, ML_KEM_768_PRIVATE_KEY_BYTES, 'ml_kem768.secretKey');
  return { publicKey: k.publicKey, privateKey: k.secretKey };
}

export function mlKem768Encapsulate(
  publicKey: Uint8Array,
): { ciphertext: Uint8Array; sharedSecret: Uint8Array } {
  assertLength(publicKey, ML_KEM_768_PUBLIC_KEY_BYTES, 'ml_kem768.publicKey');
  const r = ml_kem768.encapsulate(publicKey);
  assertLength(r.cipherText, ML_KEM_768_CIPHERTEXT_BYTES, 'cipherText');
  assertLength(r.sharedSecret, ML_KEM_768_SHARED_SECRET_BYTES, 'sharedSecret');
  return { ciphertext: r.cipherText, sharedSecret: r.sharedSecret };
}

/**
 * Recover the ML-KEM-768 public key from its secret key. Used by the
 * initiator to attach its own pq_kem_pub to the v2 INIT payload (the
 * responder only needs the KEM ciphertext; the public key travels in the
 * bundle, but we expose it via the INIT for redundancy).
 */
export function mlKem768DerivePublicKey(privateKey: Uint8Array): Uint8Array {
  const pub = ml_kem768.getPublicKey(privateKey);
  assertLength(pub, ML_KEM_768_PUBLIC_KEY_BYTES, 'ml_kem768.getPublicKey');
  return pub;
}

export function mlKem768Decapsulate(
  privateKey: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  assertLength(ciphertext, ML_KEM_768_CIPHERTEXT_BYTES, 'cipherText');
  const ss = ml_kem768.decapsulate(ciphertext, privateKey);
  assertLength(ss, ML_KEM_768_SHARED_SECRET_BYTES, 'sharedSecret');
  return ss;
}

// `secretKey` from noble's keygen is 2400 bytes; we expose a typed alias
// here but keep callers free of the exact byte length.
export const ML_KEM_768_PRIVATE_KEY_BYTES = 2400;

// ---------------- ML-DSA-44 ----------------

export interface MlDsa44Keypair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export function generateMlDsa44Keypair(): MlDsa44Keypair {
  const k = mlDsa44Module.keygen();
  assertLength(k.publicKey, ML_DSA_44_PUBLIC_KEY_BYTES, 'ml_dsa44.publicKey');
  // ML-DSA-44 secret key length is 2560 bytes; expose as alias.
  assertLength(k.secretKey, ML_DSA_44_PRIVATE_KEY_BYTES, 'ml_dsa44.secretKey');
  return { publicKey: k.publicKey, privateKey: k.secretKey };
}

/**
 * Recover the ML-DSA-44 public key from its secret key. The device
 * stores the secret key (encrypted under the passphrase) and re-derives
 * the public key on demand.
 */
export function mlDsa44DerivePublicKey(privateKey: Uint8Array): Uint8Array {
  const pub = mlDsa44Module.getPublicKey(privateKey);
  assertLength(pub, ML_DSA_44_PUBLIC_KEY_BYTES, 'ml_dsa44.getPublicKey');
  return pub;
}

export function mlDsa44Sign(
  message: Uint8Array,
  privateKey: Uint8Array,
): Uint8Array {
  const sig = mlDsa44Module.sign(message, privateKey);
  assertLength(sig, ML_DSA_44_SIGNATURE_BYTES, 'ml_dsa44 signature');
  return sig;
}

export function mlDsa44Verify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  assertLength(signature, ML_DSA_44_SIGNATURE_BYTES, 'ml_dsa44 signature');
  assertLength(publicKey, ML_DSA_44_PUBLIC_KEY_BYTES, 'ml_dsa44 publicKey');
  return mlDsa44Module.verify(signature, message, publicKey);
}

export const ML_DSA_44_PRIVATE_KEY_BYTES = 2560;

// ---------------- helpers ----------------

function assertLength(buf: Uint8Array, expected: number, name: string): void {
  if (!(buf instanceof Uint8Array) || buf.length !== expected) {
    throw new Error(
      `${name} must be a Uint8Array of length ${expected}; got ${buf?.length}`,
    );
  }
}

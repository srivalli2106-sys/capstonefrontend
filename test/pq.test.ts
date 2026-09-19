/**
 * Tests for the @noble/post-quantum wrappers (`src/crypto/pq.ts`).
 */

import { describe, expect, it } from 'vitest';
import {
  generateMlDsa44Keypair,
  generateMlKem768Keypair,
  ML_DSA_44_PRIVATE_KEY_BYTES,
  ML_DSA_44_PUBLIC_KEY_BYTES,
  ML_DSA_44_SIGNATURE_BYTES,
  ML_KEM_768_CIPHERTEXT_BYTES,
  ML_KEM_768_PRIVATE_KEY_BYTES,
  ML_KEM_768_PUBLIC_KEY_BYTES,
  ML_KEM_768_SHARED_SECRET_BYTES,
  mlDsa44DerivePublicKey,
  mlDsa44Sign,
  mlDsa44Verify,
  mlKem768Decapsulate,
  mlKem768DerivePublicKey,
  mlKem768Encapsulate,
} from '../src/crypto/pq';

describe('ML-KEM-768 (NIST FIPS 203)', () => {
  it('generates a keypair with the documented byte lengths', () => {
    const k = generateMlKem768Keypair();
    expect(k.publicKey.length).toBe(ML_KEM_768_PUBLIC_KEY_BYTES);
    expect(k.privateKey.length).toBe(ML_KEM_768_PRIVATE_KEY_BYTES);
  });

  it('encapsulates and decapsulates to the same shared secret', () => {
    const k = generateMlKem768Keypair();
    const { ciphertext, sharedSecret } = mlKem768Encapsulate(k.publicKey);
    expect(ciphertext.length).toBe(ML_KEM_768_CIPHERTEXT_BYTES);
    expect(sharedSecret.length).toBe(ML_KEM_768_SHARED_SECRET_BYTES);
    const ss2 = mlKem768Decapsulate(k.privateKey, ciphertext);
    expect(ss2.length).toBe(ML_KEM_768_SHARED_SECRET_BYTES);
    expect(toEqual(ss2, sharedSecret)).toBe(true);
  });

  it('produces distinct shared secrets for distinct encapsulations', () => {
    const k = generateMlKem768Keypair();
    const a = mlKem768Encapsulate(k.publicKey);
    const b = mlKem768Encapsulate(k.publicKey);
    expect(toEqual(a.sharedSecret, b.sharedSecret)).toBe(false);
  });

  it('derives the public key from the private key (round-trip)', () => {
    const k = generateMlKem768Keypair();
    const derived = mlKem768DerivePublicKey(k.privateKey);
    expect(toEqual(derived, k.publicKey)).toBe(true);
  });

  it('rejects wrong-length inputs', () => {
    expect(() => mlKem768Encapsulate(new Uint8Array(32))).toThrow();
    expect(() => mlKem768Decapsulate(new Uint8Array(32), new Uint8Array(32))).toThrow();
  });
});

describe('ML-DSA-44 (NIST FIPS 204)', () => {
  it('generates a keypair with the documented byte lengths', () => {
    const k = generateMlDsa44Keypair();
    expect(k.publicKey.length).toBe(ML_DSA_44_PUBLIC_KEY_BYTES);
    expect(k.privateKey.length).toBe(ML_DSA_44_PRIVATE_KEY_BYTES);
  });

  it('signs and verifies a message', () => {
    const k = generateMlDsa44Keypair();
    const msg = new TextEncoder().encode('hello post-quantum');
    const sig = mlDsa44Sign(msg, k.privateKey);
    expect(sig.length).toBe(ML_DSA_44_SIGNATURE_BYTES);
    expect(mlDsa44Verify(sig, msg, k.publicKey)).toBe(true);
  });

  it('rejects a tampered message', () => {
    const k = generateMlDsa44Keypair();
    const msg = new TextEncoder().encode('original message');
    const sig = mlDsa44Sign(msg, k.privateKey);
    const tampered = new TextEncoder().encode('tampered message');
    expect(mlDsa44Verify(sig, tampered, k.publicKey)).toBe(false);
  });

  it('rejects a tampered signature', () => {
    const k = generateMlDsa44Keypair();
    const msg = new TextEncoder().encode('test');
    const sig = mlDsa44Sign(msg, k.privateKey);
    const tampered = new Uint8Array(sig);
    tampered[0] = (tampered[0] ?? 0) ^ 0xff;
    expect(mlDsa44Verify(tampered, msg, k.publicKey)).toBe(false);
  });

  it('rejects a signature under a different public key', () => {
    const alice = generateMlDsa44Keypair();
    const bob = generateMlDsa44Keypair();
    const msg = new TextEncoder().encode('for bob');
    const sig = mlDsa44Sign(msg, alice.privateKey);
    expect(mlDsa44Verify(sig, msg, bob.publicKey)).toBe(false);
  });

  it('derives the public key from the private key (round-trip)', () => {
    const k = generateMlDsa44Keypair();
    const derived = mlDsa44DerivePublicKey(k.privateKey);
    expect(toEqual(derived, k.publicKey)).toBe(true);
  });
});

function toEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

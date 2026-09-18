import { describe, expect, it } from 'vitest';
import {
  ED25519_PRIVATE_SEED_BYTES,
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_BYTES,
  generateEd25519Keypair,
  publicKeyFromHex,
  publicKeyFromPrivateSeed,
  publicKeyToHex,
  signRaw,
  verifyRaw,
} from '../src/crypto/ed25519';
import { bytesToHex, hexToBytes } from '../src/crypto/hex';

describe('hex round-trip', () => {
  it('encodes and decodes a 32-byte sequence', () => {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i += 1) bytes[i] = i;
    const hex = bytesToHex(bytes);
    expect(hex.length).toBe(64);
    expect(hex).toBe(
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    );
    const decoded = hexToBytes(hex);
    expect(decoded).toEqual(bytes);
  });

  it('rejects odd-length hex', () => {
    expect(() => hexToBytes('abc')).toThrow();
  });

  it('rejects non-hex characters', () => {
    expect(() => hexToBytes('zz')).toThrow();
  });
});

describe('Ed25519 key generation', () => {
  it('produces a 32-byte private seed and 32-byte public key', () => {
    const kp = generateEd25519Keypair();
    expect(kp.privateSeed.length).toBe(ED25519_PRIVATE_SEED_BYTES);
    expect(kp.publicKey.length).toBe(ED25519_PUBLIC_KEY_BYTES);
  });

  it('produces distinct keypairs on each call', () => {
    const a = generateEd25519Keypair();
    const b = generateEd25519Keypair();
    expect(bytesToHex(a.privateSeed)).not.toBe(bytesToHex(b.privateSeed));
    expect(bytesToHex(a.publicKey)).not.toBe(bytesToHex(b.publicKey));
  });

  it('derives a matching public key from the seed', () => {
    const { privateSeed, publicKey } = generateEd25519Keypair();
    const derived = publicKeyFromPrivateSeed(privateSeed);
    expect(derived).toEqual(publicKey);
  });
});

describe('Ed25519 hex encoding', () => {
  it('emits 64 lowercase hex chars for a public key', () => {
    const { publicKey } = generateEd25519Keypair();
    const hex = publicKeyToHex(publicKey);
    expect(hex.length).toBe(64);
    expect(hex).toMatch(/^[0-9a-f]+$/);
  });

  it('rejects non-32-byte input', () => {
    expect(() => publicKeyToHex(new Uint8Array(31))).toThrow();
    expect(() => publicKeyFromHex('ab'.repeat(31))).toThrow();
  });
});

describe('Ed25519 sign + verify', () => {
  it('produces a 64-byte signature', () => {
    const { privateSeed } = generateEd25519Keypair();
    const sig = signRaw(new Uint8Array([1, 2, 3]), privateSeed);
    expect(sig.length).toBe(ED25519_SIGNATURE_BYTES);
  });

  it('verifies the correct signature on the correct nonce', () => {
    const { privateSeed, publicKey } = generateEd25519Keypair();
    const nonce = new Uint8Array(32);
    for (let i = 0; i < 32; i += 1) nonce[i] = i * 7;
    const sig = signRaw(nonce, privateSeed);
    expect(verifyRaw(sig, nonce, publicKey)).toBe(true);
  });

  it('rejects a modified nonce', () => {
    const { privateSeed, publicKey } = generateEd25519Keypair();
    const nonce = new Uint8Array(32).fill(1);
    const sig = signRaw(nonce, privateSeed);
    const tampered = new Uint8Array(nonce);
    tampered[0] = (tampered[0] ?? 0) ^ 1;
    expect(verifyRaw(sig, tampered, publicKey)).toBe(false);
  });

  it('rejects a wrong public key', () => {
    const a = generateEd25519Keypair();
    const b = generateEd25519Keypair();
    const nonce = new Uint8Array(32).fill(2);
    const sig = signRaw(nonce, a.privateSeed);
    expect(verifyRaw(sig, nonce, b.publicKey)).toBe(false);
  });

  it('does NOT verify when the hex string of the nonce is signed', () => {
    const { privateSeed, publicKey } = generateEd25519Keypair();
    const nonceBytes = new Uint8Array(32).fill(3);
    const nonceHex = bytesToHex(nonceBytes);
    // Sign the ASCII bytes of the hex string (the wrong input).
    const wrongSig = signRaw(new TextEncoder().encode(nonceHex), privateSeed);
    // The backend signs the RAW bytes; verify on the raw bytes must fail.
    expect(verifyRaw(wrongSig, nonceBytes, publicKey)).toBe(false);
  });
});
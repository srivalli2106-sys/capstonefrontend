import { describe, expect, it } from 'vitest';
import {
  X25519_KEY_BYTES,
  X25519_SHARED_SECRET_BYTES,
  dhX25519,
  generateX25519Keypair,
  x25519PublicFromHex,
  x25519PublicFromPrivate,
  x25519PublicToHex,
} from '../src/crypto/x25519';
import { bytesToHex, hexToBytes } from '../src/crypto/hex';

function fromHex(hex: string): Uint8Array {
  return hexToBytes(hex);
}

const IKX_A_PRIV_HEX =
  '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20';
// Known-good public key for that scalar (RFC 7748 vector, computed by
// cryptography / Python via the backend protocol package):
const IKX_A_PUB_HEX =
  '07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c';

describe('X25519 key generation', () => {
  it('produces 32-byte private and 32-byte public keys', () => {
    const kp = generateX25519Keypair();
    expect(kp.privateKey.length).toBe(X25519_KEY_BYTES);
    expect(kp.publicKey.length).toBe(X25519_KEY_BYTES);
  });

  it('produces distinct keypairs on each call', () => {
    const a = generateX25519Keypair();
    const b = generateX25519Keypair();
    expect(bytesToHex(a.privateKey)).not.toBe(bytesToHex(b.privateKey));
    expect(bytesToHex(a.publicKey)).not.toBe(bytesToHex(b.publicKey));
  });

  it('derives a matching public key from the private key', () => {
    const { privateKey, publicKey } = generateX25519Keypair();
    expect(x25519PublicFromPrivate(privateKey)).toEqual(publicKey);
  });
});

describe('X25519 public-key derivation matches the backend (fixed vector)', () => {
  it('computes the reference public key for a fixed scalar', () => {
    const pub = x25519PublicFromPrivate(fromHex(IKX_A_PRIV_HEX));
    expect(bytesToHex(pub)).toBe(IKX_A_PUB_HEX);
  });
});

describe('X25519 encoding', () => {
  it('emits 64 lowercase hex chars', () => {
    const { publicKey } = generateX25519Keypair();
    const hex = x25519PublicToHex(publicKey);
    expect(hex.length).toBe(64);
    expect(hex).toMatch(/^[0-9a-f]+$/);
  });

  it('round-trips hex', () => {
    const { publicKey } = generateX25519Keypair();
    expect(x25519PublicFromHex(x25519PublicToHex(publicKey))).toEqual(publicKey);
  });

  it('rejects wrong-length encoded keys', () => {
    expect(() => x25519PublicFromHex('ab'.repeat(31))).toThrow();
    expect(() => x25519PublicFromHex('ab')).toThrow();
  });

  it('rejects non-hex input', () => {
    expect(() => x25519PublicFromHex('zz'.repeat(32))).toThrow();
  });
});

describe('X25519 DH', () => {
  it('agrees symmetrically (s1 === s2)', () => {
    const a = generateX25519Keypair();
    const b = generateX25519Keypair();
    const s1 = dhX25519(a.privateKey, b.publicKey);
    const s2 = dhX25519(b.privateKey, a.publicKey);
    expect(s1.length).toBe(X25519_SHARED_SECRET_BYTES);
    expect(s2).toEqual(s1);
  });

  it('differs across key pairs', () => {
    const a = generateX25519Keypair();
    const b = generateX25519Keypair();
    const c = generateX25519Keypair();
    const ab = dhX25519(a.privateKey, b.publicKey);
    const ac = dhX25519(a.privateKey, c.publicKey);
    expect(bytesToHex(ab)).not.toBe(bytesToHex(ac));
  });

  it('rejects wrong-length public input', () => {
    const { privateKey } = generateX25519Keypair();
    expect(() => dhX25519(privateKey, new Uint8Array(31))).toThrow();
    expect(() => dhX25519(privateKey, new Uint8Array(33))).toThrow();
  });
});
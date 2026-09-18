import { describe, expect, it } from 'vitest';
import { encrypt, decrypt } from '../src/crypto/aead';
import { deriveAesKey, randomSalt } from '../src/crypto/kdf';

describe('PBKDF2 + AES-GCM identity envelope', () => {
  it('round-trips: correct passphrase decrypts to the original seed', async () => {
    const passphrase = 'correct horse battery staple';
    const salt = randomSalt();
    const { subtleKey } = await deriveAesKey(passphrase, salt);

    const plaintext = new Uint8Array(32);
    for (let i = 0; i < 32; i += 1) plaintext[i] = i + 1;
    const ad = new TextEncoder().encode('secure-messaging-identity-v1\x1falice');

    const blob = await encrypt(subtleKey, plaintext, ad);
    expect(blob.ivHex.length).toBe(24); // 12 bytes hex
    expect(blob.ciphertextHex.length).toBeGreaterThanOrEqual(64); // 32 seed + 16 tag

    const decrypted = await decrypt(subtleKey, blob, ad);
    expect(decrypted).toEqual(plaintext);
  });

  it('wrong passphrase yields a decryption error (AEAD tag mismatch)', async () => {
    const salt = randomSalt();
    const goodKey = (await deriveAesKey('right', salt)).subtleKey;
    const wrongKey = (await deriveAesKey('wrong', salt)).subtleKey;

    const plaintext = new Uint8Array(32).fill(7);
    const ad = new Uint8Array([1, 2, 3]);
    const blob = await encrypt(goodKey, plaintext, ad);

    await expect(decrypt(wrongKey, blob, ad)).rejects.toBeDefined();
  });

  it('a flipped ciphertext byte fails decryption', async () => {
    const passphrase = 'tamper-test';
    const salt = randomSalt();
    const { subtleKey } = await deriveAesKey(passphrase, salt);
    const plaintext = new Uint8Array(32).fill(9);
    const ad = new Uint8Array([4, 5, 6]);
    const blob = await encrypt(subtleKey, plaintext, ad);

    // Mutate the ciphertext (flip a bit).
    const tamperedBytes = Uint8Array.from(
      blob.ciphertextHex.match(/.{1,2}/g)!.map((b) => Number.parseInt(b, 16)),
    );
    tamperedBytes[0] = tamperedBytes[0]! ^ 1;
    const tampered = {
      ivHex: blob.ivHex,
      ciphertextHex: Array.from(tamperedBytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join(''),
    };

    await expect(decrypt(subtleKey, tampered, ad)).rejects.toBeDefined();
  });

  it('produces distinct IVs across calls (fresh nonce per encryption)', async () => {
    const passphrase = 'iv-test';
    const salt = randomSalt();
    const { subtleKey } = await deriveAesKey(passphrase, salt);
    const plaintext = new Uint8Array(32).fill(1);
    const ad = new Uint8Array();
    const a = await encrypt(subtleKey, plaintext, ad);
    const b = await encrypt(subtleKey, plaintext, ad);
    expect(a.ivHex).not.toBe(b.ivHex);
  });

  it('derives the same key from the same passphrase + salt (PBKDF2 determinism)', async () => {
    const salt = randomSalt();
    const a = (await deriveAesKey('p', salt)).rawKey;
    const b = (await deriveAesKey('p', salt)).rawKey;
    expect(a).toEqual(b);
  });

  it('different salts produce different keys', async () => {
    const a = (await deriveAesKey('p', randomSalt())).rawKey;
    const b = (await deriveAesKey('p', randomSalt())).rawKey;
    expect(a).not.toEqual(b);
  });
});
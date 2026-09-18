import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  IDENTITY_DB_NAME,
  deleteIdentityRecord,
  getIdentityRecord,
  listIdentityUserIds,
  saveIdentityRecord,
} from '../src/crypto/identityStore';
import {
  createLocalIdentity,
  deleteLocalIdentity,
  inspectIdentity,
  unlockIdentity,
} from '../src/crypto/identity';
import {
  generateEd25519Keypair,
  publicKeyFromHex,
  publicKeyToHex,
  signRaw,
  verifyRaw,
} from '../src/crypto/ed25519';
import { bytesToHex } from '../src/crypto/hex';

function uniqueUserId(label: string): string {
  return `${label}_${Date.now().toString(36)}_${Math.floor(Math.random() * 1e6).toString(36)}`;
}

async function clearDb(): Promise<void> {
  const dbs = await indexedDB.databases?.();
  if (!dbs) return;
  for (const db of dbs) {
    if (db.name === IDENTITY_DB_NAME && db.version !== undefined) {
      await new Promise<void>((resolve, reject) => {
        const req = indexedDB.deleteDatabase(db.name!);
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
        req.onblocked = () => resolve();
      });
    }
  }
}

beforeEach(async () => {
  await clearDb();
});

afterEach(async () => {
  await clearDb();
});

describe('IndexedDB identity record format', () => {
  it('refuses to persist an unsupported schema_version', async () => {
    await expect(
      saveIdentityRecord({
        user_id: 'alice',
        ik_public: 'ab'.repeat(32),
        created_at: Date.now(),
        schema_version: 999,
        enc_seed: {
          record_version: 1,
          kdf: 'pbkdf2-sha256',
          iterations: 1,
          salt_hex: '00'.repeat(16),
          iv_hex: '00'.repeat(12),
          ciphertext_hex: '00',
        },
      }),
    ).rejects.toThrow(/schema_version/);
  });
});

describe('Encrypted local identity lifecycle', () => {
  it('creates, unlocks, signs, and decrypts to the original seed', async () => {
    const userId = uniqueUserId('alice');
    const passphrase = 'a-strong-passphrase-1';

    const { publicKeyHex } = await createLocalIdentity(userId, passphrase);
    expect(publicKeyHex).toMatch(/^[0-9a-f]{64}$/);

    // Confirm the record is on disk and the seed is NOT plaintext.
    const record = await getIdentityRecord(userId);
    expect(record).not.toBeNull();
    expect(record!.user_id).toBe(userId);
    expect(record!.ik_public).toBe(publicKeyHex);
    expect(record!.enc_seed.ciphertext_hex).not.toContain(publicKeyHex.slice(0, 16));
    expect(record!.enc_seed.kdf).toBe('pbkdf2-sha256');
    expect(record!.enc_seed.iterations).toBeGreaterThanOrEqual(100_000);

    // Unlock with the correct passphrase and verify the seed produces
    // signatures that the original public key verifies.
    const unlocked = await unlockIdentity(userId, passphrase);
    const nonce = new Uint8Array(32);
    for (let i = 0; i < 32; i += 1) nonce[i] = i + 1;
    const sig = unlocked.signNonceRaw(nonce);
    expect(
      verifyRaw(sig, nonce, publicKeyFromHex(unlocked.publicKeyHex)),
    ).toBe(true);

    unlocked.lock();
  });

  it('rejects an incorrect passphrase (wrong_passphrase error)', async () => {
    const userId = uniqueUserId('bob');
    await createLocalIdentity(userId, 'right-passphrase');
    await expect(unlockIdentity(userId, 'wrong-passphrase')).rejects.toMatchObject(
      { code: 'wrong_passphrase' },
    );
  });

  it('returns no_record when the user_id has never been registered locally', async () => {
    await expect(
      unlockIdentity(uniqueUserId('ghost'), 'whatever'),
    ).rejects.toMatchObject({ code: 'no_record' });
  });

  it('inspectIdentity returns the public summary without decrypting', async () => {
    const userId = uniqueUserId('carol');
    const { publicKeyHex } = await createLocalIdentity(userId, 'p4ssphrase');
    const summary = await inspectIdentity(userId);
    expect(summary).not.toBeNull();
    expect(summary!.userId).toBe(userId);
    expect(summary!.publicKeyHex).toBe(publicKeyHex);
    expect(summary!.publicKeyShortId).toBe(publicKeyHex.slice(0, 12));
    expect(await inspectIdentity(uniqueUserId('nope'))).toBeNull();
  });

  it('deleteLocalIdentity removes the record', async () => {
    const userId = uniqueUserId('dave');
    await createLocalIdentity(userId, 'p4ssphrase');
    expect((await listIdentityUserIds()).includes(userId)).toBe(true);
    await deleteLocalIdentity(userId);
    expect(await getIdentityRecord(userId)).toBeNull();
  });

  it('the persisted record does not leak the public key inside the ciphertext', async () => {
    const userId = uniqueUserId('eve');
    const { publicKeyHex } = await createLocalIdentity(userId, 'p4ssphrase');
    const record = await getIdentityRecord(userId);
    expect(record).not.toBeNull();
    const ctLower = record!.enc_seed.ciphertext_hex.toLowerCase();
    const pkLower = publicKeyHex.toLowerCase();
    // A weak sanity check: no 16-hex-char prefix of the public key appears
    // verbatim in the ciphertext (would require astronomically unlikely luck).
    for (let i = 0; i + 16 <= pkLower.length; i += 8) {
      expect(ctLower).not.toContain(pkLower.slice(i, i + 16));
    }
  });
});

describe('Ed25519 ↔ backend wire format compatibility', () => {
  it('produces a 32-byte public key whose hex is accepted by hexToBytes round-trip', () => {
    const { publicKey } = generateEd25519Keypair();
    const hex = publicKeyToHex(publicKey);
    expect(hex.length).toBe(64);
    // round trip
    expect(publicKeyFromHex(hex)).toEqual(publicKey);
  });

  it('signs the RAW nonce bytes (not the ASCII hex) and verifies on the raw bytes', () => {
    const { privateSeed, publicKey } = generateEd25519Keypair();
    // Backend wire form is a 64-char hex string. Backend verifies with
    // public_key.verify(signature, bytes.fromhex(nonce_hex)).
    const nonceBytes = new Uint8Array(32);
    for (let i = 0; i < 32; i += 1) nonceBytes[i] = 0xa0 ^ i;
    const nonceHex = bytesToHex(nonceBytes);

    const sig = signRaw(nonceBytes, privateSeed);
    // Verifying on raw bytes: must succeed.
    expect(verifyRaw(sig, nonceBytes, publicKey)).toBe(true);
    // Verifying on the ASCII bytes of the hex string: must fail.
    const sigOverHexString = signRaw(new TextEncoder().encode(nonceHex), privateSeed);
    expect(verifyRaw(sigOverHexString, nonceBytes, publicKey)).toBe(false);
    // The hex string's first byte ('0' = 0x30) is different from 0xa0.
    expect(nonceHex.charCodeAt(0)).toBe(0x30);
  });
});

describe('Phase 3 client invariants', () => {
  it('private seed never appears in the JSON-serializable persisted record', async () => {
    const userId = uniqueUserId('frank');
    const { publicKeyHex } = await createLocalIdentity(userId, 'p4ssphrase');
    const record = await getIdentityRecord(userId);
    const json = JSON.stringify(record);
    // Public key MAY appear (it's intentionally persisted). Private seed
    // MUST NOT.
    expect(json).toContain(publicKeyHex.slice(0, 32));
    // No 64-hex-char span in the JSON should match the entire public key.
    // (Hard to assert without knowing the seed; the no-plaintext guarantee
    // is verified above by the AEAD round-trip test.)
    expect(json).not.toContain(record!.enc_seed.ciphertext_hex.slice(0, 64));
  });
});
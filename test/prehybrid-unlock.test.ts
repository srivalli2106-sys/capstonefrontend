/**
 * Regression test for the pre-hybrid unlock failure.
 *
 * Before the fix:
 *   - deserializeDeviceKeys() rejected any payload whose version byte was
 *     not the current DEVICE_KEYS_PAYLOAD_VERSION (= 2).
 *   - Users who registered before the hybrid upgrade had a v1 device-keys
 *     payload on disk (version byte = 1).
 *   - unlockIdentity() surfaced the rejection as
 *     "Incorrect passphrase or corrupted record." — the passphrase was
 *     correct, the payload was simply a different (older) version.
 *
 * After the fix:
 *   - deserializeDeviceKeys() accepts both v1 and v2.
 *   - v1 payloads decode to classical-only keys (pqKemPrivate = null,
 *     pqSigPrivate = null).
 *   - The full unlock flow (IndexedDB → AES-GCM → identity.ts) succeeds
 *     end-to-end with the v1 payload on disk.
 */

import { beforeEach, afterEach, describe, expect, it } from 'vitest';
import {
  createLocalIdentity,
  deleteLocalIdentity,
  unlockIdentity,
} from '../src/crypto/identity';
import {
  IDENTITY_DB_NAME,
  _closeForTest,
  getIdentityRecord,
  saveIdentityRecord,
  type IdentityRecord,
} from '../src/crypto/identityStore';
import { deriveAesKey, randomSalt, PBKDF2_ITERATIONS } from '../src/crypto/kdf';
import { encrypt } from '../src/crypto/aead';
import {
  deviceKeysAssociatedData,
} from '../src/crypto/deviceKeys';

const PASS = 'correct horse battery staple';

async function clearDb(): Promise<void> {
  await _closeForTest();
  const dbs = await indexedDB.databases?.();
  if (!dbs) return;
  for (const db of dbs) {
    if (db.name === IDENTITY_DB_NAME && db.version !== undefined) {
      await new Promise<void>((resolve, reject) => {
        const req = indexedDB.deleteDatabase(db.name!);
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
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

describe('pre-hybrid v1 unlock: end-to-end', () => {
  it('an existing user with a v1 encrypted device-keys blob can unlock', async () => {
    const userId = `prehybrid-${Date.now()}`;

    // 1. Create a normal identity (this uses the same seed envelope format
    //    as before; the seed envelope is unchanged).
    await createLocalIdentity(userId, PASS);

    // 2. Simulate a pre-hybrid device-keys envelope: a v1 binary payload,
    //    encrypted under the user's passphrase + a fresh salt (this matches
    //    how the persistence layer created envelopes before the upgrade).
    const record = await getIdentityRecord(userId);
    expect(record).not.toBeNull();

    const v1Payload = new Uint8Array(98); // version 1, with OPK
    v1Payload[0] = 1; // v1
    for (let i = 0; i < 32; i += 1) v1Payload[1 + i] = 0x10 + i;
    for (let i = 0; i < 32; i += 1) v1Payload[33 + i] = 0x30 + i;
    v1Payload[65] = 1; // OPK present
    for (let i = 0; i < 32; i += 1) v1Payload[66 + i] = 0x70 + i;

    const salt = randomSalt();
    const { subtleKey } = await deriveAesKey(PASS, salt, PBKDF2_ITERATIONS);
    const ad = deviceKeysAssociatedData(userId);
    const blob = await encrypt(subtleKey, v1Payload, ad);

    const v1Envelope = {
      record_version: 1,
      kdf: 'pbkdf2-sha256' as const,
      iterations: PBKDF2_ITERATIONS,
      salt_hex: bytesToHex(salt),
      iv_hex: blob.ivHex,
      ciphertext_hex: blob.ciphertextHex,
    };

    const r = record as IdentityRecord;
    r.enc_device_keys = v1Envelope;
    await saveIdentityRecord(r);

    // 3. The user signs in again. unlockIdentity() must succeed and the
    //    device keys must match the v1 payload exactly (with PQ keys null).
    const unlocked = await unlockIdentity(userId, PASS);
    expect(unlocked.userId).toBe(userId);
    expect(unlocked.deviceKeys).not.toBeNull();
    const dk = unlocked.deviceKeys!;
    expect(dk.pqKemPrivate).toBeNull();
    expect(dk.pqSigPrivate).toBeNull();
    expect(dk.ikxPrivate).toEqual(v1Payload.slice(1, 33));
    expect(dk.spkPrivate).toEqual(v1Payload.slice(33, 65));
    expect(dk.opkPrivate).toEqual(v1Payload.slice(66, 98));
    unlocked.lock();
  });

  it('wrong passphrase still fails (does not silently accept a v1 mismatch)', async () => {
    const userId = `prehybrid-wrongpw-${Date.now()}`;
    await createLocalIdentity(userId, PASS);

    const record = await getIdentityRecord(userId);
    expect(record).not.toBeNull();

    // Drop a v1 envelope — same path as the test above.
    const v1Payload = new Uint8Array(66); // v1, no OPK
    v1Payload[0] = 1;
    for (let i = 0; i < 32; i += 1) v1Payload[1 + i] = 0x11 + i;
    for (let i = 0; i < 32; i += 1) v1Payload[33 + i] = 0x33 + i;
    v1Payload[65] = 0; // no OPK
    const salt = randomSalt();
    const { subtleKey } = await deriveAesKey(PASS, salt, PBKDF2_ITERATIONS);
    const ad = deviceKeysAssociatedData(userId);
    const blob = await encrypt(subtleKey, v1Payload, ad);
    const r = record as IdentityRecord;
    r.enc_device_keys = {
      record_version: 1,
      kdf: 'pbkdf2-sha256',
      iterations: PBKDF2_ITERATIONS,
      salt_hex: bytesToHex(salt),
      iv_hex: blob.ivHex,
      ciphertext_hex: blob.ciphertextHex,
    };
    await saveIdentityRecord(r);

    await expect(unlockIdentity(userId, 'wrong-passphrase')).rejects.toMatchObject({
      code: 'wrong_passphrase',
    });
  });
});

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) {
    out += (bytes[i] ?? 0).toString(16).padStart(2, '0');
  }
  return out;
}

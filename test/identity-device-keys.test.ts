import { describe, expect, it } from 'vitest';
import {
  createLocalIdentity,
  deleteLocalIdentity,
  unlockIdentity,
} from '../src/crypto/identity';
import {
  getIdentityRecord,
  saveIdentityRecord,
  type IdentityRecord,
} from '../src/crypto/identityStore';

const PASS = 'correct horse battery staple';

describe('device-key provisioning lifecycle', () => {
  it('new records embed an encrypted device-keys envelope', async () => {
    const userId = `dk-new-${Date.now()}`;
    await createLocalIdentity(userId, PASS);
    const record = await getIdentityRecord(userId);
    expect(record).not.toBeNull();
    expect(record!.enc_device_keys).toBeDefined();
    expect(record!.enc_device_keys!.ciphertext_hex.length).toBeGreaterThan(0);
    // The plaintext private scalar must NOT be anywhere in the record JSON.
    expect(JSON.stringify(record)).not.toContain('ikxPrivate');
  });

  it('legacy records (no envelope) are lazily provisioned and persisted', async () => {
    const userId = `dk-legacy-${Date.now()}`;
    await createLocalIdentity(userId, PASS);

    // Simulate a pre-Phase-4 record by removing the device-keys envelope.
    const legacy = await getIdentityRecord(userId);
    expect(legacy).not.toBeNull();
    const record = legacy as IdentityRecord;
    delete record.enc_device_keys;
    await saveIdentityRecord(record);

    const unlocked = await unlockIdentity(userId, PASS);
    expect(unlocked.deviceKeys).not.toBeNull();
    expect(unlocked.deviceKeys!.ikxPrivate.length).toBe(32);

    // Provisioning must have persisted the envelope for future unlocks.
    const after = await getIdentityRecord(userId);
    expect(after!.enc_device_keys).toBeDefined();
    await unlocked.lock();
  });

  it('re-unlocking yields the SAME device keys (stable persistence)', async () => {
    const userId = `dk-stable-${Date.now()}`;
    await createLocalIdentity(userId, PASS);

    const a = await unlockIdentity(userId, PASS);
    const ikxHexA = hex(a.deviceKeys!.ikxPrivate);
    const spkHexA = hex(a.deviceKeys!.spkPrivate);
    const opkHexA = a.deviceKeys!.opkPrivate === null ? null : hex(a.deviceKeys!.opkPrivate);
    a.lock();

    const b = await unlockIdentity(userId, PASS);
    expect(hex(b.deviceKeys!.ikxPrivate)).toBe(ikxHexA);
    expect(hex(b.deviceKeys!.spkPrivate)).toBe(spkHexA);
    expect(b.deviceKeys!.opkPrivate === null ? null : hex(b.deviceKeys!.opkPrivate)).toBe(
      opkHexA,
    );
    b.lock();
  });

  it('lock() wipes the in-memory device-key buffers', async () => {
    const userId = `dk-wipe-${Date.now()}`;
    await createLocalIdentity(userId, PASS);
    const unlocked = await unlockIdentity(userId, PASS);
    const device = unlocked.deviceKeys!;
    expect(hex(device.ikxPrivate)).not.toBe('00'.repeat(32));
    expect(hex(device.spkPrivate)).not.toBe('00'.repeat(32));
    unlocked.lock();
    expect(Array.from(device.ikxPrivate).every((b) => b === 0)).toBe(true);
    expect(Array.from(device.spkPrivate).every((b) => b === 0)).toBe(true);
  });

  it('device keys are decrypted under the SAME passphrase domain', async () => {
    const userId = `dk-wrongpw-${Date.now()}`;
    await createLocalIdentity(userId, PASS);
    await expect(
      unlockIdentity(userId, 'wrong-passphrase'),
    ).rejects.toMatchObject({ code: 'wrong_passphrase' });
  });

  it('cleanup deletes the record', async () => {
    const userId = `dk-cleanup-${Date.now()}`;
    await createLocalIdentity(userId, PASS);
    await deleteLocalIdentity(userId);
    expect(await getIdentityRecord(userId)).toBeNull();
  });
});

function hex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) {
    out += (bytes[i] ?? 0).toString(16).padStart(2, '0');
  }
  return out;
}
import { describe, expect, it } from 'vitest';
import {
  DEVICE_KEYS_AD_CONTEXT,
  buildDevicePublicBundle,
  decryptDeviceKeys,
  deserializeDeviceKeys,
  deviceKeysAssociatedData,
  devicePublicBundleToHex,
  encryptDeviceKeys,
  generateDeviceKeys,
  serializeDeviceKeys,
  signSignedPrekey,
  verifySignedPrekey,
  type DeviceKeysPrivate,
} from '../src/crypto/deviceKeys';
import { deriveAesKey, randomSalt } from '../src/crypto/kdf';
import { bytesToHex, hexToBytes } from '../src/crypto/hex';
import { signRaw } from '../src/crypto/ed25519';

function fromHex(hex: string): Uint8Array {
  return hexToBytes(hex);
}

/** Deterministic 32-byte block repeating a 0x01 step (matches backend vector script). */
function block32(start: number): Uint8Array {
  return fromHex(block32Hex(start));
}

function block32Hex(start: number): string {
  let out = '';
  for (let i = start; i < start + 32; i += 1) {
    out += (i % 256).toString(16).padStart(2, '0');
  }
  return out;
}

// Fixed inputs used to generate the reference vectors with the backend
// protocol package (protocol/keys.py + protocol/x3dh.py).
const IKX_B_PRIV = block32(33); // 21..40
const SPK_B_PRIV = block32(65); // 41..60
const OPK_B_PRIV = block32(97); // 61..80
const AUTH_SEED_B = block32(232); // e8..07 (mod 256)

const expected = {
  ikxBPublic: '5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b',
  spkBPublic: '64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466',
  opkBPublic: '244fe3b963e899dd295baffce248d3530f3a9a7479ba063002680ebfe7adad49',
  spkSignature:
    'fe80d335e8cb953ca979482407af28188a4734b5bf88e1064fd9f3ad7f0f3c7015ac0ca6ae442aecb4ba646ccb5d79725312b4790ecca9492f8e457ee407d402',
};

function fixedDevice(): DeviceKeysPrivate {
  return {
    ikxPrivate: block32(33),
    spkPrivate: block32(65),
    opkPrivate: block32(97),
  };
}

describe('device key generation', () => {
  it('generates a single OPK by default (backend stores one at a time)', () => {
    const device = generateDeviceKeys();
    expect(device.ikxPrivate.length).toBe(32);
    expect(device.spkPrivate.length).toBe(32);
    expect(device.opkPrivate).not.toBeNull();
    expect(device.opkPrivate?.length).toBe(32);
  });

  it('supports opkCount 0', () => {
    const device = generateDeviceKeys(0);
    expect(device.opkPrivate).toBeNull();
  });

  it('rejects negative opk counts', () => {
    expect(() => generateDeviceKeys(-1)).toThrow();
  });
});

describe('bundle construction matches backend reference vectors', () => {
  const bundle = buildDevicePublicBundle(AUTH_SEED_B, fixedDevice());

  it('matches the pinned X25519 publics', () => {
    expect(bytesToHex(bundle.xdhPublic)).toBe(expected.ikxBPublic);
    expect(bytesToHex(bundle.spkPublic)).toBe(expected.spkBPublic);
    expect(bytesToHex(bundle.opkPublics[0] ?? new Uint8Array())).toBe(
      expected.opkBPublic,
    );
  });

  it('pins the exact SPK signature (SPK_SIGN_CONTEXT || spk_public)', () => {
    expect(bytesToHex(bundle.spkSignature)).toBe(expected.spkSignature);
  });

  it('uses a 32-byte Ed25519 auth identity in the bundle', () => {
    expect(bundle.ikPublic.length).toBe(32);
    expect(verifySignedPrekey(bundle.ikPublic, bundle.spkPublic, bundle.spkSignature)).toBe(
      true,
    );
  });

  it('exposes only PUBLIC material in hex form', () => {
    const hex = devicePublicBundleToHex(bundle);
    expect(hex.ik_public).toMatch(/^[0-9a-f]{64}$/);
    expect(hex.xdh_public).toMatch(/^[0-9a-f]{64}$/);
    expect(hex.spk_public).toMatch(/^[0-9a-f]{64}$/);
    expect(hex.spk_signature).toMatch(/^[0-9a-f]{128}$/);
    expect(Array.isArray(hex.opk_publics)).toBe(true);
    expect((hex.opk_publics as string[])[0]).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('SPK signature verification', () => {
  const device = fixedDevice();
  const bundle = buildDevicePublicBundle(AUTH_SEED_B, device);

  it('accepts the genuine signature', () => {
    expect(verifySignedPrekey(bundle.ikPublic, bundle.spkPublic, bundle.spkSignature)).toBe(
      true,
    );
  });

  it('rejects a tampered SPK public key', () => {
    const tampered = new Uint8Array(bundle.spkPublic);
    tampered[0] = (tampered[0] ?? 0) ^ 0xff;
    expect(verifySignedPrekey(bundle.ikPublic, tampered, bundle.spkSignature)).toBe(
      false,
    );
  });

  it('rejects a tampered signature', () => {
    const bad = new Uint8Array(bundle.spkSignature);
    bad[0] = (bad[0] ?? 0) ^ 0xff;
    expect(verifySignedPrekey(bundle.ikPublic, bundle.spkPublic, bad)).toBe(false);
  });

  it('rejects a signature made under a different identity', () => {
    const otherSeed = block32(10);
    const otherSignature = signSignedPrekey(otherSeed, bundle.spkPublic);
    // ikPublic of the OTHER seed does not verify a sig by OUR seed, and the
    // bundle's ikPublic must reject the other-signature too:
    expect(verifySignedPrekey(bundle.ikPublic, bundle.spkPublic, otherSignature)).toBe(
      false,
    );
  });

  it('rejects a signature over a different context string', () => {
    const forged = signRawForContext('other-context', bundle.spkPublic, AUTH_SEED_B);
    expect(verifySignedPrekey(bundle.ikPublic, bundle.spkPublic, forged)).toBe(false);
  });

  it('rejects malformed lengths', () => {
    expect(verifySignedPrekey(new Uint8Array(31), bundle.spkPublic, bundle.spkSignature)).toBe(
      false,
    );
    expect(verifySignedPrekey(bundle.ikPublic, new Uint8Array(31), bundle.spkSignature)).toBe(
      false,
    );
    expect(verifySignedPrekey(bundle.ikPublic, bundle.spkPublic, new Uint8Array(63))).toBe(
      false,
    );
  });
});

describe('device-key serialization', () => {
  it('round-trips with an OPK', () => {
    const device: DeviceKeysPrivate = {
      ikxPrivate: block32(1),
      spkPrivate: block32(33),
      opkPrivate: block32(97),
    };
    const restored = deserializeDeviceKeys(serializeDeviceKeys(device));
    expect(restored.ikxPrivate).toEqual(device.ikxPrivate);
    expect(restored.spkPrivate).toEqual(device.spkPrivate);
    expect(restored.opkPrivate).toEqual(device.opkPrivate);
  });

  it('round-trips without an OPK (flag 0)', () => {
    const device = { ikxPrivate: block32(1), spkPrivate: block32(33), opkPrivate: null };
    const restored = deserializeDeviceKeys(serializeDeviceKeys(device));
    expect(restored.opkPrivate).toBeNull();
  });

  it('rejects malformed payloads', () => {
    expect(() => deserializeDeviceKeys(new Uint8Array(4))).toThrow();
    expect(() => deserializeDeviceKeys(new Uint8Array([99, 1, 2]))).toThrow();
  });
});

describe('encrypted device-key persistence', () => {
  async function deriveKey(): Promise<CryptoKey> {
    const { subtleKey } = await deriveAesKey('test-passphrase', randomSalt(), 1000);
    return subtleKey;
  }

  it('encrypts and decrypts with user binding', async () => {
    const key = await deriveKey();
    const device = fixedDevice();
    const ad = deviceKeysAssociatedData('alice');
    const blob = await encryptDeviceKeys(key, device, ad);
    expect(blob.ciphertextHex.length).toBeGreaterThan(0);
    expect(blob.ivHex.length).toBe(24);

    const restored = await decryptDeviceKeys(key, blob, ad);
    expect(restored.ikxPrivate).toEqual(device.ikxPrivate);
    expect(restored.spkPrivate).toEqual(device.spkPrivate);
    expect(restored.opkPrivate).toEqual(device.opkPrivate);
  });

  it('binds ciphertext to the user_id (wrong AD fails)', async () => {
    const key = await deriveKey();
    const device = fixedDevice();
    const blob = await encryptDeviceKeys(key, device, deviceKeysAssociatedData('alice'));
    await expect(
      decryptDeviceKeys(key, blob, deviceKeysAssociatedData('bob')),
    ).rejects.toThrow();
  });

  it('produces fresh ciphertext on each write (random IV)', async () => {
    const key = await deriveKey();
    const device = fixedDevice();
    const ad = deviceKeysAssociatedData('alice');
    const a = await encryptDeviceKeys(key, device, ad);
    const b = await encryptDeviceKeys(key, device, ad);
    expect(a.ivHex).not.toBe(b.ivHex);
  });
});

describe('device keys AD context', () => {
  it('is domain-separated from the identity envelope', () => {
    expect(DEVICE_KEYS_AD_CONTEXT).toBe('secure-messaging-device-keys-v1');
    expect(deviceKeysAssociatedData('alice')).not.toEqual(
      deviceKeysAssociatedData('bob'),
    );
  });

  it('never embeds private scalars', () => {
    const bundle = buildDevicePublicBundle(AUTH_SEED_B, fixedDevice());
    const hex = devicePublicBundleToHex(bundle);
    const joined = JSON.stringify(hex);
    expect(joined).not.toContain(bytesToHex(SPK_B_PRIV));
    expect(joined).not.toContain(bytesToHex(AUTH_SEED_B));
  });
});

function signRawForContext(
  context: string,
  spkPublic: Uint8Array,
  seed: Uint8Array,
): Uint8Array {
  const ctx = new TextEncoder().encode(context);
  const message = new Uint8Array(ctx.length + spkPublic.length);
  message.set(ctx, 0);
  message.set(spkPublic, ctx.length);
  return signRaw(message, seed);
}
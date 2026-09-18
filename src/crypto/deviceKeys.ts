/**
 * Device key material for X3DH (Phase 4).
 *
 * A device carries two cryptographic identity domains (backend
 * `protocol/keys.py`):
 *
 *   1. Ed25519 *auth identity* (`ik_public`, registered with the backend) —
 *      signs the SPK binding; NOT used for X25519 math.
 *   2. X25519 *X3DH identity* (`IKX` = `xdh_public`) — used in DH terms.
 *
 * Plus X25519 prekeys:
 *   - `SPK` (signed prekey): the auth identity signs `SPK_SIGN_CONTEXT || spk_public`
 *     so peers can prove the SPK belongs to the claimed identity.
 *   - `OPK` (one-time prekey): single-use; the backend stores/consumes one at a
 *     time, so we generate/replenish one OPK at a time here.
 *
 * Private X25519 scalars NEVER leave the device except as ciphertext inside the
 * encrypted identity record (see `identityStore`/`identity`). This module only
 * builds and encodes the PUBLIC half for upload.
 *
 * SPK signature binding (must match `protocol/keys.py` EXACTLY):
 *
 *     SPK_SIGN_CONTEXT = b"secure-messaging-signed-prekey-v1"
 *     signature = Ed25519.sign(SPK_SIGN_CONTEXT + spk_public_32bytes, auth_seed)
 */

import {
  ED25519_PRIVATE_SEED_BYTES,
  publicKeyFromPrivateSeed,
  signRaw,
  signatureToHex,
  verifyRaw,
  publicKeyToHex,
} from './ed25519';
import {
  X25519_KEY_BYTES,
  generateX25519Keypair,
  x25519PublicFromPrivate,
  x25519PublicToHex,
} from './x25519';
import { encrypt, decrypt, type EncryptedBlob } from './aead';

export const SPK_SIGN_CONTEXT = 'secure-messaging-signed-prekey-v1';
export const SPK_SIGN_CONTEXT_BYTES = new TextEncoder().encode(SPK_SIGN_CONTEXT);

/** AEAD associated-data context for the device-keys encryption envelope. */
export const DEVICE_KEYS_AD_CONTEXT = 'secure-messaging-device-keys-v1';

/** Binary layout version inside the encrypted device-keys payload. */
export const DEVICE_KEYS_PAYLOAD_VERSION = 1;

/** How many OPKs a freshly provisioned device generates (spec default). */
export const INITIAL_OPK_COUNT = 1;

/**
 * Private device key material. Each field is the raw 32-byte scalar.
 * `opkPrivate` is exactly the single one-time prekey currently held (the
 * backend stores at most one OPK at a time).
 */
export interface DeviceKeysPrivate {
  /** X25519 X3DH identity private (IKX). */
  ikxPrivate: Uint8Array;
  /** X25519 signed-prekey private (SPK). */
  spkPrivate: Uint8Array;
  /** X25519 one-time prekey private (OPK), or null when none is held. */
  opkPrivate: Uint8Array | null;
}

/**
 * Public key bundle (mirrors `protocol.keys.KeyBundle`). All fields are raw
 * 32-byte keys; `spkSignature` is the 64-byte Ed25519 binding.
 */
export interface DevicePublicBundle {
  ikPublic: Uint8Array; // Ed25519 auth identity (32 bytes)
  xdhPublic: Uint8Array; // X25519 X3DH identity IKX (32 bytes)
  spkPublic: Uint8Array; // X25519 signed prekey (32 bytes)
  spkSignature: Uint8Array; // Ed25519(SPK_SIGN_CONTEXT || spk_public) (64 bytes)
  opkPublics: Uint8Array[]; // one or more X25519 OPKs
}

export function generateDeviceKeys(opkCount: number = INITIAL_OPK_COUNT): DeviceKeysPrivate {
  if (opkCount < 0) {
    throw new Error('opkCount must be >= 0');
  }
  // Only the FIRST generated OPK is retained (backend stores one at a time).
  const ikx = generateX25519Keypair();
  const spk = generateX25519Keypair();
  let opk: Uint8Array | null = null;
  if (opkCount > 0) {
    opk = generateX25519Keypair().privateKey;
  }
  return {
    ikxPrivate: ikx.privateKey,
    spkPrivate: spk.privateKey,
    opkPrivate: opk,
  };
}

/**
 * Sign the signed prekey binding exactly as the backend does:
 * `Ed25519.sign(SPK_SIGN_CONTEXT || spk_public_32bytes, auth_seed)`.
 */
export function signSignedPrekey(
  authSeed: Uint8Array,
  spkPublicRaw: Uint8Array,
): Uint8Array {
  if (authSeed.length !== ED25519_PRIVATE_SEED_BYTES) {
    throw new Error(
      `Ed25519 seed must be ${ED25519_PRIVATE_SEED_BYTES} bytes; got ${authSeed.length}.`,
    );
  }
  if (spkPublicRaw.length !== X25519_KEY_BYTES) {
    throw new Error(`SPK public key must be ${X25519_KEY_BYTES} bytes.`);
  }
  const message = new Uint8Array(SPK_SIGN_CONTEXT_BYTES.length + spkPublicRaw.length);
  message.set(SPK_SIGN_CONTEXT_BYTES, 0);
  message.set(spkPublicRaw, SPK_SIGN_CONTEXT_BYTES.length);
  return signRaw(message, authSeed);
}

/** Verify an SPK binding against the peer's Ed25519 auth identity. */
export function verifySignedPrekey(
  ikPublic: Uint8Array,
  spkPublic: Uint8Array,
  spkSignature: Uint8Array,
): boolean {
  if (
    ikPublic.length !== 32 ||
    spkPublic.length !== X25519_KEY_BYTES ||
    spkSignature.length !== 64
  ) {
    return false;
  }
  const message = new Uint8Array(SPK_SIGN_CONTEXT_BYTES.length + spkPublic.length);
  message.set(SPK_SIGN_CONTEXT_BYTES, 0);
  message.set(spkPublic, SPK_SIGN_CONTEXT_BYTES.length);
  return verifyRaw(spkSignature, message, ikPublic);
}

/** Derive the device's public bundle from its private material + auth seed. */
export function buildDevicePublicBundle(
  authSeed: Uint8Array,
  device: DeviceKeysPrivate,
): DevicePublicBundle {
  const ikPublic = publicKeyFromPrivateSeed(authSeed);
  const spkPrivate = device.spkPrivate;
  const spkPublic = x25519PublicFromPrivate(spkPrivate);
  return {
    ikPublic,
    xdhPublic: x25519PublicFromPrivate(device.ikxPrivate),
    spkPublic,
    spkSignature: signSignedPrekey(authSeed, spkPublic),
    opkPublics:
      device.opkPrivate === null
        ? []
        : [x25519PublicFromPrivate(device.opkPrivate)],
  };
}

/** Wire-format ASCII view of the public bundle (64-hex fields). */
export function devicePublicBundleToHex(
  bundle: DevicePublicBundle,
): Record<string, string | string[]> {
  return {
    ik_public: publicKeyToHex(bundle.ikPublic),
    xdh_public: x25519PublicToHex(bundle.xdhPublic),
    spk_public: x25519PublicToHex(bundle.spkPublic),
    spk_signature: signatureToHex(bundle.spkSignature),
    opk_publics: bundle.opkPublics.map((k) => x25519PublicToHex(k)),
  };
}

// ---------------------------------------------------------------------------
// Encrypted persistence envelope
// ---------------------------------------------------------------------------

/**
 * Serialize the private device keys into a versioned binary payload:
 *
 *     byte 0        payload version (1)
 *     bytes 1..32   ikx private
 *     bytes 33..64  spk private
 *     byte 65       0x00 = no OPK, 0x01 = OPK present
 *     bytes 66..97  opk private (only when flag == 0x01)
 *
 * Only ciphertext of this payload is ever stored.
 */
export function serializeDeviceKeys(device: DeviceKeysPrivate): Uint8Array {
  const hasOpk = device.opkPrivate !== null;
  const out = new Uint8Array(1 + 2 * X25519_KEY_BYTES + 1 + (hasOpk ? X25519_KEY_BYTES : 0));
  out[0] = DEVICE_KEYS_PAYLOAD_VERSION;
  out.set(device.ikxPrivate, 1);
  out.set(device.spkPrivate, 1 + X25519_KEY_BYTES);
  out[1 + 2 * X25519_KEY_BYTES] = hasOpk ? 1 : 0;
  if (hasOpk && device.opkPrivate !== null) {
    out.set(device.opkPrivate, 1 + 2 * X25519_KEY_BYTES + 1);
  }
  return out;
}

export function deserializeDeviceKeys(raw: Uint8Array): DeviceKeysPrivate {
  if (raw.length < 1 + 2 * X25519_KEY_BYTES + 1) {
    throw new Error('malformed device-keys payload');
  }
  const version = raw[0];
  if (version !== DEVICE_KEYS_PAYLOAD_VERSION) {
    throw new Error(
      `unsupported device-keys payload version ${version}; expected ${DEVICE_KEYS_PAYLOAD_VERSION}`,
    );
  }
  const ikx = raw.slice(1, 1 + X25519_KEY_BYTES);
  const spk = raw.slice(1 + X25519_KEY_BYTES, 1 + 2 * X25519_KEY_BYTES);
  const flag = raw[1 + 2 * X25519_KEY_BYTES] ?? 0;
  let opk: Uint8Array | null = null;
  if (flag === 1) {
    const start = 1 + 2 * X25519_KEY_BYTES + 1;
    if (raw.length < start + X25519_KEY_BYTES) {
      throw new Error('malformed device-keys OPK payload');
    }
    opk = raw.slice(start, start + X25519_KEY_BYTES);
  } else if (flag !== 0) {
    throw new Error(`malformed device-keys OPK flag ${flag}`);
  }
  return { ikxPrivate: new Uint8Array(ikx), spkPrivate: new Uint8Array(spk), opkPrivate: opk };
}

/**
 * Associated data binding for the device-keys envelope:
 * `"secure-messaging-device-keys-v1" || 0x1F || user_id`. The keyed user_id
 * prevents an encrypted envelope from being replayed against another account.
 */
export function deviceKeysAssociatedData(userId: string): Uint8Array {
  const enc = new TextEncoder();
  const ctx = enc.encode(DEVICE_KEYS_AD_CONTEXT);
  const uid = enc.encode(userId);
  const out = new Uint8Array(ctx.length + 1 + uid.length);
  out.set(ctx, 0);
  out.set([0x1f], ctx.length);
  out.set(uid, ctx.length + 1);
  return out;
}

export async function encryptDeviceKeys(
  subtleKey: CryptoKey,
  device: DeviceKeysPrivate,
  ad: Uint8Array,
): Promise<EncryptedBlob> {
  return encrypt(subtleKey, serializeDeviceKeys(device), ad);
}

export async function decryptDeviceKeys(
  subtleKey: CryptoKey,
  blob: EncryptedBlob,
  ad: Uint8Array,
): Promise<DeviceKeysPrivate> {
  const raw = await decrypt(subtleKey, blob, ad);
  return deserializeDeviceKeys(raw);
}
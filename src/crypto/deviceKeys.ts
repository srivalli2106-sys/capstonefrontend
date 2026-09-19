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
import {
  generateMlKem768Keypair,
  generateMlDsa44Keypair,
  mlDsa44Sign,
  mlDsa44Verify,
  mlKem768DerivePublicKey,
  mlDsa44DerivePublicKey,
  ML_KEM_768_PRIVATE_KEY_BYTES,
  ML_DSA_44_PRIVATE_KEY_BYTES,
} from './pq';
import { encrypt, decrypt, type EncryptedBlob } from './aead';

export const SPK_SIGN_CONTEXT = 'secure-messaging-signed-prekey-v1';
export const SPK_SIGN_CONTEXT_BYTES = new TextEncoder().encode(SPK_SIGN_CONTEXT);

/** AEAD associated-data context for the device-keys encryption envelope. */
export const DEVICE_KEYS_AD_CONTEXT = 'secure-messaging-device-keys-v1';

/** Binary layout version inside the encrypted device-keys payload.
 *
 *  Version 1: classical only (ikx + spk + optional OPK).
 *  Version 2: classical + ML-KEM-768 + ML-DSA-44 (hybrid v2 capable).
 */
export const DEVICE_KEYS_PAYLOAD_VERSION = 2;

/** How many OPKs a freshly provisioned device generates (spec default). */
export const INITIAL_OPK_COUNT = 1;

/**
 * Private device key material. Each field is the raw 32-byte scalar.
 * `opkPrivate` is exactly the single one-time prekey currently held (the
 * backend stores at most one OPK at a time).
 *
 * PQ private keys (`pqKemPrivate`, `pqSigPrivate`) are opaque to the rest
 * of the codebase; their byte length is dictated by the underlying
 * `@noble/post-quantum` library (2400 and 2560 bytes respectively). They
 * are NEVER sent to the backend. They live only inside the encrypted
 * device-keys envelope.
 */
export interface DeviceKeysPrivate {
  /** X25519 X3DH identity private (IKX). */
  ikxPrivate: Uint8Array;
  /** X25519 signed-prekey private (SPK). */
  spkPrivate: Uint8Array;
  /** X25519 one-time prekey private (OPK), or null when none is held. */
  opkPrivate: Uint8Array | null;
  /** ML-KEM-768 private key (opaque), undefined/null if hybrid mode is disabled. */
  pqKemPrivate?: Uint8Array | null;
  /** ML-DSA-44 private key (opaque), undefined/null if hybrid mode is disabled. */
  pqSigPrivate?: Uint8Array | null;
}

/**
 * Public key bundle (mirrors `protocol.keys.KeyBundle`). All fields are raw
 * 32-byte keys; `spkSignature` is the 64-byte Ed25519 binding.
 *
 * PQ fields (`pqKemPublic`, `pqSigPublic`, `pqBindingSig`) are populated
 * only when the device has generated PQ keys (hybrid mode). The classical
 * fields are identical to v1 so every existing classical client stays
 * byte-compatible.
 */
export interface DevicePublicBundle {
  ikPublic: Uint8Array; // Ed25519 auth identity (32 bytes)
  xdhPublic: Uint8Array; // X25519 X3DH identity IKX (32 bytes)
  spkPublic: Uint8Array; // X25519 signed prekey (32 bytes)
  spkSignature: Uint8Array; // Ed25519(SPK_SIGN_CONTEXT || spk_public) (64 bytes)
  opkPublics: Uint8Array[]; // one or more X25519 OPKs
  /** ML-KEM-768 public key, or null if hybrid mode is off. */
  pqKemPublic: Uint8Array | null;
  /** ML-DSA-44 public key, or null if hybrid mode is off. */
  pqSigPublic: Uint8Array | null;
  /** ML-DSA-44 signature over the hybrid binding context, or null. */
  pqBindingSig: Uint8Array | null;
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
  // Hybrid v2 is opt-in: callers that want PQ support must call
  // generateHybridDeviceKeys below. The default keeps every existing
  // classical test byte-identical.
  return {
    ikxPrivate: ikx.privateKey,
    spkPrivate: spk.privateKey,
    opkPrivate: opk,
    pqKemPrivate: null,
    pqSigPrivate: null,
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

/**
 * Domain-separated context for the ML-DSA binding signature on the
 * hybrid key bundle. The signature signs exactly:
 *
 *     HYBRID_BIND_CONTEXT
 *     || ik_public
 *     || xdh_public
 *     || spk_public
 *     || protocol_version ("v2")
 *     || pq_kem_public
 *     || pq_sig_public
 *
 * The Ed25519 SPK signature continues to authenticate the classical
 * material; the ML-DSA signature provides PQ-level authentication of the
 * whole bundle, signed by the device's long-term ML-DSA key. The
 * initiating peer verifies BOTH signatures before completing the
 * handshake.
 */
export const HYBRID_BIND_CONTEXT = 'secure-messaging-hybrid-binding-v1';
export const HYBRID_BIND_CONTEXT_BYTES = new TextEncoder().encode(HYBRID_BIND_CONTEXT);
export const HYBRID_PROTOCOL_VERSION_TAG = 'v2';

/**
 * Generate the device's PQ keys and attach them to the existing
 * classical keys. Pure JS via `@noble/post-quantum`; private keys are
 * opaque byte strings kept on-device only.
 */
export async function generateHybridDeviceKeys(
  base?: DeviceKeysPrivate,
): Promise<DeviceKeysPrivate> {
  const classical = base ?? generateDeviceKeys(0);
  const kem = generateMlKem768Keypair();
  const sig = generateMlDsa44Keypair();
  return {
    ikxPrivate: classical.ikxPrivate,
    spkPrivate: classical.spkPrivate,
    opkPrivate: classical.opkPrivate,
    pqKemPrivate: kem.privateKey,
    pqSigPrivate: sig.privateKey,
  };
}

/**
 * Build the canonical hybrid binding context (used both for signing on
 * the originating device and for verification on the peer's device).
 */
export function buildHybridBindingContext(
  ikPublic: Uint8Array,
  xdhPublic: Uint8Array,
  spkPublic: Uint8Array,
  pqKemPublic: Uint8Array,
  pqSigPublic: Uint8Array,
): Uint8Array {
  const parts = [
    HYBRID_BIND_CONTEXT_BYTES,
    ikPublic,
    xdhPublic,
    spkPublic,
    new TextEncoder().encode(HYBRID_PROTOCOL_VERSION_TAG),
    pqKemPublic,
    pqSigPublic,
  ];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/**
 * Verify the ML-DSA binding signature on a remote hybrid key bundle.
 * Returns ``false`` for tampered / wrong-context signatures; never throws.
 */
export function verifyHybridBindingSignature(
  signature: Uint8Array,
  ikPublic: Uint8Array,
  xdhPublic: Uint8Array,
  spkPublic: Uint8Array,
  pqKemPublic: Uint8Array,
  pqSigPublic: Uint8Array,
): boolean {
  const ctx = buildHybridBindingContext(
    ikPublic,
    xdhPublic,
    spkPublic,
    pqKemPublic,
    pqSigPublic,
  );
  return mlDsa44Verify(signature, ctx, pqSigPublic);
}

/** Derive the device's public bundle from its private material + auth seed. */
export async function buildDevicePublicBundle(
  authSeed: Uint8Array,
  device: DeviceKeysPrivate,
): Promise<DevicePublicBundle> {
  const ikPublic = publicKeyFromPrivateSeed(authSeed);
  const spkPublic = x25519PublicFromPrivate(device.spkPrivate);

  let pqKemPublic: Uint8Array | null = null;
  let pqSigPublic: Uint8Array | null = null;
  let pqBindingSig: Uint8Array | null = null;
  if (device.pqKemPrivate && device.pqSigPrivate) {
    // ML-KEM public key is the publicKey from the keypair. The keygen
    // The ML-KEM and ML-DSA public keys are recovered from the device's
    // actual private keys (which were generated on this device and have
    // never left it). Re-keying here would invalidate the ML-DSA binding
    // signature we are about to emit.
    pqKemPublic = mlKem768DerivePublicKey(device.pqKemPrivate);
    pqSigPublic = mlDsa44DerivePublicKey(device.pqSigPrivate);
    const ctx = buildHybridBindingContext(
      ikPublic,
      x25519PublicFromPrivate(device.ikxPrivate),
      spkPublic,
      pqKemPublic,
      pqSigPublic,
    );
    pqBindingSig = mlDsa44Sign(ctx, device.pqSigPrivate);
  }

  return {
    ikPublic,
    xdhPublic: x25519PublicFromPrivate(device.ikxPrivate),
    spkPublic,
    spkSignature: signSignedPrekey(authSeed, spkPublic),
    opkPublics:
      device.opkPrivate === null
        ? []
        : [x25519PublicFromPrivate(device.opkPrivate)],
    pqKemPublic,
    pqSigPublic,
    pqBindingSig,
  };
}

/** Wire-format ASCII view of the public bundle (64-hex fields). */
export function devicePublicBundleToHex(
  bundle: DevicePublicBundle,
): Record<string, string | string[] | null | number> {
  return {
    ik_public: publicKeyToHex(bundle.ikPublic),
    xdh_public: x25519PublicToHex(bundle.xdhPublic),
    spk_public: x25519PublicToHex(bundle.spkPublic),
    spk_signature: signatureToHex(bundle.spkSignature),
    opk_publics: bundle.opkPublics.map((k) => x25519PublicToHex(k)),
    pq_kem_public:
      bundle.pqKemPublic === null
        ? null
        : bytesToHex(bundle.pqKemPublic),
    pq_sig_public:
      bundle.pqSigPublic === null
        ? null
        : bytesToHex(bundle.pqSigPublic),
    pq_binding_sig:
      bundle.pqBindingSig === null
        ? null
        : bytesToHex(bundle.pqBindingSig),
    protocol_version: bundle.pqKemPublic ? 2 : 1,
  };
}

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) {
    out += (bytes[i] ?? 0).toString(16).padStart(2, '0');
  }
  return out;
}

// ---------------------------------------------------------------------------
// Encrypted persistence envelope
// ---------------------------------------------------------------------------

/**
 * Serialize the private device keys into a versioned binary payload:
 *
 *     byte 0        payload version (2)
 *     bytes 1..32   ikx private
 *     bytes 33..64  spk private
 *     byte 65       opk flag (0 = none, 1 = present)
 *     bytes 66..97  opk private (only when flag == 1)
 *     byte 98       pq flag (0 = none, 1 = present)
 *     bytes 99..    pq_kem_private (2400 bytes) followed by pq_sig_private
 *                   (2560 bytes) when pq flag == 1
 *
 * Only ciphertext of this payload is ever stored.
 */
export function serializeDeviceKeys(device: DeviceKeysPrivate): Uint8Array {
  const hasOpk = device.opkPrivate !== null && device.opkPrivate !== undefined;
  const hasPq =
    device.pqKemPrivate !== null &&
    device.pqKemPrivate !== undefined &&
    device.pqSigPrivate !== null &&
    device.pqSigPrivate !== undefined;
  const classicalPartLen =
    1 + 2 * X25519_KEY_BYTES + 1 + (hasOpk ? X25519_KEY_BYTES : 0);
  const pqPartLen = hasPq ? 1 + ML_KEM_768_PRIVATE_KEY_BYTES + ML_DSA_44_PRIVATE_KEY_BYTES : 0;
  const out = new Uint8Array(classicalPartLen + pqPartLen);
  out[0] = DEVICE_KEYS_PAYLOAD_VERSION;
  out.set(device.ikxPrivate, 1);
  out.set(device.spkPrivate, 1 + X25519_KEY_BYTES);
  out[1 + 2 * X25519_KEY_BYTES] = hasOpk ? 1 : 0;
  if (hasOpk && device.opkPrivate !== null) {
    out.set(device.opkPrivate, 1 + 2 * X25519_KEY_BYTES + 1);
  }
  if (hasPq && device.pqKemPrivate && device.pqSigPrivate) {
    let offset = classicalPartLen;
    out[offset] = 1;
    offset += 1;
    out.set(device.pqKemPrivate, offset);
    offset += ML_KEM_768_PRIVATE_KEY_BYTES;
    out.set(device.pqSigPrivate, offset);
  }
  return out;
}

export function deserializeDeviceKeys(raw: Uint8Array): DeviceKeysPrivate {
  const minClassical = 1 + 2 * X25519_KEY_BYTES + 1;
  if (raw.length < minClassical) {
    throw new Error('malformed device-keys payload');
  }
  const version = raw[0];
  // Backward-compatibility: accept both the pre-hybrid v1 layout
  // (classical-only) and the current v2 layout (classical + PQ).
  // v1 payloads have no PQ section; pqKem/pqSig are returned as null.
  if (version !== 1 && version !== DEVICE_KEYS_PAYLOAD_VERSION) {
    throw new Error(
      `unsupported device-keys payload version ${version}; expected 1 or ${DEVICE_KEYS_PAYLOAD_VERSION}`,
    );
  }
  const ikx = raw.slice(1, 1 + X25519_KEY_BYTES);
  const spk = raw.slice(1 + X25519_KEY_BYTES, 1 + 2 * X25519_KEY_BYTES);
  const opkFlag = raw[1 + 2 * X25519_KEY_BYTES] ?? 0;
  let opk: Uint8Array | null = null;
  let offset = 1 + 2 * X25519_KEY_BYTES + 1;
  if (opkFlag === 1) {
    if (raw.length < offset + X25519_KEY_BYTES) {
      throw new Error('malformed device-keys OPK payload');
    }
    opk = raw.slice(offset, offset + X25519_KEY_BYTES);
    offset += X25519_KEY_BYTES;
  } else if (opkFlag !== 0) {
    throw new Error(`malformed device-keys OPK flag ${opkFlag}`);
  }
  let pqKemPrivate: Uint8Array | null = null;
  let pqSigPrivate: Uint8Array | null = null;
  // v2 payloads may carry an optional PQ section after the classical block.
  // v1 payloads never carry a PQ section.
  if (version === DEVICE_KEYS_PAYLOAD_VERSION && raw.length > offset) {
    const pqFlag = raw[offset] ?? 0;
    if (pqFlag !== 1) {
      throw new Error(`malformed device-keys PQ flag ${pqFlag}`);
    }
    offset += 1;
    if (raw.length < offset + ML_KEM_768_PRIVATE_KEY_BYTES + ML_DSA_44_PRIVATE_KEY_BYTES) {
      throw new Error('malformed device-keys PQ payload');
    }
    pqKemPrivate = raw.slice(offset, offset + ML_KEM_768_PRIVATE_KEY_BYTES);
    offset += ML_KEM_768_PRIVATE_KEY_BYTES;
    pqSigPrivate = raw.slice(offset, offset + ML_DSA_44_PRIVATE_KEY_BYTES);
    offset += ML_DSA_44_PRIVATE_KEY_BYTES;
  }
  return {
    ikxPrivate: new Uint8Array(ikx),
    spkPrivate: new Uint8Array(spk),
    opkPrivate: opk,
    pqKemPrivate,
    pqSigPrivate,
  };
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
/**
 * Identity abstraction.
 *
 * Lifecycle:
 *   1. `registerNew(userId, passphrase)` — generate a fresh Ed25519 keypair
 *      locally, persist the encrypted seed in IndexedDB, and return the
 *      public key hex (caller registers it with the backend).
 *   2. `unlock(userId, passphrase)` — fetch the record, derive the AES key
 *      from the passphrase + salt, decrypt the seed, return an
 *      `UnlockedIdentity` that can sign PoP nonces.
 *   3. `lock()` — wipe the in-memory seed.
 *   4. `deleteLocal(userId)` — remove the encrypted record.
 *
 * The private seed NEVER leaves the JS heap except as ciphertext inside an
 * IndexedDB record.
 */

import {
  ED25519_PRIVATE_SEED_BYTES,
  generateEd25519Keypair,
  publicKeyFromHex,
  publicKeyShortId,
  publicKeyToHex,
  signRaw,
} from './ed25519';
import { decrypt, encrypt } from './aead';
import {
  PBKDF2_ITERATIONS,
  deriveAesKey,
  randomSalt,
} from './kdf';
import {
  IDENTITY_AD_CONTEXT,
  IDENTITY_RECORD_VERSION,
  deleteIdentityRecord,
  getIdentityRecord,
  isIndexedDbAvailable,
  saveIdentityRecord,
  type IdentityRecord,
} from './identityStore';

export class IdentityError extends Error {
  public readonly code:
    | 'no_record'
    | 'wrong_passphrase'
    | 'corrupted'
    | 'unsupported'
    | 'unavailable'
    | 'invalid_input';
  constructor(
    code:
      | 'no_record'
      | 'wrong_passphrase'
      | 'corrupted'
      | 'unsupported'
      | 'unavailable'
      | 'invalid_input',
    message: string,
  ) {
    super(message);
    this.name = 'IdentityError';
    this.code = code;
  }
}

export interface PublicIdentity {
  userId: string;
  publicKeyHex: string;
  publicKeyShortId: string;
}

export interface UnlockedIdentity extends PublicIdentity {
  /**
   * Sign the raw bytes of a backend challenge nonce. Caller must supply the
   * RAW 32-byte nonce (i.e. `bytes.fromhex(nonce_hex)`), NOT the hex string.
   */
  signNonceRaw(rawNonce: Uint8Array): Uint8Array;
  /** Return the raw 32-byte Ed25519 seed. Keep it inside the JS heap. */
  exportRawSeed(): Uint8Array;
  /** Drop the seed from memory. Calling any signing method after this fails. */
  lock(): void;
}

/**
 * Constant associated data for the identity encryption. Binds the ciphertext
 * to (user_id, AD context) so a record can't be repurposed.
 */
function buildAssociatedData(userId: string): Uint8Array {
  const enc = new TextEncoder();
  const ctx = enc.encode(IDENTITY_AD_CONTEXT);
  const uid = enc.encode(userId);
  const out = new Uint8Array(ctx.length + 1 + uid.length);
  out.set(ctx, 0);
  out.set([0x1f], ctx.length); // ASCII unit separator between context and id
  out.set(uid, ctx.length + 1);
  return out;
}

/**
 * Validate user_id and passphrase for registration.
 * Throws IdentityError with `invalid_input` for client-side issues.
 */
export function validateRegistrationInput(
  userId: string,
  passphrase: string,
  passphraseConfirm: string,
): void {
  const trimmed = userId.trim();
  if (trimmed.length < 3 || trimmed.length > 64) {
    throw new IdentityError('invalid_input', 'user_id must be 3..64 characters.');
  }
  if (passphrase.length < 8) {
    throw new IdentityError('invalid_input', 'passphrase must be at least 8 characters.');
  }
  if (passphrase !== passphraseConfirm) {
    throw new IdentityError('invalid_input', 'passphrases do not match.');
  }
}

/**
 * Generate a fresh Ed25519 identity, encrypt its seed with the passphrase,
 * persist it. The identity is NOT registered with the backend here — the
 * caller is responsible for the backend `/auth/register` call and for
 * invoking `confirmRegistration` only after that succeeds.
 */
export async function createLocalIdentity(
  userId: string,
  passphrase: string,
): Promise<{ publicKeyHex: string }> {
  if (!isIndexedDbAvailable()) {
    throw new IdentityError(
      'unavailable',
      'IndexedDB is not available; cannot persist identity locally.',
    );
  }
  validateRegistrationInput(userId, passphrase, passphrase);

  const { privateSeed, publicKey } = generateEd25519Keypair();
  const publicKeyHex = publicKeyToHex(publicKey);
  const salt = randomSalt();

  const { subtleKey } = await deriveAesKey(passphrase, salt, PBKDF2_ITERATIONS);
  const ad = buildAssociatedData(userId.trim());
  const blob = await encrypt(subtleKey, privateSeed, ad);

  const record: IdentityRecord = {
    user_id: userId.trim(),
    ik_public: publicKeyHex,
    created_at: Date.now(),
    schema_version: IDENTITY_RECORD_VERSION,
    enc_seed: {
      record_version: IDENTITY_RECORD_VERSION,
      kdf: 'pbkdf2-sha256',
      iterations: PBKDF2_ITERATIONS,
      salt_hex: bytesToHex(salt),
      iv_hex: blob.ivHex,
      ciphertext_hex: blob.ciphertextHex,
    },
  };
  await saveIdentityRecord(record);

  return { publicKeyHex };
}

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) {
    const byte = bytes[i];
    if (byte === undefined) continue;
    out += byte.toString(16).padStart(2, '0');
  }
  return out;
}

/**
 * Load the encrypted record for `userId` and return its public summary.
 * Does NOT decrypt the seed.
 */
export async function inspectIdentity(
  userId: string,
): Promise<PublicIdentity | null> {
  if (!isIndexedDbAvailable()) return null;
  const record = await getIdentityRecord(userId.trim());
  if (record === null) return null;
  return summarizeRecord(record);
}

/**
 * Decrypt the local identity for signing. The passphrase is never stored;
 * the derived AES key lives only in this function's scope and is released
 * when the caller invokes `unlocked.lock()`.
 */
export async function unlockIdentity(
  userId: string,
  passphrase: string,
): Promise<UnlockedIdentity> {
  if (!isIndexedDbAvailable()) {
    throw new IdentityError('unavailable', 'IndexedDB is not available.');
  }
  const record = await getIdentityRecord(userId.trim());
  if (record === null) {
    throw new IdentityError(
      'no_record',
      'No local identity for that user_id. Register first.',
    );
  }
  if (record.schema_version !== IDENTITY_RECORD_VERSION) {
    throw new IdentityError(
      'unsupported',
      `record schema_version ${record.schema_version} is not supported`,
    );
  }

  let seed: Uint8Array;
  try {
    const salt = hexToBytes(record.enc_seed.salt_hex);
    const { subtleKey } = await deriveAesKey(
      passphrase,
      salt,
      record.enc_seed.iterations,
    );
    const ad = buildAssociatedData(record.user_id);
    const blob = {
      ivHex: record.enc_seed.iv_hex,
      ciphertextHex: record.enc_seed.ciphertext_hex,
    };
    seed = await decrypt(subtleKey, blob, ad);
  } catch {
    throw new IdentityError(
      'wrong_passphrase',
      'Incorrect passphrase or corrupted record.',
    );
  }

  if (seed.length !== ED25519_PRIVATE_SEED_BYTES) {
    throw new IdentityError('corrupted', 'Decrypted seed has unexpected length.');
  }

  let locked = false;
  const publicKey = publicKeyFromHex(record.ik_public);
  const publicKeyHex = record.ik_public;
  const publicKeyShortId_ = publicKeyShortId(publicKey);

  const unlocked: UnlockedIdentity = {
    userId: record.user_id,
    publicKeyHex,
    publicKeyShortId: publicKeyShortId_,
    signNonceRaw(rawNonce: Uint8Array): Uint8Array {
      if (locked) {
        throw new IdentityError('invalid_input', 'Identity is locked.');
      }
      return signRaw(rawNonce, seed);
    },
    exportRawSeed(): Uint8Array {
      if (locked) {
        throw new IdentityError('invalid_input', 'Identity is locked.');
      }
      return new Uint8Array(seed);
    },
    lock(): void {
      locked = true;
      // Best-effort overwrite of the seed buffer. JS does not guarantee
      // erasure from the heap, but we still drop references so the GC can
      // reclaim the buffer.
      seed.fill(0);
    },
  };
  return unlocked;
}

/**
 * Delete the encrypted local identity record. Does NOT call the backend.
 * Use after explicit user confirmation.
 */
export async function deleteLocalIdentity(userId: string): Promise<void> {
  if (!isIndexedDbAvailable()) return;
  await deleteIdentityRecord(userId.trim());
}

function summarizeRecord(record: IdentityRecord): PublicIdentity {
  return {
    userId: record.user_id,
    publicKeyHex: record.ik_public,
    publicKeyShortId: publicKeyShortId(publicKeyFromHex(record.ik_public)),
  };
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('hex must have even length');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
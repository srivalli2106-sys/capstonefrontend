/**
 * IndexedDB persistence for encrypted local identities.
 *
 * Schema (v1):
 *
 *   Database: secure-messaging
 *   Store   : identities
 *   KeyPath : user_id
 *
 *   Record fields:
 *     user_id           — primary key; bound to backend account id
 *     ik_public         — 64-hex Ed25519 public key (registered with backend)
 *     created_at        — epoch ms
 *     schema_version    — record format version (currently 1)
 *     enc_seed          — versioned envelope wrapping the encrypted seed
 *       record_version  — 1
 *       kdf             — 'pbkdf2-sha256'
 *       iterations      — PBKDF2 iteration count
 *       salt_hex        — per-record random salt
 *       iv_hex          — per-encryption random IV
 *       ciphertext_hex  — AES-GCM(seed || 16-byte tag), associated data =
 *                         "secure-messaging-identity-v1" || user_id
 *
 * The plaintext Ed25519 seed NEVER touches disk. We persist only the
 * ciphertext, salt, IV, KDF parameters, and the public half of the key.
 *
 * The store keeps ONE record per user_id. Re-registering the same user_id
 * with a different identity is an explicit overwrite performed by the
 * caller (`identityStore.overwrite`) after re-registering with the backend.
 */

import { openDB, type IDBPDatabase } from 'idb';

export const IDENTITY_DB_NAME = 'secure-messaging';
export const IDENTITY_STORE_NAME = 'identities';
export const IDENTITY_DB_VERSION = 1;
export const IDENTITY_RECORD_VERSION = 1;
export const IDENTITY_AD_CONTEXT = 'secure-messaging-identity-v1';

export interface EncryptedSeedEnvelope {
  record_version: number;
  kdf: 'pbkdf2-sha256';
  iterations: number;
  salt_hex: string;
  iv_hex: string;
  ciphertext_hex: string;
}

/**
 * Encrypted cache for the X25519 device key material (Phase 4).
 *
 * This reuses the same passphrase-derived AES key as the seed envelope but a
 * DIFFERENT associated-data context (`secure-messaging-device-keys-v1`), so
 * the two ciphertexts are domain-separated and bound to the owning user_id.
 */
export interface DeviceKeysEnvelope {
  record_version: number;
  kdf: 'pbkdf2-sha256';
  iterations: number;
  salt_hex: string;
  iv_hex: string;
  ciphertext_hex: string;
}

export interface IdentityRecord {
  user_id: string;
  ik_public: string;
  created_at: number;
  schema_version: number;
  enc_seed: EncryptedSeedEnvelope;
  /**
   * Present on records written by this build / after lazy provisioning.
   * Absent on old Phase 3 records — `identity.unlockIdentity` treats a
   * missing envelope as "not yet provisioned" and writes one on first unlock.
   */
  enc_device_keys?: DeviceKeysEnvelope;
}

let dbPromise: Promise<IDBPDatabase> | null = null;

function getDb(): Promise<IDBPDatabase> {
  if (dbPromise === null) {
    dbPromise = openDB(IDENTITY_DB_NAME, IDENTITY_DB_VERSION, {
      upgrade(database) {
        if (!database.objectStoreNames.contains(IDENTITY_STORE_NAME)) {
          database.createObjectStore(IDENTITY_STORE_NAME, {
            keyPath: 'user_id',
          });
        }
      },
      blocked() {
        // Another tab is holding an old version open. Refuse to wait.
        throw new Error('IndexedDB upgrade blocked by another tab');
      },
      terminated() {
        // Reset on abrupt close.
        dbPromise = null;
      },
    });
  }
  return dbPromise;
}

export function isIndexedDbAvailable(): boolean {
  try {
    return (
      typeof globalThis.indexedDB !== 'undefined' &&
      globalThis.indexedDB !== null
    );
  } catch {
    return false;
  }
}

export async function getIdentityRecord(
  userId: string,
): Promise<IdentityRecord | null> {
  if (!isIndexedDbAvailable()) {
    throw new Error('IndexedDB is not available in this environment');
  }
  const db = await getDb();
  const value = await db.get(IDENTITY_STORE_NAME, userId);
  if (value === undefined) return null;
  return value as IdentityRecord;
}

export async function listIdentityUserIds(): Promise<string[]> {
  if (!isIndexedDbAvailable()) {
    throw new Error('IndexedDB is not available in this environment');
  }
  const db = await getDb();
  return (await db.getAllKeys(IDENTITY_STORE_NAME)) as string[];
}

export async function saveIdentityRecord(record: IdentityRecord): Promise<void> {
  if (!isIndexedDbAvailable()) {
    throw new Error('IndexedDB is not available in this environment');
  }
  if (record.schema_version !== IDENTITY_RECORD_VERSION) {
    throw new Error(
      `unsupported record schema_version ${record.schema_version}; this build expects ${IDENTITY_RECORD_VERSION}`,
    );
  }
  const db = await getDb();
  await db.put(IDENTITY_STORE_NAME, record);
}

export async function deleteIdentityRecord(userId: string): Promise<void> {
  if (!isIndexedDbAvailable()) {
    throw new Error('IndexedDB is not available in this environment');
  }
  const db = await getDb();
  await db.delete(IDENTITY_STORE_NAME, userId);
}

/**
 * Attach or replace the encrypted device-keys envelope on a user's record.
 * The rest of the record is preserved verbatim.
 */
export async function setDeviceKeysEnvelope(
  userId: string,
  envelope: DeviceKeysEnvelope,
): Promise<void> {
  if (!isIndexedDbAvailable()) {
    throw new Error('IndexedDB is not available in this environment');
  }
  const db = await getDb();
  const tx = db.transaction(IDENTITY_STORE_NAME, 'readwrite');
  const store = tx.objectStore(IDENTITY_STORE_NAME);
  const record = (await store.get(userId)) as IdentityRecord | undefined;
  if (record === undefined) {
    throw new Error(`no identity record for user ${userId}`);
  }
  record.enc_device_keys = envelope;
  await store.put(record);
  await tx.done;
}

/**
 * Test/dev helper: closes the cached singleton connection (if any) and
 * resets `dbPromise` to null. Lets tests release the underlying IndexedDB
 * database so `indexedDB.deleteDatabase()` can complete instead of being
 * permanently blocked by the open connection. Production behavior is
 * unchanged — `getDb()` reopens lazily on the next call.
 */
export async function _closeForTest(): Promise<void> {
  if (dbPromise !== null) {
    try {
      const db = await dbPromise;
      db.close();
    } finally {
      dbPromise = null;
    }
  }
}

/**
 * Test/dev helper: opens an explicit database. Used to back the IndexedDB
 * polyfill under Vitest with the fake-indexeddb backend. Production callers
 * should NOT use this — the singleton `getDb()` is correct for the browser.
 */
export async function _openForTest(
  databaseName: string,
): Promise<IDBPDatabase> {
  return openDB(databaseName, IDENTITY_DB_VERSION, {
    upgrade(database) {
      if (!database.objectStoreNames.contains(IDENTITY_STORE_NAME)) {
        database.createObjectStore(IDENTITY_STORE_NAME, {
          keyPath: 'user_id',
        });
      }
    },
  });
}
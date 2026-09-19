/**
 * Encrypted local chat-history store (IndexedDB).
 *
 * Conversations are persisted per `selfUserId` as AES-256-GCM ciphertext.
 * The AES key is derived from the unlocked identity's X25519 device key
 * (`ikxPrivate`) via HKDF-SHA256 with a domain-separated label, so:
 *
 *   * History can only be decrypted while the owning identity is locally
 *     unlocked on this device (a locked identity yields no key).
 *   * The ciphertext is bound to the owning account AND the peer via the
 *     AEAD associated data, so a record cannot be replayed against another
 *     account or conversation without the tag failing.
 *
 * Schema (v1):
 *
 *   Database: secure-messaging-chat
 *   Store   : conversations
 *   KeyPath : id            ("<selfUserId>::<peerUserId>")
 *
 *   Record fields:
 *     id              — composite key
 *     selfUserId      — owning account (plaintext scope marker, not message
 *                        content)
 *     peerUserId      — counterpart (needed to address/store; not sensitive
 *                        message content)
 *     updatedAt       — last write, epoch ms
 *     ivHex           — per-encryption 12-byte AES-GCM nonce
 *     ciphertextHex   — AES-GCM(JSON(PersistedConversation)) + 16-byte tag
 *
 * No plaintext message content is ever written to the database.
 *
 * A recreated identity (fresh device keys) produces a different key, so
 * records from the previous identity are left in place but can no longer be
 * decrypted; `load` skips anything whose AEAD tag does not verify.
 */

import { openDB, type IDBPDatabase } from 'idb';
import { encrypt, decrypt } from '../crypto/aead';
import { hkdfSha256 } from '../crypto/hkdf';
import type {
  ChatPersistence,
  PersistedConversation,
} from './types';

export const CHAT_DB_NAME = 'secure-messaging-chat';
export const CHAT_STORE_NAME = 'conversations';
export const CHAT_DB_VERSION = 1;
export const CHAT_PAYLOAD_VERSION = 1;
/** HKDF info + AEAD associated-data domain separator. */
export const CHAT_AD_CONTEXT = 'secure-messaging-chat-history-v1';

export interface ChatHistoryRecord {
  id: string;
  selfUserId: string;
  peerUserId: string;
  updatedAt: number;
  ivHex: string;
  ciphertextHex: string;
}

let dbPromise: Promise<IDBPDatabase> | null = null;

function getDb(): Promise<IDBPDatabase> {
  if (dbPromise === null) {
    dbPromise = openDB(CHAT_DB_NAME, CHAT_DB_VERSION, {
      upgrade(database) {
        if (!database.objectStoreNames.contains(CHAT_STORE_NAME)) {
          database.createObjectStore(CHAT_STORE_NAME, { keyPath: 'id' });
        }
      },
      blocked() {
        throw new Error('IndexedDB upgrade blocked by another tab');
      },
      terminated() {
        dbPromise = null;
      },
    });
  }
  return dbPromise;
}

function isIndexedDbAvailable(): boolean {
  try {
    return (
      typeof globalThis.indexedDB !== 'undefined' &&
      globalThis.indexedDB !== null
    );
  } catch {
    return false;
  }
}

function recordId(selfUserId: string, peerUserId: string): string {
  return `${selfUserId}::${peerUserId}`;
}

function historyAd(selfUserId: string, peerUserId: string): Uint8Array {
  return new TextEncoder().encode(
    `${CHAT_AD_CONTEXT}\u001f${selfUserId}\u001f${peerUserId}`,
  );
}

function isPersistedConversation(value: unknown): value is PersistedConversation {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Partial<PersistedConversation>;
  if (candidate.version !== CHAT_PAYLOAD_VERSION) return false;
  if (typeof candidate.peerUserId !== 'string' || candidate.peerUserId.length === 0) return false;
  if (!Array.isArray(candidate.messages)) return false;
  if (typeof candidate.lastActivityAt !== 'number' || !Number.isFinite(candidate.lastActivityAt)) return false;
  if (typeof candidate.unreadCount !== 'number' || !Number.isFinite(candidate.unreadCount)) return false;
  return true;
}

/** Test/dev helper: closes the cached connection so tests can delete the DB. */
export async function _closeChatHistoryStoreForTest(): Promise<void> {
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
 * Build a `ChatPersistence` backed by IndexedDB. Multiple callers share the
 * same underlying cache module-wide; each instance keeps its own key scope.
 */
export function createChatHistoryPersistence(): ChatPersistence {
  let key: CryptoKey | null = null;
  let keyUserId: string | null = null;

  return {
    async unlock(selfUserId: string, ikxPrivate: Uint8Array): Promise<void> {
      if (keyUserId === selfUserId && key !== null) return;
      if (!isIndexedDbAvailable() || ikxPrivate.length !== 32) {
        return;
      }
      const info = new TextEncoder().encode(
        `${CHAT_AD_CONTEXT}\u001f${selfUserId}`,
      );
      const raw = await hkdfSha256(ikxPrivate, null, info, 32);
      const derived = await globalThis.crypto.subtle.importKey(
        'raw',
        raw as BufferSource,
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt'],
      );
      key = derived;
      keyUserId = selfUserId;
    },

    lock(): void {
      key = null;
      keyUserId = null;
    },

    isUnlocked(): boolean {
      return key !== null && keyUserId !== null;
    },

    async load(selfUserId: string): Promise<PersistedConversation[]> {
      const cachedKey = key;
      if (cachedKey === null || keyUserId !== selfUserId) return [];
      if (!isIndexedDbAvailable()) return [];
      const db = await getDb();
      const records = (await db.getAll(CHAT_STORE_NAME)) as ChatHistoryRecord[];
      const out: PersistedConversation[] = [];
      for (const record of records) {
        if (record.selfUserId !== selfUserId) continue;
        try {
          const plaintext = await decrypt(
            cachedKey,
            { ivHex: record.ivHex, ciphertextHex: record.ciphertextHex },
            historyAd(selfUserId, record.peerUserId),
          );
          const parsed: unknown = JSON.parse(new TextDecoder().decode(plaintext));
          if (!isPersistedConversation(parsed)) continue;
          out.push(parsed);
        } catch {
          // Undecryptable / tampered / stale-identity records are skipped.
        }
      }
      return out.sort((a, b) => b.lastActivityAt - a.lastActivityAt);
    },

    async save(selfUserId: string, conversation: PersistedConversation): Promise<void> {
      const cachedKey = key;
      if (cachedKey === null || keyUserId !== selfUserId) return;
      if (!isIndexedDbAvailable()) return;
      const plaintext = new TextEncoder().encode(JSON.stringify(conversation));
      const blob = await encrypt(
        cachedKey,
        plaintext,
        historyAd(selfUserId, conversation.peerUserId),
      );
      const record: ChatHistoryRecord = {
        id: recordId(selfUserId, conversation.peerUserId),
        selfUserId,
        peerUserId: conversation.peerUserId,
        updatedAt: Date.now(),
        ivHex: blob.ivHex,
        ciphertextHex: blob.ciphertextHex,
      };
      const db = await getDb();
      await db.put(CHAT_STORE_NAME, record);
    },

    async remove(selfUserId: string, peerUserId: string): Promise<void> {
      if (key === null || keyUserId !== selfUserId) return;
      if (!isIndexedDbAvailable()) return;
      const db = await getDb();
      await db.delete(CHAT_STORE_NAME, recordId(selfUserId, peerUserId));
    },
  };
}
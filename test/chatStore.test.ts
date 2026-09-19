import { afterEach, describe, expect, it } from 'vitest';
import { openDB } from 'idb';
import {
  CHAT_DB_NAME,
  CHAT_STORE_NAME,
  _closeChatHistoryStoreForTest,
  createChatHistoryPersistence,
} from '../src/persistence/chatStore';
import type {
  ChatPersistence,
  PersistedConversation,
} from '../src/persistence/types';

function sampleConversation(overrides: Partial<PersistedConversation> = {}): PersistedConversation {
  return {
    version: 1,
    peerUserId: 'bob',
    messages: [
      {
        id: 'm1',
        wireId: 'm1',
        senderUserId: 'bob',
        recipientUserId: 'alice',
        plaintext: 'super secret message text',
        createdAt: 1_700_000_000_000,
        outgoing: false,
        status: null,
        errorMessage: null,
        readAckSent: true,
      },
    ],
    lastActivityAt: 1_700_000_000_000,
    unreadCount: 1,
    ...overrides,
  };
}

function key(bytes: [number, number]): Uint8Array {
  return new Uint8Array(32).map((_, i) => ((i + bytes[0]) & 0xff) ^ bytes[1]);
}

async function rawRecords(): Promise<unknown[]> {
  const db = await openDB(CHAT_DB_NAME, 1, {
    upgrade(database) {
      if (!database.objectStoreNames.contains(CHAT_STORE_NAME)) {
        database.createObjectStore(CHAT_STORE_NAME, { keyPath: 'id' });
      }
    },
  });
  try {
    return await db.getAll(CHAT_STORE_NAME);
  } finally {
    db.close();
  }
}

function deleteChatDb(): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const req = indexedDB.deleteDatabase(CHAT_DB_NAME);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
    req.onblocked = () => resolve();
  });
}

afterEach(async () => {
  await _closeChatHistoryStoreForTest();
  await deleteChatDb();
});

describe('chatStore (IndexedDB encrypted history)', () => {
  it('saves and loads a conversation round-trip', async () => {
    const store = createChatHistoryPersistence() as ChatPersistence;
    await store.unlock('alice', key([1, 9]));
    await store.save('alice', sampleConversation());

    const loaded = await store.load('alice');
    expect(loaded).toHaveLength(1);
    expect(loaded[0]!.peerUserId).toBe('bob');
    expect(loaded[0]!.messages[0]!.plaintext).toBe('super secret message text');
    expect(loaded[0]!.unreadCount).toBe(1);
  });

  it('never writes message plaintext to disk — only ciphertext', async () => {
    const store = createChatHistoryPersistence() as ChatPersistence;
    await store.unlock('alice', key([1, 9]));
    await store.save('alice', sampleConversation());

    const records = await rawRecords();
    const serialized = JSON.stringify(records);
    expect(records).toHaveLength(1);
    expect(serialized).not.toContain('super secret message text');
    expect(serialized).not.toContain('m1');
  });

  it('loads nothing before unlock and lets save no-op silently', async () => {
    const store = createChatHistoryPersistence() as ChatPersistence;
    await expect(store.load('alice')).resolves.toEqual([]);
    await expect(
      store.save('alice', sampleConversation()),
    ).resolves.toBeUndefined();
    expect(await rawRecords()).toHaveLength(0);
  });

  it('scopes history to the owning account', async () => {
    const storeA = createChatHistoryPersistence() as ChatPersistence;
    await storeA.unlock('alice', key([1, 9]));
    await storeA.save('alice', sampleConversation());

    const storeB = createChatHistoryPersistence() as ChatPersistence;
    await storeB.unlock('bob', key([2, 9]));
    expect(await storeB.load('bob')).toEqual([]);
  });

  it('binds records to the identity key: a different device key cannot decrypt', async () => {
    const storeA = createChatHistoryPersistence() as ChatPersistence;
    await storeA.unlock('alice', key([1, 9]));
    await storeA.save('alice', sampleConversation());

    // Same account, but a DIFFERENT unlocked device key — the record was
    // authenticated under the first key, so decrypting must fail and the
    // entry is skipped instead of surfacing garbage.
    const storeSecondDevice = createChatHistoryPersistence() as ChatPersistence;
    await storeSecondDevice.unlock('alice', key([1, 99]));
    expect(await storeSecondDevice.load('alice')).toEqual([]);
  });

  it('skips tampered records instead of failing the whole load', async () => {
    const store = createChatHistoryPersistence() as ChatPersistence;
    await store.unlock('alice', key([1, 9]));
    await store.save('alice', sampleConversation());

    // Corrupt the stored ciphertext directly.
    const db = await openDB(CHAT_DB_NAME, 1);
    try {
      const record = (await db.get(CHAT_STORE_NAME, 'alice::bob')) as
        | { ciphertextHex: string }
        | undefined;
      if (record !== undefined) {
        record.ciphertextHex =
          (record.ciphertextHex.length > 4 && record.ciphertextHex.endsWith('0000')
            ? record.ciphertextHex.slice(0, -4)
            : `ff${record.ciphertextHex.slice(0, -2)}`) + 'ff';
        await db.put(CHAT_STORE_NAME, record);
      }
    } finally {
      db.close();
    }

    expect(await store.load('alice')).toEqual([]);
  });

  it('remove deletes only the targeted record', async () => {
    const store = createChatHistoryPersistence() as ChatPersistence;
    await store.unlock('alice', key([1, 9]));
    await store.save('alice', sampleConversation());
    await store.save(
      'alice',
      sampleConversation({ peerUserId: 'carol' }),
    );

    await store.remove('alice', 'bob');

    const loaded = await store.load('alice');
    expect(loaded.map((c) => c.peerUserId)).toEqual(['carol']);
  });

  it('lock drops the key: load becomes empty and further saves no-op', async () => {
    const store = createChatHistoryPersistence() as ChatPersistence;
    await store.unlock('alice', key([1, 9]));
    await store.save('alice', sampleConversation());
    expect(await store.load('alice')).toHaveLength(1);

    store.lock();
    expect(store.isUnlocked()).toBe(false);
    expect(await store.load('alice')).toEqual([]);

    await store.save('alice', sampleConversation({ messages: [] }));
    // The original record is untouched (save was a no-op while locked).
    expect(await rawRecords()).toHaveLength(1);
  });

  it('requires a 32-byte device key; invalid lengths are ignored safely', async () => {
    const store = createChatHistoryPersistence() as ChatPersistence;
    await store.unlock('alice', new Uint8Array(16));
    expect(store.isUnlocked()).toBe(false);
    expect(await store.load('alice')).toEqual([]);
  });
});
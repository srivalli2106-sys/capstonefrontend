/**
 * Local chat-history persistence types (Phase 13).
 *
 * The conversation history that `ChatController` keeps in memory is
 * persisted ENCRYPTED at rest so it survives a page refresh / reload. Only
 * the ciphertext of a serialized `PersistedConversation` ever touches disk;
 * the storage implementation lives in `persistence/chatStore.ts`.
 *
 * These types deliberately mirror the in-memory shapes in
 * `realtime/ChatController` WITHOUT importing them, so the persistence layer
 * stays decoupled from the realtime layer (no import cycles, and tests can
 * stub `ChatPersistence` directly).
 */

export type PersistedMessageStatus =
  | 'sending'
  | 'sent'
  | 'delivered'
  | 'read'
  | 'failed'
  | null;

/**
 * Frozen, serializable snapshot of one message as stored in the local
 * history. `id` is the stable client id (a `c-` id for outbound messages,
 * or the peer's wire id for inbound messages) and is used for dedup on
 * restore.
 */
export interface PersistedMessage {
  readonly id: string;
  readonly wireId: string | null;
  readonly senderUserId: string;
  readonly recipientUserId: string;
  readonly plaintext: string;
  readonly createdAt: number;
  readonly outgoing: boolean;
  readonly status: PersistedMessageStatus;
  readonly errorMessage: string | null;
  readonly readAckSent: boolean;
}

/**
 * One conversation's full history as stored on disk. `lastActivityAt`
 * drives sidebar ordering after a restore; `unreadCount` re-arms the unread
 * badge across reloads.
 */
export interface PersistedConversation {
  readonly version: 1;
  readonly peerUserId: string;
  readonly messages: PersistedMessage[];
  readonly lastActivityAt: number;
  readonly unreadCount: number;
}

/**
 * Storage contract used by `ChatController`. Implementations encrypt
 * `PersistedConversation` payloads at rest and expose an opaque
 * unlock/lock lifecycle so the key material never needs to flow through the
 * controller.
 *
 * All methods must be safe to call in any state:
 *   * Before `unlock`, `load` returns `[]` and `save`/`remove` are no-ops.
 *   * `unlock` with a different `selfUserId` replaces the active key and
 *     scopes every subsequent call.
 *   * `lock` drops the in-memory key; in-flight operations keep the key
 *     they captured at call time.
 */
export interface ChatPersistence {
  /**
   * Derive and cache the AES-GCM key for the given account from the
   * unlocked identity's X3DH device key. Idempotent per selfUserId.
   */
  unlock(selfUserId: string, ikxPrivate: Uint8Array): Promise<void>;

  /** Drop the cached key + account scope. In-flight calls keep their key. */
  lock(): void;

  /** True once a key is cached for the current account. */
  isUnlocked(): boolean;

  /** Decrypt everything stored for this account. Corrupt entries are skipped. */
  load(selfUserId: string): Promise<PersistedConversation[]>;

  /** Encrypt + upsert one conversation for this account. No-op if locked. */
  save(selfUserId: string, conversation: PersistedConversation): Promise<void>;

  /** Delete the stored record for one peer. No-op if locked or absent. */
  remove(selfUserId: string, peerUserId: string): Promise<void>;
}
/**
 * Conversation search (Messaging UX phase).
 *
 * Client-side filter over the conversation list by peer user id. Searches
 * ONLY peer user ids — never message content — so no plaintext of any kind
 * is inspected or transmitted to the backend.
 */

import type { ConversationSnapshot } from './ChatController';

export function filterConversationsBySearch(
  conversations: ConversationSnapshot[],
  term: string,
): ConversationSnapshot[] {
  const query = term.trim().toLowerCase();
  if (query.length === 0) {
    return conversations;
  }
  return conversations.filter((c) => c.peerUserId.toLowerCase().includes(query));
}
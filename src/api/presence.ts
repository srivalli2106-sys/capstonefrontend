/**
 * Presence API adapter (Messaging UX phase).
 *
 * Thin wrapper over the backend `GET /presence/{user_id}` endpoint. Read-only;
 * carries the auth Bearer token and never includes message content. Presence
 * is ephemeral, binary online/offline state — the backend deliberately exposes
 * no last-seen or device metadata.
 */

import { http, type HttpRequestOptions } from './http';

export interface PresenceResponse {
  user_id: string;
  online: boolean;
}

export function getPresence(targetUserId: string, opts: HttpRequestOptions = {}) {
  return http.get<PresenceResponse>(
    `/presence/${encodeURIComponent(targetUserId)}`,
    opts,
  );
}
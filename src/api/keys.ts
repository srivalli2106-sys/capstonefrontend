/**
 * Key-bundle API adapters (Phase 4).
 *
 * Thin wrappers over the backend `/keys/*` endpoints, mirroring `api/auth.ts`.
 * They perform no key-generation, no secret handling, and no state mutation.
 *
 * Endpoints (verified against `server/routes/keys.py`):
 *
 *   POST /keys/upload           200 → { status: "ok", user_id }
 *       Body: { spk_public, spk_sig, opk_public|null }   (auth: Bearer JWT)
 *       400 → invalid hex / wrong length · 401 → missing token · 404 → user
 *
 *   GET /keys/bundle/{user_id}  200 → KeyBundleResponse   (auth: Bearer JWT)
 *       Consumes the served OPK atomically server-side (single-use).
 *       401 → missing token · 404 → bundle/user not found
 *
 *   GET /keys/prekeys/{user_id} 200 → { user_id, opk_available, version }
 *                               401/404 as above
 *
 * Private key material is NEVER included in any request body or URL.
 */

import { http, type HttpRequestOptions } from './http';
import type {
  KeyBundleResponse,
  OPKStatusResponse,
  UploadKeyBundleRequest,
  UploadKeyBundleResponse,
} from '../types/keys';

export function uploadKeyBundle(
  body: UploadKeyBundleRequest,
  opts: HttpRequestOptions = {},
) {
  return http.post<UploadKeyBundleResponse>('/keys/upload', body, opts);
}

export function getKeyBundle(
  targetUserId: string,
  opts: HttpRequestOptions = {},
) {
  return http.get<KeyBundleResponse>(
    `/keys/bundle/${encodeURIComponent(targetUserId)}`,
    opts,
  );
}

export function getPrekeyStatus(
  targetUserId: string,
  opts: HttpRequestOptions = {},
) {
  return http.get<OPKStatusResponse>(
    `/keys/prekeys/${encodeURIComponent(targetUserId)}`,
    opts,
  );
}
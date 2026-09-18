/**
 * Key-bundle REST contract types (Phase 4).
 *
 * Derived from the CURRENT backend source:
 *   - `server/routes/keys.py` (UploadKeyBundleRequest, KeyBundleResponse,
 *     OPKStatusResponse)
 *   - `server/services/key_service.py` (logic + validation)
 *   - `server/repositories/key_repository.py` (OPK consumption semantics)
 *   - `tests/test_keys_routes.py`, `tests/test_key_service.py`,
 *     `tests/integration/test_auth_keys_flow.py`
 *
 * Wire encoding: every key field is lowercase hex of raw bytes
 * (`bytes.fromhex` server-side). `spk_public`, `opk_public` are 32-byte
 * X25519 keys (64 hex chars). `ik_public` is the 32-byte Ed25519 auth public
 * key (64 hex chars) read from the users collection — it verifies the SPK
 * signature. `spk_sig` is the hex signature over the signed prekey.
 *
 * NOTE (verified against source): the deployed `/keys/*` contract caps
 * `spk_sig` at 64 hex chars in `UploadKeyBundleRequest._MAX_KEY_HEX_LENGTH`,
 * while `protocol/keys.py` `build_key_bundle` produces real Ed25519
 * signatures of 64 bytes (128 hex chars). Likewise the REST bundle does not
 * carry the X25519 `xdh_public` (IKX) — docs/E2EE.md states the client must
 * carry it out-of-band. These backend contract gaps are reported, not
 * worked around, by this frontend.
 */

/** POST /keys/upload body (auth required). */
export interface UploadKeyBundleRequest {
  /** 64-hex X25519 signed-prekey public. */
  spk_public: string;
  /** hex SPK signature (backend currently accepts ≤ 64 hex chars). */
  spk_sig: string;
  /** 64-hex X25519 one-time-prekey public, or null. */
  opk_public: string | null;
}

export interface UploadKeyBundleResponse {
  status: 'ok';
  user_id: string;
}

/** GET /keys/bundle/{user_id} response (auth required). */
export interface KeyBundleResponse {
  user_id: string;
  /** 64-hex registered Ed25519 auth identity (verifies spk_sig). */
  ik_public: string;
  spk_public: string;
  spk_sig: string;
  /**
   * 64-hex one-time prekey — served to exactly ONE caller, then consumed
   * server-side. null when consumed or never uploaded.
   */
  opk_public: string | null;
  version: number;
}

/** GET /keys/prekeys/{user_id} response (auth required). */
export interface OPKStatusResponse {
  user_id: string;
  opk_available: boolean;
  version: number;
}
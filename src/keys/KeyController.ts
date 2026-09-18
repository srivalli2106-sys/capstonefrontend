/**
 * KeyController — frontend key-lifecycle orchestration (Phase 4).
 *
 * Depends on the unlocked identity held by `AuthController`. It does NOT
 * re-derive secrets and never touches the backend itself; API calls live in
 * `src/api/keys.ts` and are driven by callers that hold the JWT.
 *
 * Status model:
 *   - not_provisioned  : no local X25519 device key material yet.
 *   - ready            : device keys exist locally (IKX/SPK/OPK publics
 *                        derivable); nothing has been uploaded.
 *   - upload_blocked   : everything local is ready but the current backend
 *                        `/keys/upload` contract cannot carry a valid SPK
 *                        signature (see `UPLOAD_BLOCK_REASON`), so no bundle
 *                        is pushed. This is a frontend-side report of a
 *                        backend contract gap, NOT a silent workaround.
 *
 * Private scalars never leave the JS heap and are dropped on identity lock.
 */

import { authController } from '../auth/AuthController';
import {
  buildDevicePublicBundle,
  devicePublicBundleToHex,
} from '../crypto/deviceKeys';
import type { UnlockedIdentity } from '../crypto/identity';

/**
 * Actual Ed25519 signatures are 64 bytes = 128 hex chars, but
 * `server/routes/keys.py UploadKeyBundleRequest._MAX_KEY_HEX_LENGTH` caps
 * `spk_sig` at 64 hex chars. A real signed prekey can therefore not be
 * uploaded under the current contract. Reported, not worked around.
 */
export const UPLOAD_BLOCK_REASON =
  'Backend /keys/upload caps spk_sig at 64 hex chars, but the E2EE protocol requires a real Ed25519 signature (128 hex). No bundle can be uploaded without weakening the SPK binding.';

export interface LocalKeyInfo {
  userId: string;
  /** Ed25519 auth identity (64-hex) registered with the backend. */
  ikPublicHex: string;
  /** X25519 X3DH identity IKX (64-hex). */
  ikxPublicHex: string;
  /** X25519 signed prekey (64-hex). */
  spkPublicHex: string;
  /** Ed25519 signature over SPK_SIGN_CONTEXT || spk_public (128-hex). */
  spkSignatureHex: string;
  /** X25519 one-time prekey (64-hex), or null when none held. */
  opkPublicHex: string | null;
}

export type KeyStatus =
  | { kind: 'not_provisioned' }
  | { kind: 'ready'; local: LocalKeyInfo }
  | { kind: 'upload_blocked'; local: LocalKeyInfo; reason: string };

type Listener = (status: KeyStatus) => void;

class KeyControllerImpl {
  private listeners: Set<Listener> = new Set();

  getStatus(): KeyStatus {
    const identity = authController.getUnlockedIdentity();
    if (identity === null || identity.deviceKeys === null) {
      return { kind: 'not_provisioned' };
    }
    const local = buildLocalKeyInfo(identity);
    if (local === null) {
      return { kind: 'not_provisioned' };
    }
    // The bundle can be BUILT, but a real signature cannot be uploaded.
    return { kind: 'upload_blocked', local, reason: UPLOAD_BLOCK_REASON };
  }

  subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  /** Re-fan-out the current status (e.g. after the auth identity changed). */
  refresh(): void {
    this.notify();
  }

  private notify(): void {
    const status = this.getStatus();
    this.listeners.forEach((l) => {
      try {
        l(status);
      } catch {
        // listener errors must not break the loop
      }
    });
  }
}

export function buildLocalKeyInfo(
  identity: UnlockedIdentity,
): LocalKeyInfo | null {
  if (identity.deviceKeys === null) {
    return null;
  }
  const seed = identity.exportRawSeed();
  const bundle = buildDevicePublicBundle(seed, identity.deviceKeys);
  const hex = devicePublicBundleToHex(bundle);
  return {
    userId: identity.userId,
    ikPublicHex: identity.publicKeyHex,
    ikxPublicHex: typeof hex.xdh_public === 'string' ? hex.xdh_public : '',
    spkPublicHex: typeof hex.spk_public === 'string' ? hex.spk_public : '',
    spkSignatureHex:
      typeof hex.spk_signature === 'string' ? hex.spk_signature : '',
    opkPublicHex:
      Array.isArray(hex.opk_publics) && hex.opk_publics.length > 0
        ? String(hex.opk_publics[0])
        : null,
  };
}

export const keyController = new KeyControllerImpl();

// Re-emit status whenever the auth identity changes (lock/unlock/login/logout).
authController.subscribe(() => {
  keyController.refresh();
});
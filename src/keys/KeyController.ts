/**
 * KeyController — frontend key-lifecycle orchestration (Phase 4).
 *
 * Depends on the unlocked identity held by `AuthController`. It does NOT
 * re-derive secrets; the API call itself lives in `src/api/keys.ts` and is
 * driven here with the current JWT.
 *
 * Status model:
 *   - not_provisioned  : no local X25519 device key material yet.
 *   - ready            : device keys exist locally (IKX/SPK/OPK publics
 *                        derivable) and the bundle upload has been
 *                        attempted against the backend when the identity
 *                        is unlocked and a JWT is held.
 *
 * When the identity becomes unlocked (register/login/unlock) the current
 * user's key bundle is uploaded so peers can fetch it during X3DH session
 * establishment. Upload failures are best-effort and never block auth or
 * chat UI.
 *
 * Private scalars never leave the JS heap and are dropped on identity lock.
 */

import { authController } from '../auth/AuthController';
import { uploadKeyBundle } from '../api/keys';
import {
  buildDevicePublicBundle,
  devicePublicBundleToHex,
} from '../crypto/deviceKeys';
import type { UnlockedIdentity } from '../crypto/identity';

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
  /** ML-KEM-768 public key (2368-hex), or null when classical-only. */
  pqKemPublicHex: string | null;
  /** ML-DSA-44 public key (2624-hex), or null when classical-only. */
  pqSigPublicHex: string | null;
  /** ML-DSA-44 binding signature over the hybrid context (4840-hex). */
  pqBindingSigHex: string | null;
  /** 1 = classical, 2 = hybrid. */
  protocolVersion: number;
}

export type KeyStatus =
  | { kind: 'not_provisioned' }
  | { kind: 'ready'; local: LocalKeyInfo };

type Listener = (status: KeyStatus) => void;

class KeyControllerImpl {
  private listeners: Set<Listener> = new Set();
  /** Guards against overlapping uploads for the same unlocked identity. */
  private uploading = false;

  async getStatus(): Promise<KeyStatus> {
    const identity = authController.getUnlockedIdentity();
    if (identity === null || identity.deviceKeys === null) {
      return { kind: 'not_provisioned' };
    }
    const local = await buildLocalKeyInfo(identity);
    if (local === null) {
      return { kind: 'not_provisioned' };
    }
    return { kind: 'ready', local };
  }

  subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  /**
   * Upload the current unlocked identity's public key bundle to the backend
   * so peers can fetch it when establishing an X3DH session. Best-effort:
   * failures are logged to console only and surface as a `ready` status so
   * they never block auth or chat.
   */
  async ensureBundleUploaded(): Promise<void> {
    const status = await this.getStatus();
    if (status.kind !== 'ready' || this.uploading) {
      return;
    }
    const token = authController.getToken();
    if (token === null) {
      return;
    }
    const { local } = status;
    this.uploading = true;
    try {
      await uploadKeyBundle(
        {
          xdh_public: local.ikxPublicHex,
          spk_public: local.spkPublicHex,
          spk_sig: local.spkSignatureHex,
          opk_public: local.opkPublicHex,
          pq_kem_public: local.pqKemPublicHex,
          pq_sig_public: local.pqSigPublicHex,
          pq_binding_sig: local.pqBindingSigHex,
          protocol_version: local.protocolVersion,
        },
        { authToken: token },
      );
    } catch (err) {
      // Best-effort upload: do not block the UI on transient backend issues.
      // eslint-disable-next-line no-console
      console.warn('Key bundle upload failed:', err instanceof Error ? err.message : err);
    } finally {
      this.uploading = false;
    }
  }

  /** Re-fan-out the current status (e.g. after the auth identity changed). */
  refresh(): void {
    // When the identity is freshly unlocked, publish the bundle so peers can
    // fetch it. Guarded by the `uploading` flag inside ensureBundleUploaded.
    if (
      authController.getUnlockedIdentity() !== null &&
      authController.getToken() !== null
    ) {
      void this.ensureBundleUploaded();
    }
    this.notify();
  }

  private notify(): void {
    this.getStatus().then((status) => {
      this.listeners.forEach((l) => {
        try {
          l(status);
        } catch {
          // listener errors must not break the loop
        }
      });
    });
  }
}

export async function buildLocalKeyInfo(
  identity: UnlockedIdentity,
): Promise<LocalKeyInfo | null> {
  if (identity.deviceKeys === null) {
    return null;
  }
  const seed = identity.exportRawSeed();
  const bundle = await buildDevicePublicBundle(seed, identity.deviceKeys);
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
    pqKemPublicHex:
      typeof hex.pq_kem_public === 'string' ? hex.pq_kem_public : null,
    pqSigPublicHex:
      typeof hex.pq_sig_public === 'string' ? hex.pq_sig_public : null,
    pqBindingSigHex:
      typeof hex.pq_binding_sig === 'string' ? hex.pq_binding_sig : null,
    protocolVersion:
      typeof hex.protocol_version === 'number' ? hex.protocol_version : 1,
  };
}

export const keyController = new KeyControllerImpl();

// Re-emit status and attempt bundle upload whenever the auth identity
// changes (lock/unlock/login/logout).
authController.subscribe(() => {
  keyController.refresh();
});
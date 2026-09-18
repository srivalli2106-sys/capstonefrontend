/**
 * AuthController — single source of truth for the frontend's authentication
 * and identity state.
 *
 * Responsibilities (Phase 3):
 *  - Generate a real Ed25519 identity locally on registration.
 *  - Persist the encrypted identity in IndexedDB (no plaintext on disk).
 *  - Run the backend's PoP authentication (`/auth/challenge` + `/auth/verify`)
 *    by signing the raw nonce bytes with the local Ed25519 private key.
 *  - Hold the in-memory JWT and the unlocked identity.
 *  - Restore JWT from sessionStorage on app boot (identity is never restored
 *    — the user must re-unlock with their passphrase).
 *  - Register a 401 handler so stale tokens invalidate the session.
 *
 * Phase 3 explicitly does NOT use the dev-only `/auth/login` endpoint.
 *
 * Phase 4+ will introduce X25519, X3DH, the Double Ratchet, and key
 * bundles. None of that is wired here.
 */

import {
  createChallenge as apiChallenge,
  logout as apiLogout,
  register as apiRegister,
  verifyChallenge as apiVerify,
} from '../api/auth';
import { setUnauthorizedHandler } from '../api/http';
import {
  clearToken,
  loadToken,
  loadUserId,
  saveToken,
} from './sessionStorage';
import {
  IdentityError,
  createLocalIdentity,
  deleteLocalIdentity,
  inspectIdentity,
  unlockIdentity,
  validateRegistrationInput,
  type PublicIdentity,
  type UnlockedIdentity,
} from '../crypto/identity';
import { hexToBytes } from '../crypto/hex';
import type { JwtClaims } from '../types/auth';

const USER_ID_MIN_LENGTH = 3;
const USER_ID_MAX_LENGTH = 64;

export type IdentityState =
  | { kind: 'none' }
  | { kind: 'locked'; userId: string; publicKeyHex: string; publicKeyShortId: string }
  | { kind: 'unlocked'; userId: string; publicKeyHex: string; publicKeyShortId: string };

export interface AuthSnapshot {
  authenticated: boolean;
  userId: string | null;
  exp: number | null;
  identity: IdentityState;
}

type Listener = (snapshot: AuthSnapshot) => void;

class AuthControllerImpl {
  private token: string | null;
  private sessionUserId: string | null;
  private exp: number | null;
  private unlocked: UnlockedIdentity | null;
  private knownIdentity: PublicIdentity | null;
  private listeners: Set<Listener> = new Set();
  private installed = false;

  constructor() {
    this.token = loadToken();
    this.sessionUserId = loadUserId();
    this.exp = this.decodeExp(this.token);
    if (this.token !== null && (this.exp === null || this.exp * 1000 <= Date.now())) {
      this.token = null;
      this.sessionUserId = null;
      this.exp = null;
      clearToken();
    }
    this.unlocked = null;
    this.knownIdentity = null;
  }

  install(): void {
    if (this.installed) return;
    this.installed = true;
    setUnauthorizedHandler((info) => {
      if (info.path === '/auth/logout') return;
      this.clearSession({ silent: false });
    });
  }

  getSnapshot(): AuthSnapshot {
    return {
      authenticated: this.token !== null && this.sessionUserId !== null,
      userId: this.sessionUserId,
      exp: this.exp,
      identity: this.identityState(),
    };
  }

  subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  getToken(): string | null {
    return this.token;
  }

  getUserId(): string | null {
    return this.sessionUserId;
  }

  getUnlockedIdentity(): UnlockedIdentity | null {
    return this.unlocked;
  }

  validateUserId(userId: string): string | null {
    const trimmed = userId.trim();
    if (trimmed.length < USER_ID_MIN_LENGTH) {
      return `user_id must be at least ${USER_ID_MIN_LENGTH} characters.`;
    }
    if (trimmed.length > USER_ID_MAX_LENGTH) {
      return `user_id must be at most ${USER_ID_MAX_LENGTH} characters.`;
    }
    return null;
  }

  /**
   * Inspect the local IndexedDB record for `userId`. Does NOT decrypt.
   * Useful for the login screen to detect "no identity yet" cases.
   */
  async hasLocalIdentity(userId: string): Promise<boolean> {
    try {
      const pub = await inspectIdentity(userId);
      return pub !== null;
    } catch {
      return false;
    }
  }

  /**
   * Phase 3 registration flow:
   *   1. Generate an Ed25519 keypair locally.
   *   2. Encrypt + persist the private seed in IndexedDB.
   *   3. POST /auth/register with the real `ik_public`.
   *   4. On backend success: unlock the identity, run PoP challenge/verify,
   *      and establish the session.
   *   5. On backend failure: wipe the local record (rollback) and throw.
   */
  async register(
    userId: string,
    passphrase: string,
    passphraseConfirm: string,
  ): Promise<void> {
    const idError = this.validateUserId(userId);
    if (idError !== null) {
      throw new Error(idError);
    }

    const trimmedId = userId.trim();

    // Validate input (including passphrase length + confirmation) before any
    // crypto work so a bad passphrase cannot leave a half-initialized
    // IndexedDB record behind.
    try {
      validateRegistrationInput(trimmedId, passphrase, passphraseConfirm);
    } catch (err) {
      throw err instanceof Error ? err : new Error(String(err));
    }

    let createdHex: string | null = null;
    try {
      const { publicKeyHex } = await createLocalIdentity(
        trimmedId,
        passphrase,
      );
      createdHex = publicKeyHex;

      await apiRegister({ user_id: trimmedId, ik_public: publicKeyHex });

      // Register succeeded; now complete the PoP login.
      await this.completeChallengeVerify(trimmedId, passphrase);

      // Update cached known identity.
      this.knownIdentity = {
        userId: trimmedId,
        publicKeyHex,
        publicKeyShortId: publicKeyHex.slice(0, 12),
      };
    } catch (err) {
      // Rollback the local record if we created one but registration failed.
      if (createdHex !== null) {
        try {
          await deleteLocalIdentity(trimmedId);
        } catch {
          // ignore secondary failure
        }
      }
      throw err;
    }
  }

  /**
   * Phase 3 login flow:
   *   1. Look up the encrypted local identity.
   *   2. Decrypt the seed with the passphrase (PBKDF2 + AES-GCM).
   *   3. Run PoP challenge/verify against the backend.
   *   4. On success, hold both the JWT and the unlocked identity.
   *   5. On failure, lock the identity and rethrow.
   */
  async login(userId: string, passphrase: string): Promise<void> {
    const idError = this.validateUserId(userId);
    if (idError !== null) {
      throw new Error(idError);
    }
    const trimmedId = userId.trim();

    // Unlock first; if the passphrase is wrong or no record exists, fail
    // BEFORE we touch the backend. This avoids leaking which user_ids exist
    // via a backend 404 vs a local "no record" 404.
    const unlocked = await unlockIdentity(trimmedId, passphrase);
    try {
      await this.runChallengeVerifyAgainstUnlocked(unlocked);
      this.unlocked = unlocked;
      this.knownIdentity = {
        userId: unlocked.userId,
        publicKeyHex: unlocked.publicKeyHex,
        publicKeyShortId: unlocked.publicKeyShortId,
      };
      this.acceptSessionFromLogin(trimmedId);
    } catch (err) {
      unlocked.lock();
      throw err;
    }
  }

  /**
   * Re-unlock the local identity without re-running challenge/verify.
   * Useful after a page reload when the JWT may still be valid.
   */
  async unlock(userId: string, passphrase: string): Promise<void> {
    const unlocked = await unlockIdentity(userId.trim(), passphrase);
    // If the unlocked identity's user_id doesn't match the current session,
    // refuse — keeps us from signing challenges as the wrong account.
    if (this.sessionUserId !== null && unlocked.userId !== this.sessionUserId) {
      unlocked.lock();
      throw new Error(
        'Unlocked identity does not match the current session. Sign out first.',
      );
    }
    if (this.unlocked !== null) {
      this.unlocked.lock();
    }
    this.unlocked = unlocked;
    this.knownIdentity = {
      userId: unlocked.userId,
      publicKeyHex: unlocked.publicKeyHex,
      publicKeyShortId: unlocked.publicKeyShortId,
    };
    this.notify();
  }

  /**
   * Lock the in-memory identity (drops the decrypted seed) without
   * touching the JWT or the on-disk record.
   */
  lockIdentity(): void {
    if (this.unlocked !== null) {
      this.unlocked.lock();
      this.unlocked = null;
    }
    this.notify();
  }

  /**
   * Refresh the cached `knownIdentity` for the active session by re-reading
   * IndexedDB. Useful after a successful register where we want the UI to
   * reflect the just-created record.
   */
  async refreshKnownIdentity(): Promise<void> {
    if (this.sessionUserId === null) return;
    const pub = await inspectIdentity(this.sessionUserId);
    this.knownIdentity = pub;
    this.notify();
  }

  async logout(): Promise<void> {
    const current = this.token;
    try {
      if (current !== null) {
        await apiLogout({ authToken: current });
      }
    } finally {
      this.clearSession({ silent: false });
    }
  }

  /**
   * Wipe the local encrypted identity record for the current user.
   * Use only after explicit user confirmation.
   */
  async wipeLocalIdentity(userId?: string): Promise<void> {
    const id = (userId ?? this.sessionUserId ?? '').trim();
    if (id.length === 0) return;
    await deleteLocalIdentity(id);
    if (this.knownIdentity?.userId === id) {
      this.knownIdentity = null;
    }
    if (this.unlocked?.userId === id) {
      this.unlocked.lock();
      this.unlocked = null;
    }
    this.notify();
  }

  clearLocal(): void {
    this.clearSession({ silent: false });
  }

  // ----- private helpers -----

  private async completeChallengeVerify(
    userId: string,
    passphrase: string,
  ): Promise<void> {
    const unlocked = await unlockIdentity(userId, passphrase);
    try {
      await this.runChallengeVerifyAgainstUnlocked(unlocked);
      this.unlocked = unlocked;
      this.acceptSessionFromLogin(userId);
    } catch (err) {
      unlocked.lock();
      throw err;
    }
  }

  private async runChallengeVerifyAgainstUnlocked(
    unlocked: UnlockedIdentity,
  ): Promise<void> {
    const { data: challenge } = await apiChallenge({
      user_id: unlocked.userId,
    });
    const rawNonce = hexToBytes(challenge.nonce);
    if (rawNonce.length !== 32) {
      throw new Error('server returned an unexpected nonce length');
    }
    const signatureBytes = unlocked.signNonceRaw(rawNonce);
    const signatureHex = bytesToHex(signatureBytes);
    const { data: verified } = await apiVerify({
      user_id: unlocked.userId,
      nonce: challenge.nonce,
      signature: signatureHex,
    });
    this.token = verified.token;
    this.sessionUserId = verified.user_id;
    this.exp = this.decodeExp(verified.token);
    saveToken(verified.token, verified.user_id);
  }

  private acceptSessionFromLogin(_userId: string): void {
    // The session fields were already written by runChallengeVerifyAgainstUnlocked.
    this.notify();
  }

  private identityState(): IdentityState {
    if (this.unlocked !== null) {
      return {
        kind: 'unlocked',
        userId: this.unlocked.userId,
        publicKeyHex: this.unlocked.publicKeyHex,
        publicKeyShortId: this.unlocked.publicKeyShortId,
      };
    }
    if (this.knownIdentity !== null) {
      return {
        kind: 'locked',
        userId: this.knownIdentity.userId,
        publicKeyHex: this.knownIdentity.publicKeyHex,
        publicKeyShortId: this.knownIdentity.publicKeyShortId,
      };
    }
    return { kind: 'none' };
  }

  private clearSession(_opts: { silent: boolean }): void {
    if (this.unlocked !== null) {
      this.unlocked.lock();
      this.unlocked = null;
    }
    this.token = null;
    this.sessionUserId = null;
    this.exp = null;
    this.knownIdentity = null;
    clearToken();
    this.notify();
  }

  private notify(): void {
    const snap = this.getSnapshot();
    this.listeners.forEach((l) => {
      try {
        l(snap);
      } catch {
        // Listener exceptions must not affect other listeners.
      }
    });
  }

  private decodeExp(token: string | null): number | null {
    if (token === null) return null;
    const claims = decodeJwtClaims(token);
    if (claims === null) return null;
    return claims.exp;
  }
}

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) {
    const byte = bytes[i];
    if (byte === undefined) continue;
    out += byte.toString(16).padStart(2, '0');
  }
  return out;
}

function decodeJwtClaims(token: string): JwtClaims | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const payloadPart = parts[1];
  if (payloadPart === undefined) return null;
  let b64 = payloadPart.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) {
    b64 += '=';
  }
  let json: string;
  try {
    json = atob(b64);
  } catch {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== 'object') return null;
  const obj = parsed as Record<string, unknown>;
  if (
    typeof obj.sub !== 'string' ||
    typeof obj.iss !== 'string' ||
    typeof obj.iat !== 'number' ||
    typeof obj.exp !== 'number' ||
    typeof obj.jti !== 'string'
  ) {
    return null;
  }
  return {
    sub: obj.sub,
    iss: obj.iss,
    iat: obj.iat,
    exp: obj.exp,
    jti: obj.jti,
    user_id: typeof obj.user_id === 'string' ? obj.user_id : obj.sub,
  };
}

export { IdentityError };
export const authController = new AuthControllerImpl();
authController.install();
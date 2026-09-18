/**
 * AuthController — single source of truth for the frontend's authentication
 * state.
 *
 * Responsibilities (Phase 2):
 *  - Hold the in-memory JWT and the resolved user_id.
 *  - Restore from sessionStorage on app boot.
 *  - Register with the HTTP client so every authenticated request gets the
 *    `Authorization: Bearer <token>` header and so any 401 invalidates the
 *    current session.
 *  - Expose `register`, `login` (dev-only), `logout`, and a small listener
 *    API for React.
 *
 * Phase 2 limitations (documented, NOT implemented here):
 *  - `register` accepts a placeholder `ik_public` of 64 hex chars generated
 *    from `crypto.getRandomValues`. Real Ed25519 key generation, signature
 *    computation, and encrypted local storage are deferred to Phase 3.
 *  - `login` uses the dev-only `/auth/login` endpoint. In production this
 *    returns 403 (verified in `tests/test_auth_routes.py::test_login_disabled_in_production`);
 *    Phase 3 will switch to the challenge/verify PoP flow.
 */

import {
  devLogin,
  logout as apiLogout,
  register as apiRegister,
} from '../api/auth';
import { setUnauthorizedHandler } from '../api/http';
import {
  clearToken,
  loadToken,
  loadUserId,
  saveToken,
} from './sessionStorage';
import type { JwtClaims } from '../types/auth';

const USER_ID_MIN_LENGTH = 3;
const USER_ID_MAX_LENGTH = 64;
const IK_PUBLIC_HEX_LENGTH = 64;

export interface ValidationError {
  field: string;
  message: string;
}

export interface AuthSnapshot {
  authenticated: boolean;
  userId: string | null;
  exp: number | null;
}

type Listener = (snapshot: AuthSnapshot) => void;

class AuthControllerImpl {
  private token: string | null;
  private userId: string | null;
  private exp: number | null;
  private listeners: Set<Listener> = new Set();
  private installed = false;

  constructor() {
    this.token = loadToken();
    this.userId = loadUserId();
    this.exp = this.decodeExp(this.token);
    if (this.token !== null && (this.exp === null || this.exp * 1000 <= Date.now())) {
      this.token = null;
      this.userId = null;
      this.exp = null;
      clearToken();
    }
  }

  install(): void {
    if (this.installed) return;
    this.installed = true;
    setUnauthorizedHandler((info) => {
      if (info.path === '/auth/logout') return;
      this.clear({ silent: false });
    });
  }

  getSnapshot(): AuthSnapshot {
    return {
      authenticated: this.token !== null && this.userId !== null,
      userId: this.userId,
      exp: this.exp,
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
    return this.userId;
  }

  validateUserId(userId: string): ValidationError | null {
    const trimmed = userId.trim();
    if (trimmed.length < USER_ID_MIN_LENGTH) {
      return {
        field: 'user_id',
        message: `user_id must be at least ${USER_ID_MIN_LENGTH} characters.`,
      };
    }
    if (trimmed.length > USER_ID_MAX_LENGTH) {
      return {
        field: 'user_id',
        message: `user_id must be at most ${USER_ID_MAX_LENGTH} characters.`,
      };
    }
    return null;
  }

  /**
   * Generate a 32-byte random placeholder, hex-encoded.
   *
   * NOT an Ed25519 key. Replaced by a real keypair in Phase 3.
   * Documented in the register page and the README.
   */
  generatePlaceholderIkPublic(): string {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return bytesToHex(bytes);
  }

  validateIkPublic(hex: string): ValidationError | null {
    if (hex.length !== IK_PUBLIC_HEX_LENGTH) {
      return {
        field: 'ik_public',
        message: `ik_public must be exactly ${IK_PUBLIC_HEX_LENGTH} hex characters.`,
      };
    }
    if (!/^[0-9a-fA-F]+$/.test(hex)) {
      return {
        field: 'ik_public',
        message: 'ik_public must be hexadecimal.',
      };
    }
    return null;
  }

  async register(userId: string, ikPublicHex: string): Promise<void> {
    const idError = this.validateUserId(userId);
    if (idError !== null) {
      throw new Error(idError.message);
    }
    const keyError = this.validateIkPublic(ikPublicHex);
    if (keyError !== null) {
      throw new Error(keyError.message);
    }
    await apiRegister({ user_id: userId.trim(), ik_public: ikPublicHex });
  }

  /**
   * Dev-only login. Will throw an `ApiError` with status 403 in production.
   * Phase 3 replaces this with the Ed25519 challenge/verify flow.
   */
  async login(userId: string): Promise<void> {
    const idError = this.validateUserId(userId);
    if (idError !== null) {
      throw new Error(idError.message);
    }
    const { data } = await devLogin({ user_id: userId.trim() });
    this.acceptSession(data.token, data.user_id);
  }

  async logout(): Promise<void> {
    const current = this.token;
    try {
      if (current !== null) {
        await apiLogout({ authToken: current });
      }
    } finally {
      this.clear({ silent: false });
    }
  }

  /**
   * Local-only logout (e.g., when 401 indicates the token is dead).
   * Does NOT call the backend; the server-side blacklist will expire
   * naturally at `exp`.
   */
  clearLocal(): void {
    this.clear({ silent: false });
  }

  private acceptSession(token: string, userId: string): void {
    this.token = token;
    this.userId = userId;
    this.exp = this.decodeExp(token);
    saveToken(token, userId);
    this.notify();
  }

  private clear(_opts: { silent: boolean }): void {
    this.token = null;
    this.userId = null;
    this.exp = null;
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

/**
 * Decode a JWT WITHOUT verifying the signature. Verification is the server's
 * responsibility. We only use this for client-side UX (e.g., expiry
 * detection). Any tampering or false claims will be rejected by the backend.
 */
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

export const authController = new AuthControllerImpl();
authController.install();
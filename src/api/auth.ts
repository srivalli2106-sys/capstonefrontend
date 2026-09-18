/**
 * Authentication API.
 *
 * Thin wrappers over the backend `/auth/*` endpoints. These functions
 * perform no auth-state mutation, no token storage, no React glue.
 *
 * Endpoints (verified against `server/routes/auth.py`):
 *
 *   POST /auth/register   — one-time account creation.
 *                            Body:  { user_id, ik_public (hex) }
 *                            201  → { status: "registered", user_id }
 *                            409  → conflict (duplicate user_id)
 *                            422  → validation_error
 *                            429  → rate limit (1/hour per IP)
 *
 *   POST /auth/login      — DEV-ONLY password-less login.
 *                            200  → { token, user_id }
 *                            403  → forbidden (production)
 *                            404  → not_found
 *
 *   POST /auth/challenge  — issue a PoP nonce.
 *                            200  → { user_id, nonce (64 hex chars) }
 *                            404  → not_found
 *                            422  → validation_error
 *
 *   POST /auth/verify     — complete PoP and obtain a JWT.
 *                            Body: { user_id, nonce (64 hex), signature (128 hex) }
 *                            200  → { token, user_id }
 *                            401  → Authentication failed (generic)
 *                            422  → validation_error
 *
 *   POST /auth/logout     — revoke the current JWT.
 *                            Header: Authorization: Bearer <token>
 *                            200  → { status: "logged_out" }
 *                            401  → invalid token
 */

import { http, type HttpRequestOptions } from './http';
import type {
  ChallengeRequest,
  ChallengeResponse,
  DevLoginRequest,
  DevLoginResponse,
  LogoutResponse,
  RegisterRequest,
  RegisterResponse,
  VerifyRequest,
  VerifyResponse,
} from '../types/auth';

export function register(
  body: RegisterRequest,
  opts: HttpRequestOptions = {},
) {
  return http.post<RegisterResponse>('/auth/register', body, opts);
}

export function devLogin(body: DevLoginRequest, opts: HttpRequestOptions = {}) {
  return http.post<DevLoginResponse>('/auth/login', body, opts);
}

export function createChallenge(
  body: ChallengeRequest,
  opts: HttpRequestOptions = {},
) {
  return http.post<ChallengeResponse>('/auth/challenge', body, opts);
}

export function verifyChallenge(
  body: VerifyRequest,
  opts: HttpRequestOptions = {},
) {
  return http.post<VerifyResponse>('/auth/verify', body, opts);
}

export function logout(opts: HttpRequestOptions = {}) {
  return http.post<LogoutResponse>('/auth/logout', undefined, opts);
}
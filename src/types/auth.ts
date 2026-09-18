/**
 * Authentication contract types.
 *
 * Derived directly from `server/routes/auth.py`, `server/auth_service.py`,
 * `server/jwt_auth.py`, and `tests/test_auth_routes.py`.
 *
 * The backend has NO password-based login. Authentication is purely
 * cryptographic: an Ed25519 identity key registered with the server, used to
 * sign a server-issued challenge nonce to obtain a short-lived JWT.
 */

export interface RegisterRequest {
  user_id: string;
  ik_public: string;
}

export interface RegisterResponse {
  status: 'registered';
  user_id: string;
}

export interface ChallengeRequest {
  user_id: string;
}

export interface ChallengeResponse {
  user_id: string;
  nonce: string;
}

export interface VerifyRequest {
  user_id: string;
  nonce: string;
  signature: string;
}

export interface VerifyResponse {
  token: string;
  user_id: string;
}

/**
 * Dev/test-only convenience login. Disabled in production.
 * Kept here for development workflows; will return 403 in prod.
 */
export interface DevLoginRequest {
  user_id: string;
}

export interface DevLoginResponse {
  token: string;
  user_id: string;
}

export interface LogoutResponse {
  status: 'logged_out';
}

/**
 * Decoded claims from a JWT.
 *
 * The backend does not provide a `/me` endpoint. The frontend may decode the
 * token locally (without trusting the signature) to read `sub`, `exp`, etc.
 * Signature verification is the server's responsibility; here we only extract
 * claims for client-side UX (e.g. expiry warnings, "logged in as ...").
 */
export interface JwtClaims {
  sub: string;
  iss: string;
  iat: number;
  exp: number;
  jti: string;
  user_id: string;
}
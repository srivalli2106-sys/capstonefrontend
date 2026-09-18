/**
 * Login page.
 *
 * Authentication flow (unchanged across phases):
 *   1. User enters user_id + passphrase.
 *   2. The frontend decrypts the local Ed25519 seed (IndexedDB + PBKDF2 +
 *      AES-GCM).
 *   3. POST /auth/challenge → nonce.
 *   4. Sign the raw 32-byte nonce (NOT the hex string) with Ed25519.
 *   5. POST /auth/verify → JWT.
 *
 * The user_id MUST match a local identity record. There is no account
 * recovery by design.
 */

import type { FormEvent, JSX } from 'react';
import { useEffect, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { ApiError } from '../api/http';
import { authController, IdentityError } from '../auth/AuthController';

type Status =
  | { kind: 'idle' }
  | { kind: 'unlocking' }
  | { kind: 'signing' }
  | { kind: 'error'; message: string; requestId: string | null };

export function LoginPage(): JSX.Element {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const next = params.get('next') ?? '/chat';

  const [userId, setUserId] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [status, setStatus] = useState<Status>({ kind: 'idle' });
  const [hasLocal, setHasLocal] = useState<boolean | null>(null);

  useEffect(() => {
    if (userId.trim().length >= 3) {
      void authController.hasLocalIdentity(userId).then(setHasLocal);
    } else {
      setHasLocal(null);
    }
  }, [userId]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setStatus({ kind: 'unlocking' });
    try {
      setStatus({ kind: 'signing' });
      await authController.login(userId, passphrase);
      navigate(decodeURIComponent(next), { replace: true });
    } catch (err) {
      setStatus(mapError(err));
    }
  }

  const submitting = status.kind === 'unlocking' || status.kind === 'signing';
  const submitLabel =
    status.kind === 'unlocking'
      ? 'Unlocking identity…'
      : status.kind === 'signing'
        ? 'Signing challenge…'
        : 'Sign in';

  return (
    <div className="page page--narrow">
      <section className="auth-card" aria-labelledby="login-title">
        <h1 id="login-title" className="auth-card__title">Sign in</h1>
        <p className="auth-card__lede">
          Authentication uses a proof-of-possession signature over a server
          challenge. Your signing key lives only on this device.
        </p>

        <hr className="auth-card__divider" />

        <form className="form" onSubmit={handleSubmit} noValidate>
          <label className="form__field">
            <span className="form__label">User identifier</span>
            <input
              className="form__input"
              type="text"
              name="user_id"
              autoComplete="username"
              minLength={3}
              maxLength={64}
              required
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
              disabled={submitting}
              placeholder="e.g. alice"
              aria-describedby="userid-hint"
            />
            <small id="userid-hint" className="form__hint">3 to 64 characters.</small>
            {hasLocal === false && userId.trim().length >= 3 && (
              <small className="form__hint form__hint--warn" role="status">
                No local identity for this user on this device.{' '}
                <Link to="/register">Register instead.</Link>
              </small>
            )}
          </label>

          <label className="form__field">
            <span className="form__label">Identity passphrase</span>
            <input
              className="form__input"
              type="password"
              name="passphrase"
              autoComplete="current-password"
              required
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              disabled={submitting}
              placeholder="Your local passphrase"
            />
            <small className="form__hint">
              Used to unlock the locally-stored Ed25519 private key.
            </small>
          </label>

          {status.kind === 'error' && (
            <div className="form__error" role="alert">
              <span>{status.message}</span>
              {status.requestId !== null && (
                <small className="form__meta">
                  request_id: <code>{status.requestId}</code>
                </small>
              )}
            </div>
          )}

          <div className="form__actions">
            <button
              type="submit"
              className="button button--primary"
              disabled={submitting || userId.trim().length < 3 || passphrase.length === 0}
            >
              {submitLabel}
            </button>
            <Link className="button button--ghost" to="/register">
              Create account
            </Link>
          </div>
        </form>

        <p className="auth-card__alt">
          New here? <Link to="/register">Create an account</Link>.
        </p>
      </section>
    </div>
  );
}

function mapError(err: unknown): { kind: 'error'; message: string; requestId: string | null } {
  if (err instanceof IdentityError) {
    return { kind: 'error', message: err.message, requestId: null };
  }
  if (err instanceof ApiError) {
    if (err.status === 401) {
      return {
        kind: 'error',
        message: 'Authentication failed. Wrong passphrase or mismatched identity.',
        requestId: err.requestId,
      };
    }
    if (err.status === 404) {
      return {
        kind: 'error',
        message: 'Unknown user. Register first.',
        requestId: err.requestId,
      };
    }
    if (err.status === 429) {
      return {
        kind: 'error',
        message: 'Too many attempts. Please wait and try again.',
        requestId: err.requestId,
      };
    }
    return {
      kind: 'error',
      message: err.message,
      requestId: err.requestId,
    };
  }
  const message = err instanceof Error ? err.message : 'Sign in failed.';
  return { kind: 'error', message, requestId: null };
}

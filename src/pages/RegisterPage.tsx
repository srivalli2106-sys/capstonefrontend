/**
 * Register page.
 *
 * Phase 3 flow:
 *   1. User chooses a user_id.
 *   2. User chooses a passphrase (and confirms).
 *   3. The frontend generates a real Ed25519 keypair locally.
 *   4. The public key (64 hex chars) is sent to POST /auth/register.
 *   5. On backend success, the private seed is encrypted with a PBKDF2 key
 *      derived from the passphrase, persisted in IndexedDB, and the user
 *      is logged in via PoP challenge/verify.
 *   6. On any failure the local record is wiped before throwing.
 */

import type { FormEvent, JSX } from 'react';
import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ApiError } from '../api/http';
import { authController, IdentityError } from '../auth/AuthController';

type Status =
  | { kind: 'idle' }
  | { kind: 'generating' }
  | { kind: 'submitting' }
  | { kind: 'success'; message: string }
  | { kind: 'error'; message: string; requestId: string | null };

export function RegisterPage(): JSX.Element {
  const navigate = useNavigate();
  const [userId, setUserId] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [passphraseConfirm, setPassphraseConfirm] = useState('');
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
    setStatus({ kind: 'generating' });
    try {
      await authController.register(userId, passphrase, passphraseConfirm);
      setStatus({
        kind: 'success',
        message: 'Identity created. Signed in.',
      });
      window.setTimeout(() => navigate('/chat', { replace: true }), 400);
    } catch (err) {
      const mapped = mapError(err);
      setStatus(mapped);
    }
  }

  const submitting = status.kind === 'generating' || status.kind === 'submitting';
  const disabled =
    submitting ||
    userId.trim().length < 3 ||
    passphrase.length < 8 ||
    passphrase !== passphraseConfirm;

  return (
    <section className="page page--register">
      <h1>Create account</h1>
      <p className="page__lede">
        Your identity is generated on this device. The private key never leaves
        the browser; it is encrypted with a passphrase you choose and stored
        locally in IndexedDB. There is no recovery: lose the passphrase and
        lose the account.
      </p>

      <form className="form" onSubmit={handleSubmit} noValidate>
        <label className="form__field">
          <span className="form__label">user_id</span>
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
          />
          <small className="form__hint">3 to 64 characters. One-time per identity.</small>
          {hasLocal === true && (
            <small className="form__hint form__hint--warn">
              A local identity for this user_id already exists on this device.
              Re-registering will overwrite the local record (you may need to
              wipe the server-side account first).
            </small>
          )}
        </label>

        <label className="form__field">
          <span className="form__label">Identity passphrase</span>
          <input
            className="form__input"
            type="password"
            name="passphrase"
            autoComplete="new-password"
            minLength={8}
            required
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            disabled={submitting}
          />
          <small className="form__hint">At least 8 characters.</small>
        </label>

        <label className="form__field">
          <span className="form__label">Confirm passphrase</span>
          <input
            className="form__input"
            type="password"
            name="passphrase_confirm"
            autoComplete="new-password"
            minLength={8}
            required
            value={passphraseConfirm}
            onChange={(e) => setPassphraseConfirm(e.target.value)}
            disabled={submitting}
          />
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
        {status.kind === 'success' && (
          <div className="form__success" role="status">
            {status.message}
          </div>
        )}

        <div className="form__actions">
          <button
            type="submit"
            className="button button--primary"
            disabled={disabled}
          >
            {status.kind === 'generating'
              ? 'Generating identity…'
              : status.kind === 'submitting'
                ? 'Submitting…'
                : 'Register'}
          </button>
          <Link className="button" to="/login">
            Back to sign in
          </Link>
        </div>
      </form>
    </section>
  );
}

function mapError(err: unknown): { kind: 'error'; message: string; requestId: string | null } {
  if (err instanceof ApiError) {
    if (err.status === 409) {
      return {
        kind: 'error',
        message: 'That user_id is already registered with the server.',
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
  if (err instanceof IdentityError) {
    return { kind: 'error', message: err.message, requestId: null };
  }
  const message = err instanceof Error ? err.message : 'Registration failed.';
  return { kind: 'error', message, requestId: null };
}
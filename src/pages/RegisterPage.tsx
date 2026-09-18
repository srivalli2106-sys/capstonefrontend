/**
 * Register page.
 *
 * Phase 2 generates a 32-byte random placeholder (NOT an Ed25519 key) for the
 * `ik_public` field, so the form can complete registration against the
 * deployed backend without any cryptographic primitives. Phase 3 replaces the
 * placeholder with a real Ed25519 keypair generated via Web Crypto / noble
 * curves and persists the private half in an encrypted local store.
 *
 * After a successful registration we redirect to /login because the backend
 * register endpoint does NOT issue a token — the user must complete the
 * challenge/verify PoP flow (Phase 3) to obtain one.
 */

import type { FormEvent, JSX } from 'react';
import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ApiError } from '../api/http';
import { authController } from '../auth/AuthController';

type Status =
  | { kind: 'idle' }
  | { kind: 'submitting' }
  | { kind: 'success'; message: string }
  | { kind: 'error'; message: string; requestId: string | null };

export function RegisterPage(): JSX.Element {
  const navigate = useNavigate();
  const [userId, setUserId] = useState('');
  const [ikPublic, setIkPublic] = useState('');
  const [status, setStatus] = useState<Status>({ kind: 'idle' });

  useEffect(() => {
    setIkPublic(authController.generatePlaceholderIkPublic());
  }, []);

  async function handleSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setStatus({ kind: 'submitting' });
    try {
      await authController.register(userId, ikPublic);
      setStatus({
        kind: 'success',
        message: 'Registration complete. Please sign in.',
      });
      window.setTimeout(() => navigate('/login', { replace: true }), 600);
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 409) {
          setStatus({
            kind: 'error',
            message: 'That user_id is already registered.',
            requestId: err.requestId,
          });
          return;
        }
        if (err.status === 429) {
          setStatus({
            kind: 'error',
            message: 'Too many attempts. Please wait and try again.',
            requestId: err.requestId,
          });
          return;
        }
        setStatus({
          kind: 'error',
          message: err.message,
          requestId: err.requestId,
        });
        return;
      }
      const message =
        err instanceof Error ? err.message : 'Registration failed.';
      setStatus({ kind: 'error', message, requestId: null });
    }
  }

  function regeneratePlaceholder(): void {
    setIkPublic(authController.generatePlaceholderIkPublic());
  }

  return (
    <section className="page page--register">
      <h1>Create account</h1>
      <p className="page__lede">
        Registration is one-time per user_id. The backend issues no token at
        registration — you will be redirected to the sign-in page, which in
        Phase 2 uses the development login and in Phase 3 will use the
        Ed25519 challenge/verify flow.
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
            disabled={status.kind === 'submitting'}
          />
          <small className="form__hint">3 to 64 characters.</small>
        </label>

        <label className="form__field">
          <span className="form__label">ik_public (hex)</span>
          <div className="form__row">
            <input
              className="form__input form__input--mono"
              type="text"
              name="ik_public"
              value={ikPublic}
              readOnly
              spellCheck={false}
            />
            <button
              type="button"
              className="button"
              onClick={regeneratePlaceholder}
              disabled={status.kind === 'submitting'}
            >
              Regenerate
            </button>
          </div>
          <small className="form__hint">
            Phase 2 placeholder (32 random bytes). Phase 3 will replace this
            with a real Ed25519 public key generated on this device.
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
        {status.kind === 'success' && (
          <div className="form__success" role="status">
            {status.message}
          </div>
        )}

        <div className="form__actions">
          <button
            type="submit"
            className="button button--primary"
            disabled={
              status.kind === 'submitting' || userId.trim().length < 3
            }
          >
            {status.kind === 'submitting' ? 'Registering…' : 'Register'}
          </button>
          <Link className="button" to="/login">
            Back to sign in
          </Link>
        </div>
      </form>
    </section>
  );
}
/**
 * Login page.
 *
 * Phase 2 submits to the backend's dev-only `/auth/login` endpoint. This
 * endpoint returns 403 in production deployments (verified by
 * `tests/test_auth_routes.py::test_login_disabled_in_production`), so the UI
 * surfaces a clear message when that happens.
 *
 * Phase 3 replaces this with the Ed25519 challenge/verify PoP flow.
 */

import type { FormEvent, JSX } from 'react';
import { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { ApiError } from '../api/http';
import { authController } from '../auth/AuthController';

type Status =
  | { kind: 'idle' }
  | { kind: 'submitting' }
  | { kind: 'error'; message: string; requestId: string | null };

export function LoginPage(): JSX.Element {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const next = params.get('next') ?? '/chat';

  const [userId, setUserId] = useState('');
  const [status, setStatus] = useState<Status>({ kind: 'idle' });

  async function handleSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setStatus({ kind: 'submitting' });
    try {
      await authController.login(userId);
      navigate(decodeURIComponent(next), { replace: true });
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 403) {
          setStatus({
            kind: 'error',
            message:
              'Password-less login is disabled in this deployment. Proof-of-possession login will be enabled in Phase 3.',
            requestId: err.requestId,
          });
          return;
        }
        if (err.status === 404) {
          setStatus({
            kind: 'error',
            message: 'Unknown user. Register first.',
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
      const message = err instanceof Error ? err.message : 'Login failed.';
      setStatus({ kind: 'error', message, requestId: null });
    }
  }

  return (
    <section className="page page--login">
      <h1>Sign in</h1>
      <p className="page__lede">
        Enter your user_id. Phase 2 uses the backend development login; Phase 3
        switches to the Ed25519 challenge/verify flow.
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
            disabled={status.kind === 'submitting' || userId.trim().length < 3}
          >
            {status.kind === 'submitting' ? 'Signing in…' : 'Sign in'}
          </button>
          <Link className="button" to="/register">
            Create account
          </Link>
        </div>
      </form>
    </section>
  );
}
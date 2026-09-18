/**
 * Settings page.
 *
 * Phase 2: minimal auth-state surface (current user_id, token expiry,
 * logout). Additional settings (identity backup, key export) arrive in
 * Phase 3+.
 */

import type { JSX } from 'react';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ApiError } from '../api/http';
import { authController } from '../auth/AuthController';
import { useAuth } from '../hooks/useAuth';

type LogoutStatus =
  | { kind: 'idle' }
  | { kind: 'submitting' }
  | { kind: 'error'; message: string; requestId: string | null };

export function SettingsPage(): JSX.Element {
  const { userId, exp } = useAuth();
  const navigate = useNavigate();
  const [logoutStatus, setLogoutStatus] = useState<LogoutStatus>({
    kind: 'idle',
  });

  async function handleLogout(): Promise<void> {
    setLogoutStatus({ kind: 'submitting' });
    try {
      await authController.logout();
      navigate('/', { replace: true });
    } catch (err) {
      if (err instanceof ApiError) {
        setLogoutStatus({
          kind: 'error',
          message: err.message,
          requestId: err.requestId,
        });
        return;
      }
      const message = err instanceof Error ? err.message : 'Logout failed.';
      setLogoutStatus({ kind: 'error', message, requestId: null });
    }
  }

  const expiryText =
    exp === null
      ? 'unknown'
      : new Date(exp * 1000).toLocaleString(undefined, {
          dateStyle: 'medium',
          timeStyle: 'short',
        });

  return (
    <section className="page page--settings">
      <h1>Settings</h1>
      <p className="page__lede">
        Minimal session surface for Phase 2. Identity management, key export,
        and passphrase-protected local backup will be added in Phase 3.
      </p>

      <dl className="settings-list">
        <div className="settings-list__row">
          <dt>user_id</dt>
          <dd>
            <code>{userId ?? '—'}</code>
          </dd>
        </div>
        <div className="settings-list__row">
          <dt>token expiry</dt>
          <dd>{expiryText}</dd>
        </div>
      </dl>

      {logoutStatus.kind === 'error' && (
        <div className="form__error" role="alert">
          <span>{logoutStatus.message}</span>
          {logoutStatus.requestId !== null && (
            <small className="form__meta">
              request_id: <code>{logoutStatus.requestId}</code>
            </small>
          )}
        </div>
      )}

      <div className="form__actions">
        <button
          type="button"
          className="button"
          onClick={handleLogout}
          disabled={logoutStatus.kind === 'submitting'}
        >
          {logoutStatus.kind === 'submitting' ? 'Signing out…' : 'Sign out'}
        </button>
      </div>
    </section>
  );
}
/**
 * Settings page.
 *
 * Surfaces existing-only state in user-facing terms:
 *  - JWT session info (user_id, expiry).
 *  - Local identity status (locked/unlocked) + inline unlock UI.
 *  - Lock / wipe / sign-out actions.
 *
 * No raw or truncated cryptographic key material is displayed.
 */

import type { FormEvent, JSX } from 'react';
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ApiError } from '../api/http';
import { authController } from '../auth/AuthController';
import { useAuth } from '../hooks/useAuth';

type Action =
  | { kind: 'idle' }
  | { kind: 'logout' }
  | { kind: 'lock' }
  | { kind: 'wipe' };

export function SettingsPage(): JSX.Element {
  const { authenticated, userId, exp, identity } = useAuth();
  const navigate = useNavigate();
  const [action, setAction] = useState<Action>({ kind: 'idle' });
  const [error, setError] = useState<{ message: string; requestId: string | null } | null>(null);
  const [showUnlockForm, setShowUnlockForm] = useState(false);
  const [unlockPassphrase, setUnlockPassphrase] = useState('');
  const [unlocking, setUnlocking] = useState(false);

  // Collapse the unlock form whenever the identity becomes unlocked (e.g.
  // after a successful submission) so the UI cleanly returns to its
  // post-unlock state without a manual refresh.
  useEffect(() => {
    if (identity.kind === 'unlocked') {
      setShowUnlockForm(false);
      setUnlockPassphrase('');
      setUnlocking(false);
      setError(null);
    }
  }, [identity.kind]);

  async function performLogout(): Promise<void> {
    setAction({ kind: 'logout' });
    setError(null);
    try {
      await authController.logout();
      navigate('/', { replace: true });
    } catch (err) {
      if (err instanceof ApiError) {
        setError({ message: err.message, requestId: err.requestId });
        return;
      }
      const message = err instanceof Error ? err.message : 'Sign out failed.';
      setError({ message, requestId: null });
    } finally {
      setAction({ kind: 'idle' });
    }
  }

  async function performLock(): Promise<void> {
    setAction({ kind: 'lock' });
    setError(null);
    authController.lockIdentity();
    setAction({ kind: 'idle' });
  }

  async function performUnlock(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (userId === null) return;
    setError(null);
    setUnlocking(true);
    try {
      await authController.unlock(userId, unlockPassphrase);
      // useEffect on identity.kind will collapse the form + clear state.
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unlock failed.';
      setError({ message, requestId: null });
    } finally {
      setUnlocking(false);
    }
  }

  function cancelUnlock(): void {
    setShowUnlockForm(false);
    setUnlockPassphrase('');
    setError(null);
  }

  async function performWipe(): Promise<void> {
    if (userId === null) return;
    if (
      !window.confirm(
        'Wipe the local encrypted identity for this user_id? You will not be able to log in on this device until you re-register. The server-side account is NOT deleted.',
      )
    ) {
      return;
    }
    setAction({ kind: 'wipe' });
    setError(null);
    try {
      await authController.wipeLocalIdentity(userId);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Wipe failed.';
      setError({ message, requestId: null });
    } finally {
      setAction({ kind: 'idle' });
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
    <div className="page page--settings">
      <h1>Settings</h1>
      <p className="page__lede">
        Manage the local session and the device-stored encrypted identity.
      </p>

      <section className="card" aria-labelledby="settings-session">
        <header className="card__header">
          <div>
            <h2 id="settings-session" className="card__title">Session</h2>
            <p className="card__subtitle">Authentication token currently held by this device.</p>
          </div>
        </header>
        <dl className="settings-list">
          <div className="settings-list__row">
            <dt>User identifier</dt>
            <dd><code>{userId ?? '—'}</code></dd>
          </div>
          <div className="settings-list__row">
            <dt>Authenticated</dt>
            <dd>
              <span className={'pill ' + (authenticated ? 'pill--success' : 'pill--warning')}>
                {authenticated ? 'Yes' : 'No'}
              </span>
            </dd>
          </div>
          <div className="settings-list__row">
            <dt>Token expiry</dt>
            <dd>{expiryText}</dd>
          </div>
        </dl>
      </section>

      <section className="card" style={{ marginTop: 'var(--space-5)' }} aria-labelledby="settings-identity">
        <header className="card__header">
          <div>
            <h2 id="settings-identity" className="card__title">Identity</h2>
            <p className="card__subtitle">Your cryptographic identity, stored encrypted on this device.</p>
          </div>
        </header>
        <dl className="settings-list">
          <div className="settings-list__row">
            <dt>Identity key</dt>
            <dd>
              <div className="settings-identity-status">
                <span className={'pill ' + (identity.kind === 'unlocked' ? 'pill--success' : 'pill--warning')}>
                  {identity.kind === 'unlocked' ? 'Unlocked' : 'Locked'}
                </span>
                {identity.kind === 'locked' && !showUnlockForm && (
                  <button
                    type="button"
                    className="button button--small"
                    onClick={() => {
                      setError(null);
                      setShowUnlockForm(true);
                    }}
                    disabled={userId === null}
                    data-testid="unlock-identity-button"
                    aria-label="Unlock identity"
                  >
                    Unlock Identity
                  </button>
                )}
              </div>
            </dd>
          </div>
        </dl>

        {identity.kind === 'locked' && showUnlockForm && (
          <form
            className="settings-unlock-form"
            onSubmit={performUnlock}
            data-testid="unlock-identity-form"
            aria-labelledby="settings-identity-unlock"
          >
            <h3 id="settings-identity-unlock" className="settings-unlock-form__title">
              Unlock your identity
            </h3>
            <p className="settings-unlock-form__hint">
              Enter the passphrase you set when you registered. It is used to decrypt
              the local device keys on this device only; it is never sent to the
              server.
            </p>
            <div className="form__field">
              <label htmlFor="settings-unlock-passphrase" className="form__label">
                Passphrase
              </label>
              <input
                id="settings-unlock-passphrase"
                className="form__input"
                type="password"
                autoComplete="current-password"
                required
                value={unlockPassphrase}
                onChange={(e) => setUnlockPassphrase(e.target.value)}
                placeholder="Enter passphrase"
                disabled={unlocking}
                aria-label="Identity passphrase"
                data-testid="unlock-identity-passphrase"
              />
            </div>
            {error !== null && (
              <div className="form__error" role="alert" data-testid="unlock-identity-error">
                <span>{error.message}</span>
              </div>
            )}
            <div className="form__actions">
              <button
                type="submit"
                className="button button--primary"
                disabled={unlocking || unlockPassphrase.length === 0}
                data-testid="unlock-identity-submit"
              >
                {unlocking ? 'Unlocking…' : 'Unlock'}
              </button>
              <button
                type="button"
                className="button button--ghost"
                onClick={cancelUnlock}
                disabled={unlocking}
                data-testid="unlock-identity-cancel"
              >
                Cancel
              </button>
            </div>
          </form>
        )}
      </section>

      {error !== null && (
        <div className="form__error" role="alert" style={{ marginTop: 'var(--space-5)' }}>
          <span>{error.message}</span>
          {error.requestId !== null && (
            <small className="form__meta">
              request_id: <code>{error.requestId}</code>
            </small>
          )}
        </div>
      )}

      <section className="card" style={{ marginTop: 'var(--space-5)' }} aria-labelledby="settings-actions">
        <header className="card__header">
          <div>
            <h2 id="settings-actions" className="card__title">Actions</h2>
            <p className="card__subtitle">Lock the in-memory identity, unlock it with your passphrase, or sign out.</p>
          </div>
        </header>

        <div className="form__actions" style={{ marginTop: 'var(--space-4)' }}>
          {identity.kind === 'unlocked' && (
            <button
              type="button"
              className="button"
              onClick={performLock}
              disabled={action.kind !== 'idle'}
              data-testid="lock-identity"
            >
              {action.kind === 'lock' ? 'Locking…' : 'Lock identity'}
            </button>
          )}

          <button
            type="button"
            className="button"
            onClick={performWipe}
            disabled={action.kind !== 'idle' || identity.kind === 'none'}
            data-testid="wipe-identity"
          >
            {action.kind === 'wipe' ? 'Wiping…' : 'Wipe local identity'}
          </button>

          <button
            type="button"
            className="button button--danger"
            onClick={performLogout}
            disabled={!authenticated || action.kind !== 'idle'}
            data-testid="sign-out"
          >
            {action.kind === 'logout' ? 'Signing out…' : 'Sign out'}
          </button>
        </div>
      </section>

      <p className="page__meta">
        Private keys and message content are never accessible to the server.
        Wiping the local identity does not delete the server-side account.
      </p>
    </div>
  );
}

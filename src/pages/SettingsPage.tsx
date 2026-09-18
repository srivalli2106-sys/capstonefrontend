/**
 * Settings page.
 *
 * Surfaces existing-only state:
 *  - JWT session info (user_id, expiry).
 *  - Local identity info (public key short id, locked/unlocked).
 *  - Lock identity (drops the in-memory seed; JWT untouched).
 *  - Unlock identity (asks for passphrase; only available when the JWT
 *    user_id matches the stored local identity).
 *  - Sign out (revokes the JWT via /auth/logout, clears session, locks
 *    identity, optionally wipes the local record on explicit confirmation).
 */

import type { FormEvent, JSX } from 'react';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ApiError } from '../api/http';
import { authController } from '../auth/AuthController';
import { useAuth } from '../hooks/useAuth';
import { useKeyStatus } from '../hooks/useKeyStatus';

type Action =
  | { kind: 'idle' }
  | { kind: 'logout' }
  | { kind: 'lock' }
  | { kind: 'unlock'; passphrase: string }
  | { kind: 'wipe' };

export function SettingsPage(): JSX.Element {
  const { authenticated, userId, exp, identity } = useAuth();
  const keyStatus = useKeyStatus();
  const navigate = useNavigate();
  const [action, setAction] = useState<Action>({ kind: 'idle' });
  const [error, setError] = useState<{ message: string; requestId: string | null } | null>(null);
  const [unlockPassphrase, setUnlockPassphrase] = useState('');

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
    setAction({ kind: 'unlock', passphrase: unlockPassphrase });
    setError(null);
    try {
      await authController.unlock(userId, unlockPassphrase);
      setUnlockPassphrase('');
      setAction({ kind: 'idle' });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unlock failed.';
      setError({ message, requestId: null });
      setAction({ kind: 'idle' });
    }
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
    <div className="page">
      <h1>Settings</h1>
      <p className="page__lede">
        Manage the local session and the device-stored encrypted identity.
      </p>

      <section className="card" aria-labelledby="settings-session">
        <header className="card__header">
          <div>
            <h2 id="settings-session" className="card__title">Session</h2>
            <p className="card__subtitle">Backend authentication token currently held by this device.</p>
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
            <p className="card__subtitle">Local cryptographic identity, stored encrypted in IndexedDB.</p>
          </div>
        </header>
        <dl className="settings-list">
          <div className="settings-list__row">
            <dt>Status</dt>
            <dd>
              <span className={
                'pill ' +
                (identity.kind === 'unlocked' ? 'pill--success' :
                 identity.kind === 'locked' ? 'pill--warning' : '')
              }>
                {identityLabel(identity)}
              </span>
            </dd>
          </div>
          {identity.kind !== 'none' && (
            <div className="settings-list__row">
              <dt>Identity key</dt>
              <dd>
                <code>{identity.publicKeyShortId}…</code>
                <span className="settings-list__meta">
                  {' '}(first 12 hex chars; full key is held only in memory)
                </span>
              </dd>
            </div>
          )}
        </dl>
      </section>

      {identity.kind === 'unlocked' && (
        <section className="card" style={{ marginTop: 'var(--space-5)' }} aria-labelledby="settings-keys">
          <header className="card__header">
            <div>
              <h2 id="settings-keys" className="card__title">X3DH key bundle</h2>
              <p className="card__subtitle">Short identifiers of the X25519 keys used to establish sessions.</p>
            </div>
          </header>
          {keyStatus.kind === 'not_provisioned' ? (
            <p className="muted" style={{ marginTop: 'var(--space-3)' }}>No X25519 device key material yet.</p>
          ) : (
            <>
              <dl className="settings-list">
                <div className="settings-list__row">
                  <dt>IKX (X3DH identity)</dt>
                  <dd><code>{keyStatus.local.ikxPublicHex.slice(0, 12)}…</code></dd>
                </div>
                <div className="settings-list__row">
                  <dt>SPK (signed prekey)</dt>
                  <dd><code>{keyStatus.local.spkPublicHex.slice(0, 12)}…</code></dd>
                </div>
                <div className="settings-list__row">
                  <dt>OPK (one-time prekey)</dt>
                  <dd>
                    {keyStatus.local.opkPublicHex === null
                      ? <span className="muted">none</span>
                      : <code>{keyStatus.local.opkPublicHex.slice(0, 12)}…</code>}
                  </dd>
                </div>
              </dl>
              {keyStatus.kind === 'upload_blocked' && (
                <div className="form__error" role="alert" style={{ marginTop: 'var(--space-4)' }}>
                  <span>{keyStatus.reason}</span>
                </div>
              )}
            </>
          )}
        </section>
      )}

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
            >
              {action.kind === 'lock' ? 'Locking…' : 'Lock identity'}
            </button>
          )}

          {identity.kind === 'locked' && (
            <form className="form form--inline" onSubmit={performUnlock}>
              <div className="form__row">
                <input
                  className="form__input"
                  type="password"
                  autoComplete="current-password"
                  required
                  value={unlockPassphrase}
                  onChange={(e) => setUnlockPassphrase(e.target.value)}
                  placeholder="Passphrase"
                  disabled={action.kind !== 'idle'}
                  aria-label="Identity passphrase"
                />
                <button
                  type="submit"
                  className="button button--primary"
                  disabled={action.kind !== 'idle' || unlockPassphrase.length === 0}
                >
                  {action.kind === 'unlock' ? 'Unlocking…' : 'Unlock'}
                </button>
              </div>
            </form>
          )}

          <button
            type="button"
            className="button"
            onClick={performWipe}
            disabled={action.kind !== 'idle' || identity.kind === 'none'}
          >
            {action.kind === 'wipe' ? 'Wiping…' : 'Wipe local identity'}
          </button>

          <button
            type="button"
            className="button button--danger"
            onClick={performLogout}
            disabled={!authenticated || action.kind !== 'idle'}
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

function identityLabel(
  identity: ReturnType<typeof useAuth>['identity'],
): string {
  switch (identity.kind) {
    case 'none':
      return 'no local identity';
    case 'locked':
      return `locked (user ${identity.userId})`;
    case 'unlocked':
      return `unlocked (user ${identity.userId})`;
  }
}

/**
 * Settings page.
 *
 * Phase 3 surfaces:
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
    <section className="page page--settings">
      <h1>Settings</h1>
      <p className="page__lede">
        Manage the local session and the device-stored encrypted identity.
      </p>

      <h2 className="page__h2">Session</h2>
      <dl className="settings-list">
        <div className="settings-list__row">
          <dt>user_id</dt>
          <dd>
            <code>{userId ?? '—'}</code>
          </dd>
        </div>
        <div className="settings-list__row">
          <dt>authenticated</dt>
          <dd>{authenticated ? 'yes' : 'no'}</dd>
        </div>
        <div className="settings-list__row">
          <dt>token expiry</dt>
          <dd>{expiryText}</dd>
        </div>
      </dl>

      <h2 className="page__h2">Local identity</h2>
      <dl className="settings-list">
        <div className="settings-list__row">
          <dt>status</dt>
          <dd>{identityLabel(identity)}</dd>
        </div>
        {identity.kind !== 'none' && (
          <div className="settings-list__row">
            <dt>ik_public</dt>
            <dd>
              <code>{identity.publicKeyShortId}…</code>
              <span className="settings-list__meta">
                {' '}(first 12 hex chars; full key is held only in memory)
              </span>
            </dd>
          </div>
        )}
      </dl>

      <h2 className="page__h2">X3DH key bundle</h2>
      {identity.kind !== 'unlocked' ? (
        <p className="page__lede">Unlock your identity to view device keys.</p>
      ) : keyStatus.kind === 'not_provisioned' ? (
        <p className="page__lede">No X25519 device key material yet.</p>
      ) : (
        <>
          <dl className="settings-list">
            <div className="settings-list__row">
              <dt>IKX (X3DH identity)</dt>
              <dd>
                <code>{keyStatus.local.ikxPublicHex.slice(0, 12)}…</code>
              </dd>
            </div>
            <div className="settings-list__row">
              <dt>SPK (signed prekey)</dt>
              <dd>
                <code>{keyStatus.local.spkPublicHex.slice(0, 12)}…</code>
              </dd>
            </div>
            <div className="settings-list__row">
              <dt>OPK (one-time prekey)</dt>
              <dd>
                {keyStatus.local.opkPublicHex === null
                  ? 'none'
                  : `${keyStatus.local.opkPublicHex.slice(0, 12)}…`}
              </dd>
            </div>
          </dl>
          {keyStatus.kind === 'upload_blocked' && (
            <div className="form__error" role="alert">
              <span>{keyStatus.reason}</span>
            </div>
          )}
        </>
      )}

      {error !== null && (
        <div className="form__error" role="alert">
          <span>{error.message}</span>
          {error.requestId !== null && (
            <small className="form__meta">
              request_id: <code>{error.requestId}</code>
            </small>
          )}
        </div>
      )}

      <div className="form__actions">
        {identity.kind === 'unlocked' && (
          <button
            type="button"
            className="button"
            onClick={performLock}
            disabled={action.kind !== 'idle'}
          >
            Lock identity
          </button>
        )}
        {identity.kind === 'locked' && (
          <form className="form form--inline" onSubmit={performUnlock}>
            <label className="form__field">
              <span className="form__label">Passphrase to unlock</span>
              <div className="form__row">
                <input
                  className="form__input"
                  type="password"
                  autoComplete="current-password"
                  required
                  value={unlockPassphrase}
                  onChange={(e) => setUnlockPassphrase(e.target.value)}
                  disabled={action.kind !== 'idle'}
                />
                <button
                  type="submit"
                  className="button button--primary"
                  disabled={
                    action.kind !== 'idle' || unlockPassphrase.length === 0
                  }
                >
                  {action.kind === 'unlock' ? 'Unlocking…' : 'Unlock'}
                </button>
              </div>
            </label>
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
          className="button"
          onClick={performLogout}
          disabled={!authenticated || action.kind !== 'idle'}
        >
          {action.kind === 'logout' ? 'Signing out…' : 'Sign out'}
        </button>
      </div>
    </section>
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
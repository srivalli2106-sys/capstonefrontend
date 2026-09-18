import type { JSX } from 'react';
import { Link } from 'react-router-dom';
import { HealthStatus } from '../components/HealthStatus';
import { useAuth } from '../hooks/useAuth';

export function HomePage(): JSX.Element {
  const { authenticated, userId, identity } = useAuth();

  return (
    <section className="page page--home">
      <h1>Secure Messaging</h1>
      {authenticated ? (
        <>
          <p className="page__lede">
            Signed in as <code>{userId}</code>. Local identity:{' '}
            <strong>{identityLabel(identity)}</strong>.
          </p>
          <div className="page__actions">
            <Link className="button button--primary" to="/chat">
              Open chat
            </Link>
            <Link className="button" to="/settings">
              Settings
            </Link>
          </div>
        </>
      ) : (
        <>
          <p className="page__lede">
            End-to-end encrypted messaging client. Backend integration pending future phases.
          </p>
          <div className="page__actions">
            <Link className="button button--primary" to="/login">
              Sign in
            </Link>
            <Link className="button" to="/register">
              Create account
            </Link>
          </div>
        </>
      )}

      <HealthStatus />
    </section>
  );
}

function identityLabel(
  identity: ReturnType<typeof useAuth>['identity'],
): string {
  switch (identity.kind) {
    case 'none':
      return 'none on this device';
    case 'locked':
      return 'locked (passphrase required)';
    case 'unlocked':
      return 'unlocked';
  }
}
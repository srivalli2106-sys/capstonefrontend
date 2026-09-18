import type { JSX } from 'react';
import { Link } from 'react-router-dom';
import { HealthStatus } from '../components/HealthStatus';
import { useAuth } from '../hooks/useAuth';

export function HomePage(): JSX.Element {
  const { authenticated, userId } = useAuth();

  return (
    <section className="page page--home">
      <h1>Secure Messaging</h1>
      {authenticated ? (
        <p className="page__lede">
          Signed in as <code>{userId}</code>.
        </p>
      ) : (
        <p className="page__lede">
          End-to-end encrypted messaging client. Backend integration pending future phases.
        </p>
      )}

      {!authenticated && (
        <div className="page__actions">
          <Link className="button button--primary" to="/login">
            Sign in
          </Link>
          <Link className="button" to="/register">
            Create account
          </Link>
        </div>
      )}

      {authenticated && (
        <div className="page__actions">
          <Link className="button button--primary" to="/chat">
            Open chat
          </Link>
          <Link className="button" to="/settings">
            Settings
          </Link>
        </div>
      )}

      <HealthStatus />
    </section>
  );
}
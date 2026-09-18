import type { JSX } from 'react';
import { Link } from 'react-router-dom';
import { HealthStatus } from '../components/HealthStatus';

export function HomePage(): JSX.Element {
  return (
    <section className="page page--home">
      <h1>Secure Messaging</h1>
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

      <HealthStatus />
    </section>
  );
}
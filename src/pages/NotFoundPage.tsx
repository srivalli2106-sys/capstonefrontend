import type { JSX } from 'react';
import { Link } from 'react-router-dom';

export function NotFoundPage(): JSX.Element {
  return (
    <div className="page page--narrow">
      <section className="not-found" aria-labelledby="not-found-title">
        <div className="not-found__code" aria-hidden="true">404</div>
        <h1 id="not-found-title" className="not-found__title">Page not found</h1>
        <p className="not-found__body">
          The page you’re looking for doesn’t exist or has been moved.
        </p>
        <div className="form__actions" style={{ marginTop: 'var(--space-4)' }}>
          <Link className="button button--primary" to="/">Back to home</Link>
          <Link className="button" to="/chat">Open chat</Link>
        </div>
      </section>
    </div>
  );
}

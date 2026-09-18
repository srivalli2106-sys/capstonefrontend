import { Link } from 'react-router-dom';

export function NotFoundPage(): JSX.Element {
  return (
    <section className="page page--not-found">
      <h1>404</h1>
      <p className="page__lede">That page does not exist.</p>
      <p>
        <Link to="/">Back to home</Link>
      </p>
    </section>
  );
}
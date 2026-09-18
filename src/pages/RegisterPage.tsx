import { Link } from 'react-router-dom';

export function RegisterPage(): JSX.Element {
  return (
    <section className="page page--register">
      <h1>Create account</h1>
      <p className="page__lede">
        Registration will be implemented in a later phase. The current foundation only wires
        the route and the application shell.
      </p>
      <p>
        <Link to="/">Back to home</Link>
      </p>
    </section>
  );
}
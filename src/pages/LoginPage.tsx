import { Link } from 'react-router-dom';

export function LoginPage(): JSX.Element {
  return (
    <section className="page page--login">
      <h1>Sign in</h1>
      <p className="page__lede">
        Authentication will be implemented in a later phase. The current foundation only wires
        the route and the application shell.
      </p>
      <p>
        <Link to="/">Back to home</Link>
      </p>
    </section>
  );
}
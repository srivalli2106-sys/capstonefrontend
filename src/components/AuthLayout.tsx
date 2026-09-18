import type { JSX, ReactNode } from 'react';

interface AuthLayoutProps {
  children: ReactNode;
}

/**
 * AuthLayout - centered authentication container.
 *
 * Desktop: a single grid container holds the product/security introduction
 * on the left and the auth form on the right. Both columns are vertically
 * centered. The navbar already carries the Secure Messaging wordmark, so
 * this shell does not duplicate it.
 */
export function AuthLayout({ children }: AuthLayoutProps): JSX.Element {
  return (
    <div className="auth-layout">
      <div className="auth-layout__intro" aria-label="About Secure Messaging">
        <h1 className="auth-layout__headline">
          Private messaging for the web.
        </h1>
        <p className="auth-layout__lede">
          Your identity is created on this device. Messages are
          encrypted before they are sent.
        </p>

        <ul className="auth-layout__points" aria-label="Product properties">
          <li>Encrypted before transmission</li>
          <li>Identity keys stay on the device</li>
          <li>One-to-one conversations</li>
        </ul>
      </div>

      <div className="auth-layout__panel" aria-label="Authentication">
        {children}
      </div>
    </div>
  );
}

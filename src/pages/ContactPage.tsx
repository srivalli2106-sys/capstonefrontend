/**
 * ContactPage - support and contact information.
 *
 * Two-column layout on desktop: categories on the left, project links
 * on the right. No fake email address is invented.
 */

import type { JSX } from 'react';
import { Link } from 'react-router-dom';

export function ContactPage(): JSX.Element {
  return (
    <article className="page page--content-wide content-page">
      <header className="content-page__header">
        <p className="content-page__eyebrow">Support</p>
        <h1>Contact and support</h1>
        <p className="content-page__lede">
          Help with Secure Messaging.
        </p>
      </header>

      <div className="contact-layout">
        <div className="contact-layout__intro">
          <section className="content-page__section">
            <h2>Support channel</h2>
            <p>
              Need help with Secure Messaging? For product or technical
              support, use the support channel provided with your
              deployment.
            </p>
            <p>
              When you contact support, include the user identifier you
              signed in with, the approximate time of the issue, and a
              short description. Do not include your passphrase, identity
              keys, or message content. Support does not need them and
              cannot read encrypted messages.
            </p>
          </section>

          <section className="content-page__section contact-layout__topics">
            <h2>Common topics</h2>
            <dl className="content-page__dl">
              <dt>Account and sign in</dt>
              <dd>
                Sign-in problems, identity unlock issues, session problems.
              </dd>

              <dt>Identity and security</dt>
              <dd>
                Lost passphrase, suspicious activity, security concerns.
              </dd>

              <dt>Messaging</dt>
              <dd>
                Messages not sending, connection problems, conversation
                issues.
              </dd>

              <dt>Technical issues</dt>
              <dd>
                Browser problems, service availability, other application
                issues.
              </dd>
            </dl>
          </section>

          <section className="content-page__section">
            <h2>What support can and cannot do</h2>
            <p>
              Support can help with the client, the service, and account
              management. Support cannot recover a passphrase, read
              message content, or see encrypted session state. These
              properties are part of the design.
            </p>
          </section>
        </div>

        <aside className="contact-layout__aside" aria-label="Project links">
          <h3>Project</h3>
          <ul>
            <li>
              <Link to="/">Overview</Link>
            </li>
            <li>
              <Link to="/privacy">Privacy</Link>
            </li>
            <li>
              <Link to="/terms">Terms</Link>
            </li>
          </ul>

          <h3 style={{ marginTop: 'var(--space-8)' }}>Get started</h3>
          <ul>
            <li>
              <Link to="/register">Create account</Link>
            </li>
            <li>
              <Link to="/login">Sign in</Link>
            </li>
          </ul>
        </aside>
      </div>
    </article>
  );
}

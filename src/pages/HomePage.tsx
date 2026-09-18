/**
 * HomePage - public landing page.
 *
 * Short factual product copy. The detailed backend connectivity display
 * lives in settings; this page shows only a compact status indicator.
 */

import type { JSX } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { ServiceStatus } from '../components/ServiceStatus';

export function HomePage(): JSX.Element {
  const { authenticated, userId, identity } = useAuth();

  return (
    <div className="page page--content landing">
      <section className="landing__hero">
        <div>
          <span className="landing__eyebrow">Secure Messaging</span>
          <h1 className="landing__title">
            Private messaging, built for the web.
          </h1>
          <p className="landing__subtitle">
            Messages are encrypted on your device before they are sent.
            Your identity keys stay on your device. The server relays
            encrypted messages between users.
          </p>

          {authenticated ? (
            <div className="landing__ctas">
              <Link className="button button--primary button--large" to="/chat">
                Open chat
              </Link>
              <Link className="button button--large" to="/settings">
                Settings
              </Link>
            </div>
          ) : (
            <div className="landing__ctas">
              <Link className="button button--primary button--large" to="/register">
                Create account
              </Link>
              <Link className="button button--large" to="/login">
                Sign in
              </Link>
            </div>
          )}

          <ul className="landing__meta" aria-label="Product properties">
            <li>End-to-end encrypted</li>
            <li>On-device identity</li>
            <li>Browser-based</li>
          </ul>
        </div>

        <PreviewCard />
      </section>

      <section className="landing__section" aria-labelledby="features-heading">
        <header className="section-heading">
          <span className="section-heading__eyebrow">How it works</span>
          <h2 id="features-heading" className="section-heading__title">
            Messages stay between you and the recipient.
          </h2>
          <p className="section-heading__subtitle">
            Secure Messaging uses standard end-to-end encryption. The server
            sees routing information only.
          </p>
        </header>

        <div className="card-grid">
          <FeatureCard
            title="Encrypted on your device"
            body="Messages are encrypted before they leave your browser. Only the recipient can decrypt them."
            icon={<IconLock />}
          />
          <FeatureCard
            title="Identity keys stay local"
            body="Your identity key is generated on this device and protected by your passphrase. It is not sent to the server."
            icon={<IconKey />}
          />
          <FeatureCard
            title="Forward-secret sessions"
            body="Each conversation uses a per-session key chain, so a single leaked key does not expose older messages."
            icon={<IconShield />}
          />
          <FeatureCard
            title="Server only relays"
            body="The server routes opaque ciphertext between users. It cannot read message content."
            icon={<IconArrow />}
          />
        </div>
      </section>

      <section className="landing__section" aria-labelledby="how-heading">
        <header className="section-heading">
          <span className="section-heading__eyebrow">Get started</span>
          <h2 id="how-heading" className="section-heading__title">
            Three steps to a conversation.
          </h2>
        </header>

        <ol className="how-grid">
          <li className="how-step">
            <span className="how-step__count" aria-hidden="true" />
            <h3 className="how-step__title">Create an identity</h3>
            <p className="how-step__body">
              Pick a user identifier and a passphrase. The client
              generates a cryptographic identity on this device.
            </p>
          </li>
          <li className="how-step">
            <span className="how-step__count" aria-hidden="true" />
            <h3 className="how-step__title">Sign in</h3>
            <p className="how-step__body">
              Authentication uses a short-lived session token. Your
              passphrase stays on this device.
            </p>
          </li>
          <li className="how-step">
            <span className="how-step__count" aria-hidden="true" />
            <h3 className="how-step__title">Open a chat</h3>
            <p className="how-step__body">
              Open a conversation with another user. Messages you send are
              encrypted end to end.
            </p>
          </li>
        </ol>
      </section>

      <ServiceStatus />

      {authenticated ? (
        <section className="cta-banner" aria-labelledby="cta-heading">
          <div className="cta-banner__copy">
            <h2 id="cta-heading" className="cta-banner__title">
              Signed in as <code>{userId}</code>
            </h2>
            <p className="cta-banner__body">
              Identity: <strong>{identityLabel(identity)}</strong>. Open a
              conversation or review your session in Settings.
            </p>
          </div>
          <div className="cta-banner__actions">
            <Link className="button button--primary" to="/chat">Open chat</Link>
            <Link className="button" to="/settings">Settings</Link>
          </div>
        </section>
      ) : (
        <section className="cta-banner" aria-labelledby="cta-heading">
          <div className="cta-banner__copy">
            <h2 id="cta-heading" className="cta-banner__title">
              Start a private conversation.
            </h2>
            <p className="cta-banner__body">
              Create an account to begin. No phone number, email, or
              third-party sign-in is required.
            </p>
          </div>
          <div className="cta-banner__actions">
            <Link className="button button--primary" to="/register">Create account</Link>
            <Link className="button" to="/login">Sign in</Link>
          </div>
        </section>
      )}
    </div>
  );
}

function identityLabel(identity: ReturnType<typeof useAuth>['identity']): string {
  switch (identity.kind) {
    case 'none':
      return 'none on this device';
    case 'locked':
      return 'locked';
    case 'unlocked':
      return 'unlocked';
  }
}

function FeatureCard({
  title,
  body,
  icon,
}: {
  title: string;
  body: string;
  icon: JSX.Element;
}): JSX.Element {
  return (
    <article className="feature-card">
      <span className="feature-card__icon" aria-hidden="true">{icon}</span>
      <h3 className="feature-card__title">{title}</h3>
      <p className="feature-card__body">{body}</p>
    </article>
  );
}

function PreviewCard(): JSX.Element {
  return (
    <aside className="landing__visual" aria-label="Product preview (illustration)">
      <header className="landing__visual-header">
        <div className="landing__visual-meta-row">
          <span className="landing__visual-name">Example conversation</span>
          <span className="pill pill--info" aria-label="Example content">
            Illustration
          </span>
        </div>
      </header>

      <div className="landing__visual-messages">
        <div className="chat-bubble chat-bubble--in">
          <div className="chat-bubble__sender">them</div>
          <div className="chat-bubble__text">
            This is what an encrypted message looks like in the client.
          </div>
          <div className="chat-bubble__meta"><span>09:14</span></div>
        </div>
        <div className="chat-bubble chat-bubble--out">
          <div className="chat-bubble__sender">you</div>
          <div className="chat-bubble__text">
            The server only sees the encrypted version of this text.
          </div>
          <div className="chat-bubble__meta"><span>09:15</span></div>
        </div>
        <div className="chat-bubble chat-bubble--in">
          <div className="chat-bubble__sender">them</div>
          <div className="chat-bubble__text">
            Keys are generated on your device. Passphrases never leave.
          </div>
          <div className="chat-bubble__meta"><span>09:16</span></div>
        </div>
      </div>

      <footer className="landing__visual-footer">
        <span>End-to-end encrypted session</span>
      </footer>
    </aside>
  );
}

/* Inline icons - minimal stroke set, no external dependency. */

function IconLock(): JSX.Element {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="3.5" y="11" width="17" height="10" rx="2" />
      <path d="M7.5 11V7a4.5 4.5 0 0 1 9 0v4" />
    </svg>
  );
}

function IconKey(): JSX.Element {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="8" cy="14" r="4" />
      <path d="M10.8 11.2 20 2" />
      <path d="m17 5 2 2" />
      <path d="m14.5 7.5 2 2" />
    </svg>
  );
}

function IconShield(): JSX.Element {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 3 4 6v6c0 4.5 3.5 8.5 8 9 4.5-.5 8-4.5 8-9V6Z" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  );
}

function IconArrow(): JSX.Element {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M4 12h14" />
      <path d="m13 6 6 6-6 6" />
    </svg>
  );
}

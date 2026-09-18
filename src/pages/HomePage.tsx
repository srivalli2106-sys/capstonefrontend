/**
 * HomePage — landing experience.
 *
 * Public-facing marketing surface. Communicates what the product is, how
 * encryption works at a conceptual level, and provides clear sign-in /
 * sign-up CTAs. All claims are factual; nothing is fabricated.
 */

import type { JSX } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { HealthStatus } from '../components/HealthStatus';

export function HomePage(): JSX.Element {
  const { authenticated, userId, identity } = useAuth();

  return (
    <div className="landing">
      <section className="landing__hero">
        <div>
          <span className="landing__eyebrow">Private by design</span>
          <h1 className="landing__title">
            Conversations that only you and your recipient can read.
          </h1>
          <p className="landing__subtitle">
            Secure Messaging is a privacy-first client that encrypts every
            message on your device before it travels. No plaintext is stored,
            logged, or transmitted to the server.
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
                Create your account
              </Link>
              <Link className="button button--large" to="/login">
                Sign in
              </Link>
            </div>
          )}

          <ul className="landing__meta" aria-label="Product properties">
            <li>
              <span aria-hidden="true">●</span>
              End-to-end encrypted
            </li>
            <li>
              <span aria-hidden="true">●</span>
              On-device identity
            </li>
            <li>
              <span aria-hidden="true">●</span>
              Open protocol
            </li>
          </ul>
        </div>

        <PreviewCard />
      </section>

      <section aria-labelledby="features-heading" style={{ paddingTop: 'var(--space-12)' }}>
        <header className="section-heading">
          <span className="section-heading__eyebrow">Features</span>
          <h2 id="features-heading" className="section-heading__title">
            Built around the message, not the platform.
          </h2>
          <p className="section-heading__subtitle">
            Every part of the client is designed to minimise what the server
            can learn and what an attacker can recover.
          </p>
        </header>

        <div className="card-grid">
          <FeatureCard
            title="End-to-end encryption"
            body="Messages are encrypted on your device with AES-256-GCM keys that only you and your recipient hold. The server routes opaque ciphertext."
            icon={<IconLock />}
          />
          <FeatureCard
            title="On-device identity"
            body="Your identity key is generated locally, protected by your passphrase, and never leaves the browser. There is no password database to breach."
            icon={<IconKey />}
          />
          <FeatureCard
            title="Forward secrecy"
            body="Each message uses a fresh symmetric key derived from a continuously evolving chain. Compromising one key does not reveal past messages."
            icon={<IconShield />}
          />
          <FeatureCard
            title="Open cryptographic protocol"
            body="The handshake (X3DH) and the per-session ratchet are interoperable with widely-reviewed open standards."
            icon={<IconCode />}
          />
          <FeatureCard
            title="Replay protection"
            body="Out-of-order and duplicated messages are detected at the application layer; the underlying ratchet rejects stale message indices."
            icon={<IconRefresh />}
          />
          <FeatureCard
            title="No telemetry of plaintext"
            body="Plaintext messages never enter logs, browser storage, or the network. Only opaque ciphertext leaves the device."
            icon={<IconEyeOff />}
          />
        </div>
      </section>

      <section aria-labelledby="how-heading" style={{ paddingTop: 'var(--space-12)' }}>
        <header className="section-heading">
          <span className="section-heading__eyebrow">How it works</span>
          <h2 id="how-heading" className="section-heading__title">
            Three steps to a private conversation.
          </h2>
        </header>

        <ol className="how-grid">
          <li className="how-step">
            <span className="how-step__count" aria-hidden="true" />
            <h3 className="how-step__title">Create your identity</h3>
            <p className="how-step__body">
              Choose a user identifier and a passphrase. The client generates
              a cryptographic identity on your device. Only you ever hold the
              private key.
            </p>
          </li>
          <li className="how-step">
            <span className="how-step__count" aria-hidden="true" />
            <h3 className="how-step__title">Start a conversation</h3>
            <p className="how-step__body">
              Open a chat with another user. The clients perform an X3DH
              handshake to derive a shared secret without exposing private
              keys to the server.
            </p>
          </li>
          <li className="how-step">
            <span className="how-step__count" aria-hidden="true" />
            <h3 className="how-step__title">Send encrypted messages</h3>
            <p className="how-step__body">
              Each message is encrypted with a fresh ratchet key. The server
              only sees opaque, authenticated ciphertext routed to the
              recipient.
            </p>
          </li>
        </ol>
      </section>

      {authenticated ? (
        <section className="cta-banner" aria-labelledby="cta-heading">
          <div className="cta-banner__copy">
            <h2 id="cta-heading" className="cta-banner__title">
              Signed in as <code>{userId}</code>
            </h2>
            <p className="cta-banner__body">
              Local identity: <strong>{identityLabel(identity)}</strong>.
              Continue to your conversations or review your session details.
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
              Start a private conversation in under a minute.
            </h2>
            <p className="cta-banner__body">
              Create your identity, then open a chat with another user. No
              phone number, email, or third-party account required.
            </p>
          </div>
          <div className="cta-banner__actions">
            <Link className="button button--primary" to="/register">Create account</Link>
            <Link className="button" to="/login">Sign in</Link>
          </div>
        </section>
      )}

      <section style={{ paddingTop: 'var(--space-12)' }} aria-labelledby="status-heading">
        <header className="section-heading">
          <span className="section-heading__eyebrow">Service status</span>
          <h2 id="status-heading" className="section-heading__title">
            Backend connectivity
          </h2>
        </header>
        <HealthStatus />
      </section>
    </div>
  );
}

function identityLabel(identity: ReturnType<typeof useAuth>['identity']): string {
  switch (identity.kind) {
    case 'none':
      return 'none on this device';
    case 'locked':
      return 'locked (passphrase required)';
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
    <aside className="landing__visual" aria-label="Product preview">
      <div className="chat-main__header" style={{ borderBottom: 'none', padding: 0 }}>
        <div className="chat-main__title">
          <span className="chat-main__peer">alice</span>
          <span className="chat-main__subtitle">
            <span className="chat-meta-pill" data-state="open" style={{ height: '1.4rem' }}>
              Encrypted
            </span>
          </span>
        </div>
      </div>

      <div className="chat-messages" style={{ padding: 0 }}>
        <div className="chat-message-list">
          <div className="chat-bubble chat-bubble--in">
            <div className="chat-bubble__sender">alice</div>
            <div className="chat-bubble__text">
              Can you review the document before the meeting?
            </div>
            <div className="chat-bubble__meta"><span>09:14</span></div>
          </div>
          <div className="chat-bubble chat-bubble--out">
            <div className="chat-bubble__sender">you</div>
            <div className="chat-bubble__text">Yes — sending notes now.</div>
            <div className="chat-bubble__meta"><span>09:15</span></div>
          </div>
          <div className="chat-bubble chat-bubble--in">
            <div className="chat-bubble__sender">alice</div>
            <div className="chat-bubble__text">
              Thanks. End-to-end encrypted, no copies on the server.
            </div>
            <div className="chat-bubble__meta"><span>09:16</span></div>
          </div>
        </div>
      </div>

      <div className="landing__visual-meta">
        <span className="landing__visual-status">Encrypted session</span>
        <span>Forward-secret ratchet</span>
      </div>
    </aside>
  );
}

/* Inline icons — minimal stroke-based set, no external dependency. */

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

function IconCode(): JSX.Element {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="m9 8-4 4 4 4" />
      <path d="m15 8 4 4-4 4" />
    </svg>
  );
}

function IconRefresh(): JSX.Element {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M3 12a9 9 0 0 1 15.5-6.3L21 8" />
      <path d="M21 3v5h-5" />
      <path d="M21 12a9 9 0 0 1-15.5 6.3L3 16" />
      <path d="M3 21v-5h5" />
    </svg>
  );
}

function IconEyeOff(): JSX.Element {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="m4 4 16 16" />
      <path d="M10.6 6.1A11 11 0 0 1 12 6c5 0 9 4 10 6-.5 1-1.7 2.7-3.5 4.2" />
      <path d="M6.5 8.2C4.7 9.5 3.5 11 3 12c1 2 5 6 9 6 1.4 0 2.7-.4 3.9-1" />
      <path d="M9.9 9.9a3 3 0 1 0 4.2 4.2" />
    </svg>
  );
}

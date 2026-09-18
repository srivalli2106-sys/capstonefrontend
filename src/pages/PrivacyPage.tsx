import type { JSX } from 'react';
import { Link } from 'react-router-dom';

export function PrivacyPage(): JSX.Element {
  return (
    <article className="page page--narrow content-page">
      <header className="content-page__header">
        <p className="content-page__eyebrow">Privacy</p>
        <h1>Privacy notice</h1>
        <p className="content-page__lede">
          This notice explains how the Secure Messaging client handles your
          data in plain language.
        </p>
        <p className="content-page__meta">Effective September 19, 2026</p>
      </header>

      <section className="content-page__section">
        <h2>Overview</h2>
        <p>
          Secure Messaging is a web client for exchanging encrypted
          messages with another registered user. Cryptographic operations
          happen on your device. The server relays ciphertext between users
          and provides account and routing services.
        </p>
      </section>

      <section className="content-page__section">
        <h2>Information stored on this device</h2>
        <p>
          The client stores an encrypted identity record for the user
          signed in on this browser. The record is encrypted with a key
          derived from your passphrase and held in the browser's IndexedDB
          store. The client does not write plaintext message content to
          local storage.
        </p>
        <p>
          The session token used to authenticate WebSocket requests is held
          in memory and in sessionStorage for the duration of your browser
          session. Signing out clears it.
        </p>
      </section>

      <section className="content-page__section">
        <h2>Information sent to the service</h2>
        <p>
          When you use the client, the service receives your account
          identifier, the public keys you registered, the timestamps and
          routing metadata required to deliver envelopes, and any
          account-management requests you initiate.
        </p>
      </section>

      <section className="content-page__section">
        <h2>End-to-end encrypted messages</h2>
        <p>
          Message plaintext is encrypted on your device before it is sent.
          The server only routes opaque ciphertext between users and does
          not see message content. Each conversation uses a per-session
          key chain, so a single compromised key does not expose past
          messages in that session.
        </p>
        <p>
          The client does not persist a message history. Closing the
          browser or signing out removes the messages held in memory.
        </p>
      </section>

      <section className="content-page__section">
        <h2>Authentication and account identity</h2>
        <p>
          Your identity key is generated on this device and protected by
          your passphrase. The passphrase and the private key material
          derived from it are not sent to the server. Authentication uses a
          proof-of-possession signature over a server-issued challenge;
          the challenge is short-lived and is consumed after use.
        </p>
      </section>

      <section className="content-page__section">
        <h2>Service and technical information</h2>
        <p>
          The service processes routing and presence requests required to
          deliver envelopes between users. It applies rate limits and
          abuse controls. Standard technical information (such as request
          identifiers and timestamps) is used to operate and debug the
          service.
        </p>
      </section>

      <section className="content-page__section">
        <h2>Data retention</h2>
        <p>
          The service does not retain message plaintext. Account records,
          registered public keys, and routing metadata are retained for as
          long as your account is active. You can remove the local
          identity record from this device using Settings. Account removal
          on the server is performed through account management.
        </p>
      </section>

      <section className="content-page__section">
        <h2>Security</h2>
        <p>
          No software can guarantee absolute security. The client is
          designed to minimise what the server can learn and to keep
          private key material on the device. You are responsible for
          keeping your passphrase confidential and for the physical
          security of devices you use to sign in.
        </p>
      </section>

      <section className="content-page__section">
        <h2>Contact</h2>
        <p>
          For questions about this notice, see{' '}
          <Link to="/contact">Contact and support</Link>.
        </p>
      </section>
    </article>
  );
}

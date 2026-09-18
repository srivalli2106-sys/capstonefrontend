import type { JSX } from 'react';
import { Link } from 'react-router-dom';

export function TermsPage(): JSX.Element {
  return (
    <article className="page page--legal content-page">
      <header className="content-page__header">
        <p className="content-page__eyebrow">Terms</p>
        <h1>Terms of service</h1>
        <p className="content-page__lede">
          These terms govern your use of the Secure Messaging client. By
          using the client you accept them.
        </p>
        <p className="content-page__meta">Effective September 19, 2026</p>
      </header>

      <section className="content-page__section">
        <h2>Acceptance of terms</h2>
        <p>
          Use of the Secure Messaging client is subject to these terms. If
          you do not accept them, do not use the client.
        </p>
      </section>

      <section className="content-page__section">
        <h2>Use of the service</h2>
        <p>
          The client lets you exchange end-to-end encrypted messages with
          another registered user. Cryptographic operations happen on your
          device. The service relays ciphertext between users and provides
          account and routing functions.
        </p>
      </section>

      <section className="content-page__section">
        <h2>Accounts and identity</h2>
        <p>
          Accounts are identified by a user identifier chosen at
          registration. Your identity key is generated on your device and
          protected by your passphrase. The passphrase is not stored on the
          server and cannot be recovered.
        </p>
      </section>

      <section className="content-page__section">
        <h2>User responsibilities</h2>
        <p>
          You are responsible for keeping your passphrase confidential
          and for activity that occurs under your account. You agree to
          provide accurate registration information and to keep it
          current.
        </p>
        <p>
          You are responsible for the physical security of the devices
          you use. If a device is lost or compromised, sign out and lock
          your identity.
        </p>
      </section>

      <section className="content-page__section">
        <h2>Security and account protection</h2>
        <p>
          The client provides tools to lock the identity and sign out.
          Locking clears the in-memory private key. Signing out clears the
          session token and locks the identity. Use these controls if you
          suspect your device has been compromised.
        </p>
        <p>
          No software can guarantee absolute security. Use the service in
          accordance with its design.
        </p>
      </section>

      <section className="content-page__section">
        <h2>Acceptable use</h2>
        <p>
          Do not use the service to violate applicable law or to harm
          others. Do not attempt to disrupt the service, reverse-engineer
          it beyond what is permitted by law, or use it to send unsolicited
          messages.
        </p>
      </section>

      <section className="content-page__section">
        <h2>Service availability</h2>
        <p>
          The service is provided on an availability-as-possible basis.
          Maintenance windows, capacity limits, and external outages may
          interrupt access. The service may rate-limit or refuse abusive
          traffic.
        </p>
      </section>

      <section className="content-page__section">
        <h2>Intellectual property</h2>
        <p>
          The client and the cryptographic protocol implementations are
          provided to you under their applicable licenses. You retain
          ownership of the content you create and send.
        </p>
      </section>

      <section className="content-page__section">
        <h2>Changes to the service</h2>
        <p>
          The client and the service may be updated over time. Material
          changes to these terms will be reflected on this page with an
          updated effective date.
        </p>
      </section>

      <section className="content-page__section">
        <h2>Termination</h2>
        <p>
          You may stop using the service at any time by signing out and
          removing the local identity record. The service may refuse or
          terminate access for users who violate these terms.
        </p>
      </section>

      <section className="content-page__section">
        <h2>Limitation of liability</h2>
        <p>
          The service is provided as is, without warranty of any kind. To
          the extent permitted by law, the operators of the service are
          not liable for any indirect, incidental, or consequential
          damages arising from your use of the client or the service.
        </p>
      </section>

      <section className="content-page__section">
        <h2>Contact</h2>
        <p>
          For questions about these terms, see{' '}
          <Link to="/contact">Contact and support</Link>.
        </p>
      </section>
    </article>
  );
}

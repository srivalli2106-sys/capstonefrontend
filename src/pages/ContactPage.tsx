import type { JSX } from 'react';

export function ContactPage(): JSX.Element {
  return (
    <article className="page page--narrow content-page">
      <header className="content-page__header">
        <p className="content-page__eyebrow">Support</p>
        <h1>Contact and support</h1>
        <p className="content-page__lede">
          How to get help with Secure Messaging.
        </p>
      </header>

      <section className="content-page__section">
        <h2>Support channel</h2>
        <p>
          Need help with Secure Messaging? For product or technical
          support, use the support channel provided with your deployment.
        </p>
        <p>
          When you contact support, include the user identifier you signed
          in with, the approximate time of the issue, and a short
          description. Do not include your passphrase, identity keys, or
          message content; support does not need them and cannot read
          encrypted messages.
        </p>
      </section>

      <section className="content-page__section">
        <h2>Common topics</h2>
        <dl className="content-page__dl">
          <dt>Account access</dt>
          <dd>
            Cannot sign in, lost the passphrase, or need to remove the
            account from a device.
          </dd>

          <dt>Identity and passphrase</dt>
          <dd>
            Locking and unlocking the local identity, what the passphrase
            protects, and how to remove the local identity record.
          </dd>

          <dt>Messaging</dt>
          <dd>
            Opening a conversation, sending and receiving messages, and
            understanding the session and connection states.
          </dd>

          <dt>Connection issues</dt>
          <dd>
            WebSocket connection state, what to try when the connection
            drops, and how the client reconnects.
          </dd>

          <dt>Security concerns</dt>
          <dd>
            Suspected device compromise, lost device, or questions about
            how private keys and message content are handled.
          </dd>
        </dl>
      </section>

      <section className="content-page__section">
        <h2>What support can and cannot do</h2>
        <p>
          Support can help with the client, the service, and account
          management. Support cannot recover a passphrase, read message
          content, or see encrypted session state. These properties are
          part of the design.
        </p>
      </section>
    </article>
  );
}

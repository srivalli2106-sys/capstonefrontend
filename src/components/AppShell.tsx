/**
 * AppShell — application chrome.
 *
 * Renders the top navigation, the routed page content (via <Outlet />), and
 * the site footer. The navbar adapts on small screens.
 */

import type { JSX } from 'react';
import { Link, NavLink, Outlet } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { Logo } from './Logo';

interface NavItem {
  readonly to: string;
  readonly label: string;
  readonly protected: boolean;
}

const NAV_ITEMS: ReadonlyArray<NavItem> = [
  { to: '/', label: 'Home', protected: false },
  { to: '/chat', label: 'Chat', protected: true },
  { to: '/settings', label: 'Settings', protected: true },
];

export function AppShell(): JSX.Element {
  const { authenticated, userId, identity } = useAuth();

  const identityBadge =
    identity.kind === 'unlocked'
      ? 'unlocked'
      : identity.kind === 'locked'
        ? 'locked'
        : 'no id';

  return (
    <div className="app-shell">
      <header className="app-header" role="banner">
        <div className="app-header__inner">
          <Link to="/" className="app-header__brand" aria-label="Secure Messaging home">
            <Logo size={26} variant="header" />
          </Link>

          <nav className="app-header__nav" aria-label="Primary">
            {NAV_ITEMS.map((item) => {
              if (item.protected && !authenticated) return null;
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.to === '/'}
                  className={({ isActive }) =>
                    isActive
                      ? 'app-header__link app-header__link--active'
                      : 'app-header__link'
                  }
                >
                  {item.label}
                </NavLink>
              );
            })}
          </nav>

          <div className="app-header__user">
            {authenticated ? (
              <>
                <span
                  className={`app-header__identity app-header__identity--${identityBadge.replace(' ', '-')}`}
                  title={`Local identity: ${identityBadge}`}
                  aria-label={`Identity status: ${identityBadge}`}
                >
                  {identityBadge}
                </span>
                <span className="app-header__user-tag" title={userId ?? ''}>
                  {userId}
                </span>
              </>
            ) : (
              <>
                <NavLink to="/login" className="app-header__link">
                  Sign in
                </NavLink>
                <NavLink to="/register" className="button button--primary button--small">
                  Create account
                </NavLink>
              </>
            )}
          </div>
        </div>
      </header>

      <main className="app-main" id="main-content">
        <div className="app-main__inner">
          <Outlet />
        </div>
      </main>

      <footer className="app-footer" role="contentinfo">
        <div className="app-footer__inner">
          <div className="app-footer__brand">
            <Logo size={24} />
            <p className="app-footer__tagline">
              Private one-to-one messaging built with end-to-end encryption.
            </p>
          </div>

          <div className="app-footer__col">
            <h4>Product</h4>
            <ul>
              <li><Link to="/chat">Chat</Link></li>
              <li><Link to="/settings">Settings</Link></li>
              <li><Link to="/">Overview</Link></li>
            </ul>
          </div>

          <div className="app-footer__col">
            <h4>Security</h4>
            <ul>
              <li><span className="muted">End-to-end encryption</span></li>
              <li><span className="muted">On-device identity keys</span></li>
              <li><span className="muted">Forward-secret sessions</span></li>
            </ul>
          </div>

          <div className="app-footer__col">
            <h4>Support</h4>
            <ul>
              <li><Link to="/contact">Contact</Link></li>
              <li><Link to="/privacy">Privacy</Link></li>
              <li><Link to="/terms">Terms</Link></li>
            </ul>
          </div>
        </div>

        <div className="app-footer__bottom">
          <span>© 2026 Secure Messaging. All rights reserved.</span>
          <span className="app-footer__tagline">
            Cryptography runs in the browser; the server only relays
            ciphertext.
          </span>
        </div>
      </footer>
    </div>
  );
}

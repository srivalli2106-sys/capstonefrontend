import type { JSX } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

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
  const { authenticated, userId } = useAuth();

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="app-header__brand">Secure Messaging</div>
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
            <span className="app-header__user-tag" title={userId ?? ''}>
              {userId}
            </span>
          ) : (
            <NavLink to="/login" className="app-header__link">
              Sign in
            </NavLink>
          )}
        </div>
      </header>

      <main className="app-main">
        <Outlet />
      </main>

      <footer className="app-footer">
        <small>End-to-end encrypted client · Phase 2 foundation</small>
      </footer>
    </div>
  );
}
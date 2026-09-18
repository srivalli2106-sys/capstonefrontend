import { NavLink, Outlet } from 'react-router-dom';

interface NavItem {
  readonly to: string;
  readonly label: string;
}

const NAV_ITEMS: ReadonlyArray<NavItem> = [
  { to: '/', label: 'Home' },
  { to: '/chat', label: 'Chat' },
  { to: '/settings', label: 'Settings' },
];

export function AppShell(): JSX.Element {
  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="app-header__brand">Secure Messaging</div>
        <nav className="app-header__nav" aria-label="Primary">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                isActive ? 'app-header__link app-header__link--active' : 'app-header__link'
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
      </header>

      <main className="app-main">
        <Outlet />
      </main>

      <footer className="app-footer">
        <small>End-to-end encrypted client · Phase 0 foundation</small>
      </footer>
    </div>
  );
}
/**
 * RequireAuth — protects a route subtree.
 *
 * Redirects unauthenticated visitors to /login while preserving the intended
 * destination in the `next` query string so the login flow can return the
 * user to where they tried to go.
 */

import type { ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

interface RequireAuthProps {
  children: ReactNode;
}

export function RequireAuth({ children }: RequireAuthProps): JSX.Element {
  const { authenticated } = useAuth();
  const location = useLocation();

  if (!authenticated) {
    const next = encodeURIComponent(location.pathname + location.search);
    return <Navigate to={`/login?next=${next}`} replace />;
  }

  return <>{children}</>;
}
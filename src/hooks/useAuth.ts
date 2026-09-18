/**
 * React hook for the AuthController.
 *
 * Re-renders the calling component when the controller notifies its
 * listeners (login, logout, 401-driven clear, boot-time restore).
 */

import { useEffect, useState } from 'react';
import { authController, type AuthSnapshot } from '../auth/AuthController';

export function useAuth(): AuthSnapshot {
  const [snapshot, setSnapshot] = useState<AuthSnapshot>(() =>
    authController.getSnapshot(),
  );

  useEffect(() => {
    return authController.subscribe((next) => setSnapshot(next));
  }, []);

  return snapshot;
}
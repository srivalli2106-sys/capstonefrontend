/**
 * React hook for the KeyController (Phase 4).
 *
 * Re-renders when the key status changes (identity lock/unlock, login,
 * logout — the controller re-emits on auth changes).
 */

import { useEffect, useState } from 'react';
import { keyController, type KeyStatus } from '../keys/KeyController';

export function useKeyStatus(): KeyStatus {
  const [status, setStatus] = useState<KeyStatus>(() => keyController.getStatus());

  useEffect(() => {
    return keyController.subscribe((next) => setStatus(next));
  }, []);

  return status;
}
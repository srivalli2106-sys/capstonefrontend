/**
 * React hook for the ChatController.
 *
 * Subscribes to the singleton ChatController (created by
 * `realtime/setup.ts`). Re-renders on every snapshot update. Before the
 * realtime transport is wired (e.g. during the first render after a hard
 * reload), the hook returns a neutral empty snapshot so callers can render
 * without crashing.
 */

import { useEffect, useState } from 'react';
import { getChatControllerOrNull } from '../realtime/setup';
import type { ChatSnapshot } from '../realtime/ChatController';

const EMPTY_SNAPSHOT: ChatSnapshot = {
  connected: false,
  selfUserId: null,
  conversations: [],
  historyLoaded: false,
};

export function useChat(): ChatSnapshot {
  const [snapshot, setSnapshot] = useState<ChatSnapshot>(() => {
    const ctrl = getChatControllerOrNull();
    return ctrl === null ? EMPTY_SNAPSHOT : ctrl.getSnapshot();
  });

  useEffect(() => {
    const ctrl = getChatControllerOrNull();
    if (ctrl === null) {
      setSnapshot(EMPTY_SNAPSHOT);
      return undefined;
    }
    setSnapshot(ctrl.getSnapshot());
    return ctrl.subscribe((next) => setSnapshot(next));
  }, []);

  return snapshot;
}

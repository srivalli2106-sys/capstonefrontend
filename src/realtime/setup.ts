/**
 * Realtime transport setup (Phase 7 + 8 wiring).
 *
 * Called once from `App.tsx` after the `AuthController` and `WebSocketController`
 * have been constructed. Creates the singleton `ChatController` and binds
 * the WebSocketController's lifecycle to auth state (Phase 7 already does
 * this internally via `WebSocketController`'s `authController.subscribe`).
 *
 * Phase 8 adds: as soon as the user is authenticated AND the local identity
 * is unlocked, the WebSocket is connected so that incoming `session_init`
 * envelopes can drive responder-side E2EE sessions. Locking the identity
 * or logging out already triggers the WebSocket's `disconnect()` via its
 * auth subscription — `ChatController.dispose` clears the in-memory session
 * store when the user logs out.
 */

import { WebSocketController } from './WebSocketController';
import { ChatController, getOrCreateChatController } from './ChatController';

let webSocketController: WebSocketController | null = null;
let chatController: ChatController | null = null;

export function setRealtimeTransport(options: {
  webSocketController: WebSocketController;
  /** Connect the WebSocket immediately after the auth state becomes
   *  authenticated (the controller already handles logout / re-auth
   *  internally). Defaults to `true`. */
  autoConnect?: boolean;
}): ChatController {
  webSocketController = options.webSocketController;
  chatController = getOrCreateChatController({
    authController: options.webSocketController.getAuthController(),
    webSocketController: options.webSocketController,
  });
  if (options.autoConnect !== false) {
    options.webSocketController.connect();
  }
  return chatController;
}

export function getWebSocketController(): WebSocketController {
  if (webSocketController === null) {
    throw new Error('WebSocketController not initialised.');
  }
  return webSocketController;
}

/**
 * Returns the active ChatController, or `null` when setup hasn't run yet.
 * UI hooks use this to decide whether to render the chat UI or a placeholder.
 */
export function getChatControllerOrNull(): ChatController | null {
  return chatController;
}

export function getChatController(): ChatController {
  if (chatController === null) {
    throw new Error('ChatController not initialised. Call setRealtimeTransport first.');
  }
  return chatController;
}

/**
 * Tear down the realtime stack (used on logout from `App.tsx` to ensure
 * a clean state if the user signs back in immediately).
 */
export function disposeRealtimeTransport(): void {
  if (chatController !== null) {
    chatController.dispose();
    chatController = null;
  }
  if (webSocketController !== null) {
    webSocketController.dispose();
    webSocketController = null;
  }
}

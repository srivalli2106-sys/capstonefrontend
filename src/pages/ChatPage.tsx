/**
 * ChatPage — one-to-one encrypted messaging UI.
 *
 * The encryption logic is owned by `ChatController` + `E2EESession`. The
 * WebSocket transport only ever sees opaque base64url ciphertext. This file
 * is presentation-only and never mutates crypto state directly.
 */

import type { FormEvent, JSX } from 'react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { authController } from '../auth/AuthController';
import { getWebSocketController } from '../realtime/setup';
import { useAuth } from '../hooks/useAuth';
import { useChat } from '../hooks/useChat';
import type {
  ChatController,
  ChatError,
  ConversationSnapshot,
  DisplayMessage,
  SessionState,
} from '../realtime/ChatController';
import { getOrCreateChatController } from '../realtime/ChatController';
import type { ConnectionState } from '../realtime/types';

export function ChatPage(): JSX.Element {
  const { authenticated, userId, identity } = useAuth();
  const chat = useChat();

  const [targetInput, setTargetInput] = useState('');
  const [activePeer, setActivePeer] = useState<string | null>(null);
  const [composer, setComposer] = useState('');
  const [sendError, setSendError] = useState<string | null>(null);
  const [opening, setOpening] = useState(false);

  // Resolve the active ChatController once setup has run.
  const ctrl: ChatController | null = useMemo(() => {
    try {
      return getOrCreateChatController({
        authController,
        webSocketController: getWebSocketController(),
      });
    } catch {
      return null;
    }
  }, []);

  const activeConversation = useMemo<ConversationSnapshot | null>(() => {
    if (activePeer === null) return null;
    return chat.conversations.find((c) => c.peerUserId === activePeer) ?? null;
  }, [activePeer, chat.conversations]);

  // Keep the active peer in sync with the latest snapshot (e.g. when a
  // conversation is created automatically by an inbound session_init).
  useEffect(() => {
    if (activePeer !== null) return;
    if (chat.conversations.length > 0) {
      const first = chat.conversations[0]!;
      setActivePeer(first.peerUserId);
    }
  }, [chat.conversations, activePeer]);

  const wsState = useWebSocketStateLabel();

  const handleOpen = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      const peer = targetInput.trim();
      if (peer.length < 3 || peer.length > 64) return;
      if (peer === userId) return;
      setSendError(null);
      setOpening(true);
      setActivePeer(peer);
      if (ctrl === null) { setOpening(false); return; }
      try {
        await ctrl.openConversation(peer);
      } catch (err) {
        setSendError(safeErrorMessage(err, 'Could not open conversation.'));
      } finally {
        setOpening(false);
      }
    },
    [targetInput, ctrl, userId],
  );

  const handleSend = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (activePeer === null || ctrl === null) return;
      const trimmed = composer.trim();
      if (trimmed.length === 0) return;
      setSendError(null);
      const previous = composer;
      setComposer('');
      try {
        await ctrl.sendText(activePeer, trimmed);
      } catch (err) {
        // Restore the composer text on failure so the user does not lose
        // their draft.
        setComposer(previous);
        setSendError(safeErrorMessage(err, 'Send failed.'));
      }
    },
    [activePeer, composer, ctrl],
  );

  const handleCloseConversation = useCallback(() => {
    if (activePeer === null || ctrl === null) return;
    ctrl.closeConversation(activePeer);
    setActivePeer(null);
  }, [activePeer, ctrl]);

  const handleRetry = useCallback(
    async (peerUserId: string, failedPlaintext: string) => {
      if (ctrl === null) return;
      setSendError(null);
      try {
        await ctrl.sendText(peerUserId, failedPlaintext);
      } catch (err) {
        setSendError(safeErrorMessage(err, 'Retry failed.'));
      }
    },
    [ctrl],
  );

  // Identify / lock state.
  const identityLocked = identity.kind !== 'unlocked';

  return (
    <div className="page page--full page--chat">
      {!authenticated ? (
        <p className="page__lede">Sign in to start a conversation.</p>
      ) : (
        <div
          className="chat-layout"
          data-testid="chat-layout"
          data-active-peer={activePeer === null ? 'false' : 'true'}
        >
          <aside className="chat-sidebar" aria-label="Conversations">
            <div className="chat-sidebar__heading">
              <span>Conversations</span>
              <span className="muted" style={{ fontWeight: 400, textTransform: 'none' }}>
                {chat.conversations.length}
              </span>
            </div>

            <form className="form form--inline" onSubmit={handleOpen}>
              <div className="form__row" style={{ width: '100%' }}>
                <input
                  className="form__input"
                  name="new_peer"
                  type="text"
                  placeholder="Recipient user_id"
                  minLength={3}
                  maxLength={64}
                  autoComplete="off"
                  value={targetInput}
                  onChange={(e) => setTargetInput(e.target.value)}
                  disabled={identityLocked || ctrl === null}
                  aria-label="Recipient user identifier"
                />
                <button
                  type="submit"
                  className="button button--primary button--small"
                  disabled={targetInput.trim().length < 3 || identityLocked || ctrl === null || opening}
                  data-testid="open-conversation"
                >
                  {opening ? 'Opening…' : 'Open'}
                </button>
              </div>
            </form>

            {identityLocked && (
              <p className="form__hint form__hint--warn" role="status">
                Identity locked — unlock in Settings to start a session.
              </p>
            )}

            {sendError !== null && (
              <div className="form__error" role="alert" data-testid="open-error">
                <span>{sendError}</span>
              </div>
            )}

            {chat.conversations.length === 0 ? (
              <p className="page__lede" style={{ fontSize: 'var(--fs-sm)' }}>
                No conversations yet. Start one above.
              </p>
            ) : (
              <ul className="chat-conversation-list" role="listbox" aria-label="Active conversations">
                {chat.conversations.map((c) => (
                  <li key={c.peerUserId}>
                    <button
                      type="button"
                      className={
                        'chat-conversation' +
                        (c.peerUserId === activePeer ? ' chat-conversation--active' : '')
                      }
                      onClick={() => setActivePeer(c.peerUserId)}
                      data-peer={c.peerUserId}
                      aria-pressed={c.peerUserId === activePeer}
                    >
                      <span className="chat-conversation__peer">{c.peerUserId}</span>
                      <SessionBadge state={c.session} />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </aside>

          <section className="chat-main" aria-label="Active conversation">
            <header className="chat-main__header">
              <button
                type="button"
                className="chat-main__back"
                onClick={() => setActivePeer(null)}
                aria-label="Back to conversations"
              >
                ‹ Conversations
              </button>
              <div className="chat-main__title">
                {activePeer === null ? (
                  <span className="chat-main__subtitle">Select a conversation</span>
                ) : (
                  <>
                    <span className="chat-main__peer">{activePeer}</span>
                    <span className="chat-main__subtitle">
                      {activeConversation === null
                        ? 'Establishing secure session…'
                        : labelForSession(activeConversation.session)}
                    </span>
                  </>
                )}
              </div>
              <div className="chat-main__meta">
                <span
                  className="chat-meta-pill"
                  data-state={wsState}
                  data-testid="connection-state"
                  title={`Transport state: ${wsState}`}
                >
                  {wsState === 'open'
                    ? 'Connected'
                    : wsState === 'connecting' || wsState === 'authenticating'
                      ? 'Connecting…'
                      : wsState === 'closed'
                        ? 'Disconnected'
                        : wsState === 'closing'
                          ? 'Closing…'
                          : 'Idle'}
                </span>
                {activeConversation !== null && (
                  <span
                    className={
                      'chat-meta-pill ' +
                      (activeConversation.session.kind === 'ready'
                        ? 'pill--success'
                        : activeConversation.session.kind === 'error'
                          ? 'pill--danger'
                          : '')
                    }
                    data-testid="encryption-state"
                  >
                    {activeConversation.session.kind === 'ready'
                      ? 'Encrypted'
                      : activeConversation.session.kind === 'error'
                        ? 'Session error'
                        : activeConversation.session.kind === 'initiating'
                          ? 'Establishing…'
                          : 'No session'}
                  </span>
                )}
                {activePeer !== null && (
                  <button
                    type="button"
                    className="button button--ghost button--small"
                    onClick={handleCloseConversation}
                  >
                    Close
                  </button>
                )}
              </div>
            </header>

            <MessageList
              conversation={activeConversation}
              selfUserId={userId}
              onRetry={handleRetry}
            />

            {activeConversation?.session.kind === 'error' && (
              <div className="form__error" role="alert" data-testid="session-error">
                <span>{activeConversation.session.error.message}</span>
                {activeConversation.session.error.requestId !== null && (
                  <small className="form__meta">
                    {' '}
                    (request_id: <code>{activeConversation.session.error.requestId}</code>)
                  </small>
                )}
              </div>
            )}

            <form className="chat-composer" onSubmit={handleSend} data-testid="composer-form">
              <textarea
                className="chat-composer__input"
                name="message"
                placeholder={
                  identityLocked
                    ? 'Unlock your identity to send messages'
                    : activePeer === null
                      ? 'Select a conversation first'
                      : activeConversation === null ||
                          activeConversation.session.kind !== 'ready'
                        ? 'Secure session not established'
                        : 'Type a message — Enter to send, Shift+Enter for newline'
                }
                value={composer}
                onChange={(e) => setComposer(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    void handleSend(e as unknown as FormEvent<HTMLFormElement>);
                  }
                }}
                disabled={
                  identityLocked ||
                  activePeer === null ||
                  activeConversation === null ||
                  activeConversation.session.kind !== 'ready'
                }
                data-testid="composer-input"
                rows={1}
                aria-label="Message text"
              />
              <button
                type="submit"
                className="button button--primary"
                disabled={
                  composer.trim().length === 0 ||
                  identityLocked ||
                  activePeer === null ||
                  activeConversation === null ||
                  activeConversation.session.kind !== 'ready'
                }
                data-testid="composer-send"
              >
                Send
              </button>
            </form>

            {sendError !== null && (
              <div className="form__error" role="alert" data-testid="send-error">
                <span>{sendError}</span>
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Subcomponents
// ---------------------------------------------------------------------------

function MessageList({
  conversation,
  selfUserId,
  onRetry,
}: {
  conversation: ConversationSnapshot | null;
  selfUserId: string | null;
  onRetry?: (peerUserId: string, plaintext: string) => void;
}): JSX.Element {
  const ref = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (ref.current !== null) {
      ref.current.scrollTop = ref.current.scrollHeight;
    }
  }, [conversation?.messages.length]);

  if (conversation === null) {
    return (
      <div className="chat-messages chat-messages--empty" data-testid="message-list">
        <div className="chat-empty">
          <div className="chat-empty__title">No conversation selected</div>
          <p>Open a conversation from the sidebar to start exchanging encrypted messages.</p>
        </div>
      </div>
    );
  }
  return (
    <div className="chat-messages" ref={ref} data-testid="message-list">
      {conversation.messages.length === 0 ? (
        <div className="chat-messages--empty">
          <div className="chat-empty">
            <div className="chat-empty__title">No messages yet</div>
            <p>This conversation is empty. Send the first message below.</p>
          </div>
        </div>
      ) : (
        <ul className="chat-message-list">
          {conversation.messages.map((m) => (
            <MessageBubble key={m.id} message={m} selfUserId={selfUserId} onRetry={onRetry} />
          ))}
        </ul>
      )}
    </div>
  );
}

function MessageBubble({
  message,
  selfUserId,
  onRetry,
}: {
  message: DisplayMessage;
  selfUserId: string | null;
  onRetry?: (peerUserId: string, plaintext: string) => void;
}): JSX.Element {
  const outgoing = message.outgoing || (selfUserId !== null && message.senderUserId === selfUserId);
  const time = new Date(message.createdAt).toLocaleTimeString(undefined, {
    hour: '2-digit',
    minute: '2-digit',
  });
  return (
    <li
      className={'chat-bubble ' + (outgoing ? 'chat-bubble--out' : 'chat-bubble--in')}
      data-testid="message-bubble"
      data-outgoing={outgoing ? 'true' : 'false'}
    >
      <div className="chat-bubble__sender">{outgoing ? 'You' : message.senderUserId}</div>
      <div className="chat-bubble__text" data-testid="message-text">
        {message.plaintext}
      </div>
      <div className="chat-bubble__meta">
        <span>{time}</span>
        {outgoing && message.status !== null && (
          <span className="chat-bubble__status" data-testid="message-status">
            {' · '}
            {message.status === 'sending' && 'sending…'}
            {message.status === 'sent' && 'sent'}
            {message.status === 'failed' && (
              <>
                <span className="chat-bubble__status--failed">send failed</span>
                {onRetry && (
                  <button
                    type="button"
                    className="button button--link"
                    onClick={() => onRetry(message.recipientUserId, message.plaintext)}
                    data-testid="retry-button"
                  >
                    {' retry'}
                  </button>
                )}
              </>
            )}
          </span>
        )}
      </div>
    </li>
  );
}

function SessionBadge({ state }: { state: SessionState }): JSX.Element {
  const label = labelForSession(state);
  return <span className="chat-conversation__badge">{label}</span>;
}

function labelForSession(state: SessionState): string {
  switch (state.kind) {
    case 'none':
      return 'No session';
    case 'initiating':
      return 'Establishing…';
    case 'ready':
      return 'End-to-end encrypted';
    case 'error':
      return state.error.code === 'backend_blocker'
        ? 'Backend blocker'
        : 'Session error';
  }
}

function useWebSocketStateLabel(): ConnectionState {
  const [label, setLabel] = useState<ConnectionState>(() => {
    try {
      return getWebSocketController().state;
    } catch {
      return 'idle';
    }
  });
  useEffect(() => {
    let unsub: (() => void) | null = null;
    try {
      const ctrl = getWebSocketController();
      unsub = ctrl.onState((s: ConnectionState) => {
        setLabel(s);
      });
    } catch {
      // Setup hasn't run yet.
    }
    return () => {
      if (unsub !== null) unsub();
    };
  }, []);
  return label;
}

function safeErrorMessage(err: unknown, fallback: string): string {
  if (err && typeof err === 'object' && 'message' in err && typeof (err as { message: unknown }).message === 'string') {
    return String((err as { message: string }).message);
  }
  if (err && typeof err === 'object' && 'code' in err) {
    return `Crypto failure (${String((err as { code: unknown }).code)})`;
  }
  return err instanceof Error ? err.message : fallback;
}

// ChatController uses the controller singleton, but the controller depends
// on the AuthController being installed. Re-export authController to keep
// the import order explicit.
void authController;
void getOrCreateChatController;
void (null as ChatError | null);

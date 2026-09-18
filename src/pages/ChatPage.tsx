/**
 * ChatPage — one-to-one encrypted messaging UI (Phase 8).
 *
 * Layout (functional, not final-UX):
 *
 *   ┌─────────── sidebar ────────────┐┌───────── active conversation ─────────┐
 *   │ [+] New conversation              ││ Connection: Connected                │
 *   │ ──────────                        ││ Encryption: End-to-end encrypted     │
 *   │ alice (latest activity)           ││ ────────────────────────────────────  │
 *   │ bob                              ││ [bob]   hello                  12:01 │
 *   │                                   ││ [alice] hi                     12:02 │
 *   │                                   ││ ────────────────────────────────────  │
 *   │                                   ││ [Type a message…            ] [Send]  │
 *   └───────────────────────────────────┘└────────────────────────────────────────┘
 *
 * Encryption is enforced end-to-end via `ChatController` + `E2EESession`;
 * the WebSocket transport only ever sees opaque base64url ciphertext.
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
      setActivePeer(peer);
      if (ctrl === null) return;
      try {
        await ctrl.openConversation(peer);
      } catch (err) {
        setSendError(safeErrorMessage(err, 'Could not open conversation.'));
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

  // Identify / lock state.
  const identityLocked = identity.kind !== 'unlocked';

  return (
    <section className="page page--chat">
      <h1>Chat</h1>

      {!authenticated ? (
        <p className="page__lede">Sign in to start a conversation.</p>
      ) : (
        <div className="chat-layout" data-testid="chat-layout">
          <aside className="chat-sidebar" aria-label="Conversations">
            <form className="form form--inline" onSubmit={handleOpen}>
              <label className="form__field">
                <span className="form__label">Start with user_id</span>
                <div className="form__row">
                  <input
                    className="form__input"
                    name="new_peer"
                    type="text"
                    placeholder="recipient user_id"
                    minLength={3}
                    maxLength={64}
                    autoComplete="off"
                    value={targetInput}
                    onChange={(e) => setTargetInput(e.target.value)}
                    disabled={identityLocked || ctrl === null}
                  />
                  <button
                    type="submit"
                    className="button button--primary"
                    disabled={targetInput.trim().length < 3 || identityLocked || ctrl === null}
                    data-testid="open-conversation"
                  >
                    Open
                  </button>
                </div>
              </label>
            </form>

            {identityLocked && (
              <p className="form__hint form__hint--warn" role="status">
                Identity locked — unlock in Settings to start a session.
              </p>
            )}

            {sendError !== null && (
              <div className="form__error" role="alert" data-testid="open-error">
                {sendError}
              </div>
            )}

            {chat.conversations.length === 0 ? (
              <p className="page__lede">No conversations yet.</p>
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
              <div className="chat-main__title">
                {activePeer === null
                  ? 'Select a conversation'
                  : `Conversation with ${activePeer}`}
              </div>
              <div className="chat-main__meta">
                <span className="chat-meta-pill" data-testid="connection-state">
                  Connection: {wsState}
                </span>
                <span className="chat-meta-pill" data-testid="encryption-state">
                  {activeConversation === null
                    ? 'Encryption: —'
                    : `Encryption: ${labelForSession(activeConversation.session)}`}
                </span>
              </div>
              {activePeer !== null && (
                <button
                  type="button"
                  className="button button--small"
                  onClick={handleCloseConversation}
                >
                  Close conversation
                </button>
              )}
            </header>

            <MessageList
              conversation={activeConversation}
              selfUserId={userId}
            />

            {activeConversation?.session.kind === 'error' && (
              <div className="form__error" role="alert" data-testid="session-error">
                {activeConversation.session.error.message}
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
                        : 'Type a message'
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
                rows={2}
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
                {sendError}
              </div>
            )}
          </section>
        </div>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Subcomponents
// ---------------------------------------------------------------------------

function MessageList({
  conversation,
  selfUserId,
}: {
  conversation: ConversationSnapshot | null;
  selfUserId: string | null;
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
        <p className="page__lede">Open a conversation to start chatting.</p>
      </div>
    );
  }
  return (
    <div className="chat-messages" ref={ref} data-testid="message-list">
      {conversation.messages.length === 0 ? (
        <p className="page__lede">No messages yet.</p>
      ) : (
        <ul className="chat-message-list">
          {conversation.messages.map((m) => (
            <MessageBubble key={m.id} message={m} selfUserId={selfUserId} />
          ))}
        </ul>
      )}
    </div>
  );
}

function MessageBubble({
  message,
  selfUserId,
}: {
  message: DisplayMessage;
  selfUserId: string | null;
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
      <div className="chat-bubble__sender">{outgoing ? 'you' : message.senderUserId}</div>
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
            {message.status === 'failed' && `send failed${message.errorMessage ? `: ${message.errorMessage}` : ''}`}
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
      return 'Session error';
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

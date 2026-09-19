/**
 * ChatPage — one-to-one encrypted messaging UI.
 *
 * The encryption logic is owned by `ChatController` + `E2EESession`. The
 * WebSocket transport only ever sees opaque base64url ciphertext. Local
 * history is RESTORED from the encrypted at-rest store by the controller and
 * rendered here; the UI never writes message content to storage directly.
 * This file is presentation-only and never mutates crypto state directly.
 */

import type { FormEvent, JSX } from 'react';
import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { authController } from '../auth/AuthController';
import { getWebSocketController } from '../realtime/setup';
import { useAuth } from '../hooks/useAuth';
import { useChat } from '../hooks/useChat';
import type {
  ChatController,
  ChatError,
  ConversationSnapshot,
  DisplayMessage,
  PresenceState,
  SessionState,
} from '../realtime/ChatController';
import { getOrCreateChatController } from '../realtime/ChatController';
import type { ConnectionState } from '../realtime/types';
import {
  formatConversationTimestamp,
  formatDaySeparator,
  formatMessageTimestamp,
  formatMessageTimestampLong,
} from '../realtime/timeFormat';
import { filterConversationsBySearch } from '../realtime/chatSearch';

/** Throttle outgoing typing-start frames. */
const TYPING_START_INTERVAL_MS = 1500;
/** Stop listening (and emit typing-stop) after this much silence. */
const TYPING_STOP_AFTER_MS = 2000;
/** Presence poll cadence. */
const PRESENCE_POLL_INTERVAL_MS = 30_000;
/** Auto-disarm the "Delete conversation" confirmation. */
const DELETE_CONFIRM_TIMEOUT_MS = 8000;
/** Pixel distance from the bottom that counts as "stuck to latest". */
const SCROLL_STICK_THRESHOLD_PX = 48;

/**
 * Day key for date separators — collapses a timestamp to its calendar day.
 */
function dayKey(ts: number): string {
  return new Date(ts).toDateString();
}

/** Safe preview line for the conversation list (already-decrypted local copy). */
function conversationPreview(conversation: ConversationSnapshot): string {
  const last = conversation.messages[conversation.messages.length - 1];
  if (last === undefined) return 'End-to-end encrypted';
  return last.outgoing ? `You: ${last.plaintext}` : last.plaintext;
}

export function ChatPage(): JSX.Element {
  const { authenticated, userId, identity } = useAuth();
  const chat = useChat();

  const [targetInput, setTargetInput] = useState('');
  const [activePeer, setActivePeer] = useState<string | null>(null);
  const [composer, setComposer] = useState('');
  const [sendError, setSendError] = useState<string | null>(null);
  const [opening, setOpening] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);
  const deleteTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

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

  // ---- Typing indicator (outgoing signal management) -------------------
  const typingStartPeerRef = useRef<string | null>(null);
  const lastTypingSignalAtRef = useRef(0);
  const typingInactivityTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clearTypingTimer = useCallback(() => {
    if (typingInactivityTimerRef.current !== null) {
      clearTimeout(typingInactivityTimerRef.current);
      typingInactivityTimerRef.current = null;
    }
  }, []);

  const stopTypingFor = useCallback(
    (peer: string) => {
      if (typingStartPeerRef.current !== peer) return;
      typingStartPeerRef.current = null;
      if (ctrl !== null) {
        ctrl.sendTyping(peer, 'stop');
      }
    },
    [ctrl],
  );

  // Stop typing signals on conversation switch and on unmount.
  const prevActivePeerRef = useRef<string | null>(activePeer);
  useEffect(() => {
    const prev = prevActivePeerRef.current;
    prevActivePeerRef.current = activePeer;
    if (prev !== null && prev !== activePeer) {
      stopTypingFor(prev);
    }
    clearTypingTimer();
    if (ctrl !== null) {
      // Drives read receipts for the newly active conversation.
      ctrl.setActivePeer(activePeer);
    }
  }, [activePeer, ctrl, stopTypingFor, clearTypingTimer]);

  useEffect(() => {
    return () => {
      clearTypingTimer();
      if (typingStartPeerRef.current !== null && ctrl !== null) {
        ctrl.sendTyping(typingStartPeerRef.current, 'stop');
      }
      typingStartPeerRef.current = null;
    };
  }, [ctrl, clearTypingTimer]);

  // ---- Presence polling (online/offline) -------------------------------
  useEffect(() => {
    if (!chat.connected || ctrl === null) return;
    for (const conversation of chat.conversations) {
      void ctrl.refreshPresence(conversation.peerUserId);
    }
    const interval = window.setInterval(() => {
      if (ctrl === null) return;
      for (const conversation of ctrl.getSnapshot().conversations) {
        void ctrl.refreshPresence(conversation.peerUserId);
      }
    }, PRESENCE_POLL_INTERVAL_MS);
    return () => window.clearInterval(interval);
  }, [chat.connected, ctrl, chat.conversations.length]);

  // ---- Conversation search (client-side, never scans message content) ---
  const filteredConversations = useMemo(
    () => filterConversationsBySearch(chat.conversations, searchTerm),
    [chat.conversations, searchTerm],
  );

  const handleComposerChange = useCallback(
    (value: string) => {
      setComposer(value);
      const peer = activePeer;
      if (peer === null || ctrl === null) return;
      clearTypingTimer();
      if (value.trim().length === 0) {
        stopTypingFor(peer);
        return;
      }
      const now = Date.now();
      if (now - lastTypingSignalAtRef.current > TYPING_START_INTERVAL_MS) {
        typingStartPeerRef.current = peer;
        lastTypingSignalAtRef.current = now;
        ctrl.sendTyping(peer, 'start');
      }
      typingInactivityTimerRef.current = setTimeout(() => {
        stopTypingFor(peer);
        typingInactivityTimerRef.current = null;
      }, TYPING_STOP_AFTER_MS);
    },
    [activePeer, ctrl, clearTypingTimer, stopTypingFor],
  );

  const handleDeleteLocally = useCallback(
    (peerUserId: string, messageId: string) => {
      if (ctrl === null) return;
      ctrl.deleteMessageLocally(peerUserId, messageId);
    },
    [ctrl],
  );

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

  /**
   * Opening a conversation from the list. Navigates to it AND (re)establishes
   * the E2EE session on demand — after a reload the restored history has no
   * live session until this runs.
   */
  const handleOpenConversation = useCallback(
    (peer: string) => {
      setActivePeer(peer);
      if (ctrl === null) return;
      void ctrl.openConversation(peer).catch((err) => {
        setSendError(safeErrorMessage(err, 'Could not open conversation.'));
      });
    },
    [ctrl],
  );

  const handleSend = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (activePeer === null || ctrl === null) return;
      const trimmed = composer.trim();
      if (trimmed.length === 0) return;
      setSendError(null);
      clearTypingTimer();
      stopTypingFor(activePeer);
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
    [activePeer, composer, ctrl, clearTypingTimer, stopTypingFor],
  );

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

  // ---- Delete conversation (local only, two-step confirm) --------------
  const clearDeleteTimer = useCallback(() => {
    if (deleteTimerRef.current !== null) {
      clearTimeout(deleteTimerRef.current);
      deleteTimerRef.current = null;
    }
  }, []);

  useEffect(() => {
    return () => {
      clearDeleteTimer();
    };
  }, [clearDeleteTimer]);

  const requestDeleteConversation = useCallback(
    (peer: string) => {
      if (deleteConfirm === peer) return; // already armed for this peer
      setDeleteConfirm(peer);
      clearDeleteTimer();
      deleteTimerRef.current = setTimeout(() => {
        setDeleteConfirm((current) => (current === peer ? null : current));
        deleteTimerRef.current = null;
      }, DELETE_CONFIRM_TIMEOUT_MS);
    },
    [deleteConfirm, clearDeleteTimer],
  );

  const cancelDeleteConversation = useCallback(() => {
    clearDeleteTimer();
    setDeleteConfirm(null);
  }, [clearDeleteTimer]);

  const confirmDeleteConversation = useCallback(
    async (peer: string) => {
      cancelDeleteConversation();
      if (ctrl === null) return;
      try {
        await ctrl.deleteConversation(peer);
      } catch {
        // Best-effort: the in-memory conversation stays if storage cleanup
        // failed; nothing is sent over the wire either way.
      }
      setActivePeer((current) => (current === peer ? null : current));
    },
    [ctrl, cancelDeleteConversation],
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

            <input
              className="form__input form__input--search"
              name="conversation_search"
              type="search"
              placeholder="Search conversations"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              disabled={chat.conversations.length === 0}
              aria-label="Search conversations by user id"
              data-testid="conversation-search"
            />

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

            {!chat.historyLoaded ? (
              <p
                className="page__lede"
                style={{ fontSize: 'var(--fs-sm)' }}
                data-testid="chat-loading"
              >
                Restoring conversations…
              </p>
            ) : filteredConversations.length === 0 ? (
              <p className="page__lede" style={{ fontSize: 'var(--fs-sm)' }}>
                {chat.conversations.length === 0
                  ? 'No conversations yet. Start one above.'
                  : 'No conversations match your search.'}
              </p>
            ) : (
              <ul className="chat-conversation-list" role="listbox" aria-label="Active conversations">
                {filteredConversations.map((c) => (
                  <li key={c.peerUserId}>
                    <button
                      type="button"
                      className={
                        'chat-conversation' +
                        (c.peerUserId === activePeer ? ' chat-conversation--active' : '')
                      }
                      onClick={() => handleOpenConversation(c.peerUserId)}
                      data-peer={c.peerUserId}
                      aria-pressed={c.peerUserId === activePeer}
                    >
                      <span className="chat-conversation__top">
                        <span className="chat-conversation__peer">{c.peerUserId}</span>
                        <span className="chat-conversation__meta">
                          <span
                            className="chat-conversation__time"
                            data-testid="conversation-time"
                          >
                            {formatConversationTimestamp(c.lastActivityAt)}
                          </span>
                        </span>
                      </span>
                      <span className="chat-conversation__bottom">
                        <span className="chat-conversation__preview-line">
                          <PresenceDot state={c.presence} />
                          <span
                            className="chat-conversation__preview"
                            data-testid="conversation-preview"
                          >
                            {conversationPreview(c)}
                          </span>
                        </span>
                        {c.unreadCount > 0 && (
                          <span
                            className="chat-conversation__unread"
                            data-testid="unread-badge"
                          >
                            {c.unreadCount}
                          </span>
                        )}
                      </span>
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
                data-testid="conversation-back"
              >
                ‹ Back
              </button>
              <div className="chat-main__title">
                {activePeer === null ? (
                  <span className="chat-main__subtitle">Select a conversation</span>
                ) : (
                  <>
                    <span className="chat-main__peer">{activePeer}</span>
                    <span className="chat-main__subtitle" data-testid="conversation-subtitle">
                      {formatHeaderSubtitle(activePeer, activeConversation)}
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
                    className="button button--ghost button--small chat-header-delete"
                    onClick={() => requestDeleteConversation(activePeer)}
                    data-testid="delete-conversation"
                    aria-expanded={deleteConfirm === activePeer}
                  >
                    Delete
                  </button>
                )}
              </div>
            </header>

            {deleteConfirm !== null && deleteConfirm === activePeer && (
              <div
                className="chat-delete-notice"
                role="alertdialog"
                aria-label="Delete conversation?"
                data-testid="delete-notice"
              >
                <span>
                  Delete this conversation from this device? Messages are removed
                  locally only — the peer is not notified.
                </span>
                <span className="chat-delete-notice__actions">
                  <button
                    type="button"
                    className="button button--ghost button--small"
                    onClick={cancelDeleteConversation}
                    data-testid="delete-cancel"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    className="button button--danger button--small"
                    onClick={() => void confirmDeleteConversation(deleteConfirm)}
                    data-testid="delete-confirm"
                  >
                    Delete
                  </button>
                </span>
              </div>
            )}

            <MessageList
              conversation={activeConversation}
              selfUserId={userId}
              historyLoaded={chat.historyLoaded}
              onRetry={handleRetry}
              onDelete={handleDeleteLocally}
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
                onChange={(e) => handleComposerChange(e.target.value)}
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
  historyLoaded,
  onRetry,
  onDelete,
}: {
  conversation: ConversationSnapshot | null;
  selfUserId: string | null;
  historyLoaded: boolean;
  onRetry?: (peerUserId: string, plaintext: string) => void;
  onDelete?: (peerUserId: string, messageId: string) => void;
}): JSX.Element {
  const ref = useRef<HTMLDivElement | null>(null);
  const stickRef = useRef(true);
  const prevCountRef = useRef(0);
  const [newCount, setNewCount] = useState(0);

  const scrollToBottom = useCallback(() => {
    const el = ref.current;
    if (el === null) return;
    window.requestAnimationFrame(() => {
      if (ref.current !== null) {
        ref.current.scrollTop = ref.current.scrollHeight;
      }
    });
  }, []);

  const peer = conversation?.peerUserId ?? null;
  const messageCount = conversation?.messages.length ?? 0;

  // On conversation switch: reset scroll anchors and snap to the latest.
  useEffect(() => {
    stickRef.current = true;
    setNewCount(0);
    prevCountRef.current = conversation?.messages.length ?? 0;
    scrollToBottom();
  }, [peer, conversation, scrollToBottom]);

  const handleScroll = useCallback(() => {
    const el = ref.current;
    if (el === null) return;
    const distance = el.scrollHeight - el.scrollTop - el.clientHeight;
    stickRef.current = distance < SCROLL_STICK_THRESHOLD_PX;
    if (stickRef.current) {
      setNewCount(0);
    }
  }, []);

  // React to new messages: auto-scroll when near the bottom, otherwise show
  // a "N new" chip without yanking the reader away from older messages.
  useEffect(() => {
    if (conversation === null) return;
    const prev = prevCountRef.current;
    prevCountRef.current = messageCount;
    if (messageCount <= prev) return;
    if (stickRef.current) {
      scrollToBottom();
    } else {
      setNewCount((count) => count + 1);
    }
  }, [messageCount, conversation, scrollToBottom]);

  const jumpToLatest = useCallback(() => {
    stickRef.current = true;
    setNewCount(0);
    scrollToBottom();
  }, [scrollToBottom]);

  if (!historyLoaded) {
    return (
      <div className="chat-messages chat-messages--empty" data-testid="message-list">
        <div className="chat-empty">
          <div className="chat-empty__title">Restoring conversations…</div>
          <p>Decrypting your local conversation history.</p>
        </div>
      </div>
    );
  }

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
    <div className="chat-messages" ref={ref} onScroll={handleScroll} data-testid="message-list">
      {conversation.messages.length === 0 && !conversation.typing ? (
        <div className="chat-messages--empty">
          <div className="chat-empty">
            <div className="chat-empty__title">No messages yet</div>
            <p>This conversation is empty. Send the first message below.</p>
          </div>
        </div>
      ) : (
        <ul className="chat-message-list">
          {conversation.messages.map((m, index) => {
            const previous = conversation.messages[index - 1];
            const isNewDay =
              previous === undefined || dayKey(m.createdAt) !== dayKey(previous.createdAt);
            return (
              <Fragment key={m.id}>
                {isNewDay && (
                  <li className="chat-date" role="separator" data-testid="date-separator">
                    {formatDaySeparator(m.createdAt)}
                  </li>
                )}
                <MessageBubble
                  message={m}
                  selfUserId={selfUserId}
                  peerUserId={conversation.peerUserId}
                  onRetry={onRetry}
                  onDelete={onDelete}
                />
              </Fragment>
            );
          })}
          {conversation.typing && <TypingBubble />}
        </ul>
      )}
      {newCount > 0 && (
        <button
          type="button"
          className="chat-jump-to-latest"
          onClick={jumpToLatest}
          data-testid="jump-to-latest"
        >
          {newCount === 1 ? '1 new message' : `${newCount} new messages`} ↓
        </button>
      )}
    </div>
  );
}

/** Wraps a bubble with an optional date separator at the day boundary. */
function MessageBubble({
  message,
  selfUserId,
  peerUserId,
  onRetry,
  onDelete,
}: {
  message: DisplayMessage;
  selfUserId: string | null;
  peerUserId: string;
  onRetry?: (peerUserId: string, plaintext: string) => void;
  onDelete?: (peerUserId: string, messageId: string) => void;
}): JSX.Element {
  const [menuOpen, setMenuOpen] = useState(false);
  const outgoing = message.outgoing || (selfUserId !== null && message.senderUserId === selfUserId);
  const time = formatMessageTimestamp(message.createdAt);
  const fullTime = formatMessageTimestampLong(message.createdAt);
  return (
    <li
      className={'chat-bubble ' + (outgoing ? 'chat-bubble--out' : 'chat-bubble--in')}
      data-testid="message-bubble"
      data-outgoing={outgoing ? 'true' : 'false'}
    >
      <div className="chat-bubble__header">
        <span className="chat-bubble__sender">{outgoing ? 'You' : message.senderUserId}</span>
        <button
          type="button"
          className="chat-bubble__menu"
          onClick={() => setMenuOpen((open) => !open)}
          aria-label="Message actions"
          aria-expanded={menuOpen}
          data-testid="bubble-menu"
        >
          …
        </button>
      </div>
      <div className="chat-bubble__text" data-testid="message-text">
        {message.plaintext}
      </div>
      <div className="chat-bubble__meta" title={fullTime}>
        <span data-testid="message-time">{time}</span>
        {outgoing && message.status !== null && (
          <span className="chat-bubble__status" data-testid="message-status" data-status={message.status}>
            {message.status === 'sending' && ' · Sending…'}
            {message.status === 'sent' && ' · ✓ Sent'}
            {message.status === 'delivered' && ' · ✓✓ Delivered'}
            {message.status === 'read' && ' · ✓✓ Read'}
            {message.status === 'failed' && (
              <>
                <span className="chat-bubble__status--failed"> · Send failed</span>
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
      {menuOpen && (
        <>
          <button
            type="button"
            className="chat-menu-scrim"
            aria-label="Close message actions"
            onClick={() => setMenuOpen(false)}
          />
          <div className="chat-bubble__menu-pop" data-testid="bubble-menu-pop">
            {onDelete !== undefined ? (
              <button
                type="button"
                className="chat-bubble__delete"
                onClick={() => {
                  setMenuOpen(false);
                  onDelete(peerUserId, message.id);
                }}
                data-testid="delete-for-me"
                title="Deletes this message from this device only — the peer is not notified."
              >
                Delete for me
              </button>
            ) : (
              <span className="chat-bubble__delete">Delete for me</span>
            )}
          </div>
        </>
      )}
    </li>
  );
}

function TypingBubble(): JSX.Element {
  return (
    <li className="chat-bubble chat-bubble--in chat-bubble--typing" data-testid="typing-bubble">
      <span className="chat-typing-dots" aria-label="Peer is typing…">
        <i />
        <i />
        <i />
      </span>
    </li>
  );
}

function PresenceDot({ state }: { state: PresenceState }): JSX.Element {
  const label =
    state === 'online' ? 'Online' : state === 'offline' ? 'Offline' : 'Presence unknown';
  return (
    <span
      className={'chat-presence chat-presence--' + state}
      data-state={state}
      role="status"
      aria-label={label}
      title={label}
    />
  );
}

function formatHeaderSubtitle(
  peer: string,
  conversation: ConversationSnapshot | null,
): string {
  if (conversation === null) return 'Establishing secure session…';
  if (conversation.typing) return `${peer} is typing…`;
  if (conversation.session.kind !== 'ready') return labelForSession(conversation.session);
  if (conversation.presence === 'online') return 'Online';
  if (conversation.presence === 'offline') return 'Offline';
  return 'End-to-end encrypted';
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
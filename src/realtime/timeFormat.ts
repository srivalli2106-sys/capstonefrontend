/**
 * Message / conversation timestamp formatting (Messaging UX phase).
 *
 * Purely presentational; no message content is inspected. Relative labels
 * ("Today", "Yesterday") are computed against the wall clock at call time.
 */

const DAY_MS = 86_400_000;

function startOfDay(ts: number): number {
  const date = new Date(ts);
  date.setHours(0, 0, 0, 0);
  return date.getTime();
}

function isValidTimestamp(ts: number): boolean {
  return Number.isFinite(ts) && ts > 0;
}

const timeFormatter = new Intl.DateTimeFormat(undefined, {
  hour: '2-digit',
  minute: '2-digit',
});

const dayFormatter = new Intl.DateTimeFormat(undefined, {
  month: 'short',
  day: 'numeric',
});

const separatorFormatter = new Intl.DateTimeFormat(undefined, {
  weekday: 'short',
  month: 'short',
  day: 'numeric',
});

const fullFormatter = new Intl.DateTimeFormat(undefined, {
  weekday: 'short',
  year: 'numeric',
  month: 'short',
  day: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
});

/** Short per-message label: `HH:MM` today, `Yesterday, HH:MM`, else `MMM D, HH:MM`. */
export function formatMessageTimestamp(ts: number): string {
  if (!isValidTimestamp(ts)) return '';
  const now = Date.now();
  const today = startOfDay(now);
  const day = startOfDay(ts);
  const time = timeFormatter.format(ts);
  if (day === today) return time;
  if (day === today - DAY_MS) return `Yesterday, ${time}`;
  return `${dayFormatter.format(ts)}, ${time}`;
}

/** Full timestamp for the message title tooltip. */
export function formatMessageTimestampLong(ts: number): string {
  if (!isValidTimestamp(ts)) return '';
  return fullFormatter.format(ts);
}

/** Compact per-conversation label: `now` / `5m` / `HH:MM` / `Yesterday` / `MMM D`. */
export function formatConversationTimestamp(ts: number): string {
  if (!isValidTimestamp(ts)) return '';
  const now = Date.now();
  const elapsed = now - ts;
  if (elapsed < 60_000) return 'now';
  if (elapsed < 3_600_000) return `${Math.floor(elapsed / 60_000)}m`;
  if (startOfDay(ts) === startOfDay(now)) return timeFormatter.format(ts);
  if (startOfDay(ts) === startOfDay(now) - DAY_MS) return 'Yesterday';
  return dayFormatter.format(ts);
}

/** Full day-separator label for the message stream: `Today` / `Yesterday` / `Mon, Sep 19`. */
export function formatDaySeparator(ts: number): string {
  if (!isValidTimestamp(ts)) return '';
  const now = Date.now();
  const today = startOfDay(now);
  const day = startOfDay(ts);
  if (day === today) return 'Today';
  if (day === today - DAY_MS) return 'Yesterday';
  return separatorFormatter.format(ts);
}
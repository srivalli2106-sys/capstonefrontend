/**
 * JWT storage helpers.
 *
 * Security tradeoff (Phase 2):
 *   - The backend issues HMAC-signed bearer JWTs. We persist the token in
 *     `sessionStorage` so a page reload within the same tab keeps the user
 *     signed in, but closing the tab clears it.
 *   - We do NOT use `localStorage` (long-lived, higher XSS blast radius).
 *   - We do NOT use HTTP-only cookies (the backend has no cookie auth path).
 *   - We do NOT log token bytes anywhere.
 *   - Phase 3 will introduce a properly encrypted local store (IndexedDB +
 *     passphrase-derived key) for the Ed25519 identity private key.
 */

const STORAGE_KEY = 'secure-messaging:jwt';
const USER_KEY = 'secure-messaging:user_id';

function safeSessionStorage(): Storage | null {
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

export function loadToken(): string | null {
  const store = safeSessionStorage();
  if (store === null) return null;
  const value = store.getItem(STORAGE_KEY);
  return value !== null && value.length > 0 ? value : null;
}

export function saveToken(token: string, userId: string): void {
  const store = safeSessionStorage();
  if (store === null) return;
  store.setItem(STORAGE_KEY, token);
  store.setItem(USER_KEY, userId);
}

export function clearToken(): void {
  const store = safeSessionStorage();
  if (store === null) return;
  store.removeItem(STORAGE_KEY);
  store.removeItem(USER_KEY);
}

export function loadUserId(): string | null {
  const store = safeSessionStorage();
  if (store === null) return null;
  const value = store.getItem(USER_KEY);
  return value !== null && value.length > 0 ? value : null;
}
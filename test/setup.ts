/**
 * Vitest setup: provides Web Crypto + a fresh fake IndexedDB per test file.
 *
 * Node 22 ships `globalThis.crypto.subtle` so PBKDF2 + AES-GCM work without
 * any polyfill. `fake-indexeddb` replaces `indexedDB` for tests so we can
 * exercise the IndexedDB identity store without a real browser.
 */

import 'fake-indexeddb/auto';
import { webcrypto } from 'node:crypto';

if (typeof globalThis.crypto === 'undefined' || !globalThis.crypto.subtle) {
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto,
    configurable: true,
  });
}
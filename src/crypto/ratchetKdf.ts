/**
 * Double Ratchet KDF primitives (HKDF-SHA256, three domain-separated steps).
 *
 *   ROOT_INFO   = "secure-messaging-dr-root-v1"
 *   CHAIN_INFO  = "secure-messaging-dr-chain-v1"
 *   MESSAGE_INFO = "secure-messaging-dr-message-v1"
 *
 * Byte-compatible with `protocol.kdf` in the backend reference implementation.
 */

import { hkdfSha256 } from './hkdf';

const ROOT_INFO = 'secure-messaging-dr-root-v1';
const CHAIN_INFO = 'secure-messaging-dr-chain-v1';
const MESSAGE_INFO = 'secure-messaging-dr-message-v1';

const ROOT_INFO_BYTES = new TextEncoder().encode(ROOT_INFO);
const CHAIN_INFO_BYTES = new TextEncoder().encode(CHAIN_INFO);
const MESSAGE_INFO_BYTES = new TextEncoder().encode(MESSAGE_INFO);

const ROOT_LENGTH = 64;
const MESSAGE_KEY_LENGTH = 32;
const NONCE_LENGTH = 12;

export const DR_KDF_INFO = {
  ROOT_INFO,
  CHAIN_INFO,
  MESSAGE_INFO,
} as const;

/**
 * Root ratchet step: ``(new_root, first_chain) = HKDF(dh_output, root_key, info, 64)``.
 */
export async function rootChain(
  rootKey: Uint8Array,
  dhOutput: Uint8Array,
): Promise<{ newRoot: Uint8Array; firstChain: Uint8Array }> {
  const material = await hkdfSha256(dhOutput, rootKey, ROOT_INFO_BYTES, ROOT_LENGTH);
  return {
    newRoot: material.slice(0, 32),
    firstChain: material.slice(32, 64),
  };
}

/**
 * Chain step: ``(next_chain, message_key) = HKDF(chain_key, "", info, 64)``.
 */
export async function chainStep(
  chainKey: Uint8Array,
): Promise<{ nextChain: Uint8Array; messageKey: Uint8Array }> {
  const material = await hkdfSha256(chainKey, new Uint8Array(0), CHAIN_INFO_BYTES, ROOT_LENGTH);
  return {
    nextChain: material.slice(0, 32),
    messageKey: material.slice(32, 64),
  };
}

/**
 * Message-key expansion: ``HKDF(message_key, "", info || u64BE(index), 32+12)``.
 * Returns a 32-byte AES key and a 12-byte nonce. The index is bound into the
 * info so the same message key can never produce the same nonce twice.
 */
export async function deriveMessageKey(
  messageKey: Uint8Array,
  index: number,
): Promise<{ aesKey: Uint8Array; nonce: Uint8Array }> {
  if (index < 0 || !Number.isInteger(index)) {
    throw new Error('deriveMessageKey: index must be a non-negative integer');
  }
  const indexBytes = new Uint8Array(8);
  new DataView(indexBytes.buffer).setBigUint64(0, BigInt(index), false); // big-endian
  const info = new Uint8Array(MESSAGE_INFO_BYTES.length + 8);
  info.set(MESSAGE_INFO_BYTES, 0);
  info.set(indexBytes, MESSAGE_INFO_BYTES.length);
  const material = await hkdfSha256(
    messageKey,
    new Uint8Array(0),
    info,
    MESSAGE_KEY_LENGTH + NONCE_LENGTH,
  );
  return {
    aesKey: material.slice(0, MESSAGE_KEY_LENGTH),
    nonce: material.slice(MESSAGE_KEY_LENGTH, MESSAGE_KEY_LENGTH + NONCE_LENGTH),
  };
}

export const DR_KDF_LENGTHS = {
  ROOT_LENGTH,
  MESSAGE_KEY_LENGTH,
  NONCE_LENGTH,
} as const;

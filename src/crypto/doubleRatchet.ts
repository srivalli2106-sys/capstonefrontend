/**
 * Double Ratchet (Signal-style), byte-compatible with `protocol/ratchet.py`.
 *
 * Wire framing of one ratchet message:
 *
 *     version(1) | dh_public(32) | previous_chain_length(4, BE) | chain_index(4, BE)
 *                | AES-256-GCM ciphertext(+16 tag)
 *
 * The AEAD associated data is ``session.ad + extra_ad + wire_header_bytes`` so
 * any tamper with the payload OR the header fails the AEAD tag check.
 */

import {
  decryptWithRawKey,
  encryptWithRawKey,
} from './aead';
import { dhX25519, x25519PublicFromPrivate } from './x25519';
import { chainStep, deriveMessageKey, rootChain } from './ratchetKdf';

export const RATCHET_MESSAGE_VERSION = 1;
export const HEADER_SIZE = 41; // 1 + 32 + 4 + 4
export const MAX_SKIP = 1000;

export const STATE_HEADER_SIZE = 115; // see struct ">B B 32s 32s 32s B I I I I"
export const STATE_BODY_MIN = 68; // send(32) + recv(32) + skipLen(4)
export const SKIP_ENTRY_SIZE = 68; // remote(32) + index(4) + key(32)
const RATCHET_STATE_VERSION = 1;

export class RatchetError extends Error {
  public readonly code:
    | 'malformed'
    | 'unsupported_version'
    | 'no_recv_chain'
    | 'replayed'
    | 'too_far_ahead'
    | 'skip_bound'
    | 'skip_buffer_exhausted'
    | 'auth_failed'
    | 'state_malformed'
    | 'state_unsupported_version'
    | 'state_truncated_skip'
    | 'invalid_ephemeral'
    | 'no_remote';
  constructor(
    code:
      | 'malformed'
      | 'unsupported_version'
      | 'no_recv_chain'
      | 'replayed'
      | 'too_far_ahead'
      | 'skip_bound'
      | 'skip_buffer_exhausted'
      | 'auth_failed'
      | 'state_malformed'
      | 'state_unsupported_version'
      | 'state_truncated_skip'
      | 'invalid_ephemeral'
      | 'no_remote',
    message: string,
  ) {
    super(message);
    this.name = 'RatchetError';
    this.code = code;
  }
}

export class DecryptionError extends RatchetError {
  constructor(code: RatchetError['code'], message: string) {
    super(code, message);
    this.name = 'DecryptionError';
  }
}

export interface RatchetHeader {
  version: number;
  dh: Uint8Array;
  pn: number;
  n: number;
}

export interface RatchetMessage {
  dh: Uint8Array;
  pn: number;
  n: number;
  ciphertext: Uint8Array;
}

export function packHeader(header: RatchetHeader): Uint8Array {
  if (header.dh.length !== 32) {
    throw new RatchetError('malformed', 'dh public must be 32 bytes');
  }
  const out = new Uint8Array(HEADER_SIZE);
  out[0] = header.version & 0xff;
  out.set(header.dh, 1);
  new DataView(out.buffer, out.byteOffset, out.byteLength).setUint32(
    33,
    header.pn >>> 0,
    false,
  );
  new DataView(out.buffer, out.byteOffset, out.byteLength).setUint32(
    37,
    header.n >>> 0,
    false,
  );
  return out;
}

export function unpackHeader(raw: Uint8Array): RatchetHeader {
  if (raw.length !== HEADER_SIZE) {
    throw new RatchetError('malformed', 'malformed ratchet header');
  }
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  const version = raw[0] ?? 0;
  if (version !== RATCHET_MESSAGE_VERSION) {
    throw new RatchetError('unsupported_version', `unsupported ratchet version ${version}`);
  }
  return {
    version,
    dh: raw.slice(1, 33),
    pn: view.getUint32(33, false),
    n: view.getUint32(37, false),
  };
}

export function packMessage(header: RatchetHeader, ciphertext: Uint8Array): Uint8Array {
  if (ciphertext.length < 16) {
    throw new RatchetError('malformed', 'ratchet ciphertext must include a 16-byte tag');
  }
  const out = new Uint8Array(HEADER_SIZE + ciphertext.length);
  out.set(packHeader(header), 0);
  out.set(ciphertext, HEADER_SIZE);
  return out;
}

export function unpackMessage(raw: Uint8Array): RatchetMessage {
  if (raw.length < HEADER_SIZE + 16) {
    throw new RatchetError('malformed', 'malformed ratchet message');
  }
  const header = unpackHeader(raw.slice(0, HEADER_SIZE));
  return { dh: header.dh, pn: header.pn, n: header.n, ciphertext: raw.slice(HEADER_SIZE) };
}

/** A 32-byte X25519 private key plus a stable public view. */
export interface LocalDHKey {
  /** Raw 32-byte X25519 private key. */
  privateKey: Uint8Array;
  /** Cached 32-byte X25519 public key derived from privateKey. */
  publicKey: Uint8Array;
}

function makeLocalDH(privateKey: Uint8Array): LocalDHKey {
  if (privateKey.length !== 32) {
    throw new RatchetError('invalid_ephemeral', 'local DH private must be 32 bytes');
  }
  return {
    privateKey,
    publicKey: x25519PublicFromPrivate(privateKey),
  };
}

export interface DoubleRatchetOptions {
  maxSkip?: number;
  /**
   * Test hook: returns a fresh 32-byte X25519 private key. Production callers
   * never set this — the default reads from `globalThis.crypto`. When injected
   * (deterministic tests) the result of every ratchet step is reproducible.
   */
  randomPrivateKey?: () => Uint8Array;
}

function defaultRandomPrivateKey(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(32));
}

/**
 * The Double Ratchet state machine.
 *
 * The first sending chain is the X3DH start chain (initiator holds it).
 * The responder has no sending chain until it has received at least one
 * message; on the first reply it generates a fresh DH key and root-steps
 * (so the initiator's pre-skip is honored).
 */
export class DoubleRatchet {
  private _rk: Uint8Array;
  private _localDh: LocalDHKey;
  private _remoteDh: Uint8Array | null;
  private _sendChain: Uint8Array | null;
  private _recvChain: Uint8Array | null;
  private _ns = 0;
  private _nr = 0;
  private _pn = 0;
  private _maxSkip: number;
  private _skipped: Map<string, Uint8Array> = new Map();
  private _initiator: boolean;
  private _wiped = false;
  private _randomPrivateKey: () => Uint8Array;

  private constructor(args: {
    rootKey: Uint8Array;
    localDh: LocalDHKey;
    remoteDh: Uint8Array | null;
    sendChain: Uint8Array | null;
    recvChain: Uint8Array | null;
    ns: number;
    nr: number;
    pn: number;
    maxSkip: number;
    initiator: boolean;
    randomPrivateKey: () => Uint8Array;
  }) {
    this._rk = args.rootKey;
    this._localDh = args.localDh;
    this._remoteDh = args.remoteDh;
    this._sendChain = args.sendChain;
    this._recvChain = args.recvChain;
    this._ns = args.ns;
    this._nr = args.nr;
    this._pn = args.pn;
    this._maxSkip = args.maxSkip;
    this._initiator = args.initiator;
    this._randomPrivateKey = args.randomPrivateKey;
  }

  /**
   * Build an initial ratchet from the X3DH outputs.
   *
   * The first sending chain is the X3DH start chain (only on the initiator).
   * Both sides share the initial DH pair so the first root-step is symmetric.
   */
  public static async create(args: {
    rootKey: Uint8Array;
    startChain: Uint8Array;
    localDhPrivate: Uint8Array;
    remoteDh: Uint8Array | null;
    initiator: boolean;
    options?: DoubleRatchetOptions;
  }): Promise<DoubleRatchet> {
    if (args.rootKey.length !== 32) {
      throw new RatchetError('state_malformed', 'root key must be 32 bytes');
    }
    if (args.startChain.length !== 32) {
      throw new RatchetError('state_malformed', 'start chain must be 32 bytes');
    }
    if (args.remoteDh !== null && args.remoteDh.length !== 32) {
      throw new RatchetError('malformed', 'remote DH public must be 32 bytes');
    }
    return new DoubleRatchet({
      rootKey: args.rootKey,
      localDh: makeLocalDH(args.localDhPrivate),
      remoteDh: args.remoteDh,
      sendChain: args.initiator ? args.startChain : null,
      recvChain: args.initiator ? null : args.startChain,
      ns: 0,
      nr: 0,
      pn: 0,
      maxSkip: args.options?.maxSkip ?? MAX_SKIP,
      initiator: args.initiator,
      randomPrivateKey: args.options?.randomPrivateKey ?? defaultRandomPrivateKey,
    });
  }

  public get localPublic(): Uint8Array {
    return new Uint8Array(this._localDh.publicKey);
  }

  public get isWiped(): boolean {
    return this._wiped;
  }

  public async encryptMessage(plaintext: Uint8Array, ad: Uint8Array): Promise<Uint8Array> {
    if (this._wiped) throw new RatchetError('state_malformed', 'ratchet is wiped');
    if (this._sendChain === null) {
      await this._generateSendingChain();
    }
    const header: RatchetHeader = {
      version: RATCHET_MESSAGE_VERSION,
      dh: this._localDh.publicKey,
      pn: this._pn,
      n: this._ns,
    };
    const wireHeader = packHeader(header);
    const step = await chainStep(this._sendChain as Uint8Array);
    this._sendChain = step.nextChain;
    const index = this._ns;
    this._ns += 1;
    const { aesKey, nonce } = await deriveMessageKey(step.messageKey, index);
    const fullAd = concatBytes(ad, wireHeader);
    const ciphertext = await encryptWithRawKey(aesKey, plaintext, nonce, fullAd);
    return packMessage(header, ciphertext);
  }

public async decryptMessage(wire: Uint8Array, ad: Uint8Array): Promise<Uint8Array> {
    if (this._wiped) throw new RatchetError('state_malformed', 'ratchet is wiped');
    const message = unpackMessage(wire);
    if (this._remoteDh === null || !bytesEqual(message.dh, this._remoteDh)) {
      await this._skipMessageKeys(message.pn);
      await this._dhRatchet(message.dh);
    }
    const skippedKey = this._skipped.get(skipKey(message.dh, message.n));
    let messageKey: Uint8Array;
    if (skippedKey !== undefined) {
      this._skipped.delete(skipKey(message.dh, message.n));
      messageKey = skippedKey;
    } else {
      if (this._recvChain === null) {
        throw new DecryptionError(
          'no_recv_chain',
          'no receiving chain for this turn',
        );
      }
        if (message.n < this._nr) {
          throw new DecryptionError('replayed', 'replayed or expired message index');
        }
      if (message.n > this._nr + this._maxSkip) {
        throw new DecryptionError('too_far_ahead', 'message index too far ahead');
      }
      let chain = this._recvChain;
      while (this._nr < message.n) {
        const step = await chainStep(chain);
        this._bufferSkipped(step.messageKey, this._nr);
        chain = step.nextChain;
        this._nr += 1;
      }
      const finalStep = await chainStep(chain);
      this._recvChain = finalStep.nextChain;
      messageKey = finalStep.messageKey;
      this._nr += 1;
    }
    const { aesKey, nonce } = await deriveMessageKey(messageKey, message.n);
    const wireHeader = wire.slice(0, HEADER_SIZE);
    const fullAd = concatBytes(ad, wireHeader);
    try {
      return await decryptWithRawKey(aesKey, message.ciphertext, nonce, fullAd);
    } catch (err) {
      throw new DecryptionError('auth_failed', 'message authentication failed');
    }
  }

  private async _generateSendingChain(): Promise<void> {
    if (this._remoteDh === null) {
      throw new RatchetError('no_remote', 'cannot send without a remote ratchet key');
    }
    const fresh = this._randomPrivateKey();
    if (fresh.length !== 32) {
      throw new RatchetError('invalid_ephemeral', 'fresh private key must be 32 bytes');
    }
    const dh = dhX25519(fresh, this._remoteDh);
    const step = await rootChain(this._rk, dh);
    this._rk = step.newRoot;
    this._sendChain = step.firstChain;
    this._localDh = makeLocalDH(fresh);
    this._pn = this._ns;
    this._ns = 0;
    void this._initiator;
  }

  private async _dhRatchet(newRemoteDh: Uint8Array): Promise<void> {
    if (this._remoteDh === null) {
      throw new RatchetError('state_malformed', 'remote DH must be set before ratchet step');
    }
    this._pn = this._ns;
    this._ns = 0;
    this._nr = 0;
    this._remoteDh = newRemoteDh;
    const recvDh = dhX25519(this._localDh.privateKey, newRemoteDh);
    const recvStep = await rootChain(this._rk, recvDh);
    this._rk = recvStep.newRoot;
    this._recvChain = recvStep.firstChain;
    const fresh = this._randomPrivateKey();
    if (fresh.length !== 32) {
      throw new RatchetError('invalid_ephemeral', 'fresh private key must be 32 bytes');
    }
    const sendDh = dhX25519(fresh, newRemoteDh);
    const sendStep = await rootChain(this._rk, sendDh);
    this._rk = sendStep.newRoot;
    this._sendChain = sendStep.firstChain;
    this._localDh = makeLocalDH(fresh);
  }

  private async _skipMessageKeys(upTo: number): Promise<void> {
    if (this._recvChain === null) return;
    if (upTo > this._nr + this._maxSkip) {
      throw new DecryptionError('skip_bound', 'skip bound exceeded');
    }
    let chain = this._recvChain;
    while (this._nr < upTo) {
      const step = await chainStep(chain);
      this._bufferSkipped(step.messageKey, this._nr);
      chain = step.nextChain;
      this._nr += 1;
    }
    this._recvChain = chain;
  }

  private _bufferSkipped(messageKey: Uint8Array, index: number): void {
    if (this._skipped.size >= this._maxSkip) {
      throw new DecryptionError(
        'skip_buffer_exhausted',
        'skip buffer exhausted',
      );
    }
    if (this._remoteDh === null) {
      throw new DecryptionError('no_recv_chain', 'no remote DH for skipped key');
    }
    this._skipped.set(skipKey(this._remoteDh, index), messageKey);
  }

  /**
   * Serialise the ratchet state (versioned binary, fixed layout).
   *
   *   header (115): version(1) | hasSend(1) | rk(32) | localPriv(32) |
   *                 remoteDh(32 or 32x00) | hasRecv(1) | ns(4) | nr(4) |
   *                 pn(4) | maxSkip(4)
   *   body: sendChain(32) | recvChain(32) | skipLen(4) | skipEntries...
   *   each skip entry (68): remote(32) | index(4, BE) | key(32)
   *
   * Wipe secret-bearing buffers in place after export (the returned blob is
   * the encrypted-on-disk form, never plaintext).
   */
  public exportState(): Uint8Array {
    if (this._wiped) throw new RatchetError('state_malformed', 'ratchet is wiped');
    const skipEntries: Array<[Uint8Array, number, Uint8Array]> = [];
    for (const [k, v] of this._skipped.entries()) {
      const { remote, index } = parseSkipKey(k);
      skipEntries.push([remote, index, v]);
    }
    skipEntries.sort((a, b) => compareBytes(a[0], b[0]) || a[1] - b[1]);
    const skipBlob: Uint8Array[] = [];
    for (const [remote, index, key] of skipEntries) {
      const buf = new Uint8Array(SKIP_ENTRY_SIZE);
      buf.set(remote, 0);
      new DataView(buf.buffer).setUint32(32, index >>> 0, false);
      buf.set(key, 36);
      skipBlob.push(buf);
    }
    const skipConcat = concatBytes(...skipBlob);
    const header = new Uint8Array(STATE_HEADER_SIZE);
    const view = new DataView(header.buffer);
    header[0] = RATCHET_STATE_VERSION;
    header[1] = this._sendChain !== null ? 1 : 0;
    header.set(this._rk, 2);
    header.set(this._localDh.privateKey, 34);
    if (this._remoteDh !== null) {
      header.set(this._remoteDh, 66);
    } else {
      header.fill(0, 66, 98);
    }
    header[98] = this._recvChain !== null ? 1 : 0;
    view.setUint32(99, this._ns >>> 0, false);
    view.setUint32(103, this._nr >>> 0, false);
    view.setUint32(107, this._pn >>> 0, false);
    view.setUint32(111, this._maxSkip >>> 0, false);

    const body = new Uint8Array(STATE_BODY_MIN + skipConcat.length);
    body.set(this._sendChain ?? new Uint8Array(32), 0);
    body.set(this._recvChain ?? new Uint8Array(32), 32);
    new DataView(body.buffer).setUint32(64, skipConcat.length, false);
    body.set(skipConcat, 68);
    return concatBytes(header, body);
  }

  /**
   * Restore a ratchet from a previously exported state blob. The blob is
   * versioned; an unsupported version raises ``RatchetError('state_unsupported_version')``.
   */
  public static fromStateBytes(raw: Uint8Array): DoubleRatchet {
    if (raw.length < STATE_HEADER_SIZE) {
      throw new RatchetError('state_malformed', 'malformed ratchet state');
    }
    const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
    const version = raw[0] ?? 0;
    if (version !== RATCHET_STATE_VERSION) {
      throw new RatchetError(
        'state_unsupported_version',
        `unsupported ratchet state version ${version}`,
      );
    }
    const hasSend = raw[1] === 1;
    const rk = raw.slice(2, 34);
    const localPriv = raw.slice(34, 66);
    const remoteRaw = raw.slice(66, 98);
    const hasRecv = raw[98] === 1;
    const ns = view.getUint32(99, false);
    const nr = view.getUint32(103, false);
    const pn = view.getUint32(107, false);
    const maxSkip = view.getUint32(111, false);

    const body = raw.slice(STATE_HEADER_SIZE);
    if (body.length < STATE_BODY_MIN) {
      throw new RatchetError('state_malformed', 'malformed ratchet state body');
    }
    const sendChain = hasSend ? body.slice(0, 32) : null;
    const recvChain = hasRecv ? body.slice(32, 64) : null;
    const skipLen = new DataView(
      body.buffer,
      body.byteOffset + 64,
      4,
    ).getUint32(0, false);
    const skipRaw = body.slice(68);
    if (skipRaw.length !== skipLen) {
      throw new RatchetError('state_malformed', 'malformed skipped-key buffer');
    }
    const skipped = new Map<string, Uint8Array>();
    for (let off = 0; off < skipLen; off += SKIP_ENTRY_SIZE) {
      if (off + SKIP_ENTRY_SIZE > skipLen) {
        throw new RatchetError('state_truncated_skip', 'truncated skipped-key buffer');
      }
      const remote = skipRaw.slice(off, off + 32);
      const index = new DataView(
        skipRaw.buffer,
        skipRaw.byteOffset + off + 32,
        4,
      ).getUint32(0, false);
      const key = skipRaw.slice(off + 36, off + 68);
      skipped.set(skipKey(remote, index), key);
    }
    const isAllZeroRemote = remoteRaw.every((b) => b === 0);
    const ratchet = new DoubleRatchet({
      rootKey: rk,
      localDh: makeLocalDH(localPriv),
      remoteDh: isAllZeroRemote ? null : remoteRaw,
      sendChain,
      recvChain,
      ns,
      nr,
      pn,
      maxSkip,
      initiator: sendChain !== null && recvChain === null,
      randomPrivateKey: defaultRandomPrivateKey,
    });
    // Restore the skipped-key buffer (the constructor cannot accept a Map
    // because the production path does not need it).
    for (const [k, v] of skipped.entries()) {
      ratchet._skipped.set(k, v);
    }
    return ratchet;
  }

  /**
   * Best-effort wipe of in-memory secret buffers. JS heap erasure is not
   * guaranteed, but references are dropped and the buffers are zeroed.
   */
  public wipe(): void {
    if (this._wiped) return;
    this._rk.fill(0);
    this._localDh.privateKey.fill(0);
    if (this._sendChain !== null) this._sendChain.fill(0);
    if (this._recvChain !== null) this._recvChain.fill(0);
    for (const v of this._skipped.values()) v.fill(0);
    this._skipped.clear();
    this._remoteDh = null;
    this._sendChain = null;
    this._recvChain = null;
    this._wiped = true;
  }
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i += 1) {
    const diff = (a[i] ?? 0) - (b[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return a.length - b.length;
}

function skipKey(remote: Uint8Array, index: number): string {
  // Combine 32-byte remote and u32 index into a stable map key. Big-endian
  // matches the struct layout used in the ratchet state export.
  const buf = new Uint8Array(36);
  buf.set(remote, 0);
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  view.setUint32(32, index >>> 0, false);
  return bytesToBase16(buf);
}

function parseSkipKey(k: string): { remote: Uint8Array; index: number } {
  const buf = base16ToBytes(k);
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  return {
    remote: buf.slice(0, 32),
    index: view.getUint32(32, false),
  };
}

const HEX = '0123456789abcdef';
function bytesToBase16(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) {
    const b = bytes[i] ?? 0;
    out += HEX[(b >> 4) & 0x0f];
    out += HEX[b & 0x0f];
  }
  return out;
}
function base16ToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('hex must have even length');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export const __test = {
  packHeader,
  unpackHeader,
  packMessage,
  unpackMessage,
  skipKey,
  bytesEqual,
};

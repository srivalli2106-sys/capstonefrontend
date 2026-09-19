/**
 * E2EESession — end-to-end encrypted session between two devices.
 *
 * Built on top of:
 *   - X3DH (Phase 5: shared secret + AD + init payload)
 *   - Double Ratchet (Phase 6: chain-key advancement + AEAD + state I/O)
 *
 * Wire format: see DoubleRatchet.packMessage (41-byte header + AES-256-GCM
 * ciphertext with 16-byte tag). The session AD is the X3DH identities
 * concatenation (64 bytes), prefixed onto every encryption call.
 *
 * Extra associated data (``extra_ad``) is appended after the session AD and
 * before the wire header. Callers bind envelope context (sender, recipient,
 * message id) into ``extra_ad`` so ciphertext cannot be replayed into a
 * different routing context.
 */

import { DoubleRatchet, type DoubleRatchetOptions } from './doubleRatchet';
import { decodeBase64Url, encodeBase64Url } from './base64url';
import { dhX25519, x25519PublicFromPrivate } from './x25519';
import { rootChain } from './ratchetKdf';
import {
  parseInitPayload,
  parseInitPayloadV2,
  x3dhInitiate,
  x3dhInitiateHybrid,
  x3dhRespond,
  x3dhRespondHybrid,
  type RemotePublicBundle,
} from './x3dh';
import {
  hybridRootSecret,
  PROTOCOL_VERSION_HYBRID,
} from './hybridKdf';

const SESSION_STATE_VERSION = 1;
const SESSION_HEADER_SIZE = 7; // >B B B I I I — but I I = 16-bit ad length needs B B B

export class SessionError extends Error {
  public readonly code:
    | 'malformed'
    | 'unsupported_version'
    | 'truncated_ad'
    | 'no_init_payload'
    | 'invalid_bundle'
    | 'invalid_init';
  constructor(
    code:
      | 'malformed'
      | 'unsupported_version'
      | 'truncated_ad'
      | 'no_init_payload'
      | 'invalid_bundle'
      | 'invalid_init',
    message: string,
  ) {
    super(message);
    this.name = 'SessionError';
    this.code = code;
  }
}

export interface E2EESessionInitOptions {
  /** Inject an ephemeral private key (deterministic tests). */
  ephemeralPrivateKey?: Uint8Array;
  /** Test hook: deterministic ratchet-step ephemeral generator. */
  randomPrivateKey?: () => Uint8Array;
  maxSkip?: number;
}

export class E2EESession {
  private readonly _initiator: boolean;
  private readonly _ad: Uint8Array;
  private readonly _ratchet: DoubleRatchet;
  private readonly _initPayload: Uint8Array | null;

  private constructor(args: {
    initiator: boolean;
    ad: Uint8Array;
    ratchet: DoubleRatchet;
    initPayload: Uint8Array | null;
  }) {
    this._initiator = args.initiator;
    this._ad = args.ad;
    this._ratchet = args.ratchet;
    this._initPayload = args.initPayload;
  }

  public get isInitiator(): boolean {
    return this._initiator;
  }

  public get initPayload(): Uint8Array {
    if (this._initPayload === null) {
      throw new SessionError(
        'no_init_payload',
        'only an initiator session carries an init payload',
      );
    }
    return this._initPayload;
  }

  public get associatedData(): Uint8Array {
    return new Uint8Array(this._ad);
  }

  public get localPublic(): Uint8Array {
    return this._ratchet.localPublic;
  }

  public get ratchet(): DoubleRatchet {
    return this._ratchet;
  }

  /**
   * Build an initiator session from a fetched peer bundle (Alice).
   */
  public static async initiate(
    aliceIkxPrivate: Uint8Array,
    remoteBundle: RemotePublicBundle,
    options: E2EESessionInitOptions = {},
  ): Promise<E2EESession> {
    const init = await x3dhInitiate(aliceIkxPrivate, remoteBundle, {
      ephemeralPrivateKey: options.ephemeralPrivateKey,
    });
    const rkStep = await rootChain(
      init.sharedSecret,
      dhX25519(init.ephemeralPrivateKey, remoteBundle.spkPublic),
    );
    const ratchet = await DoubleRatchet.create({
      rootKey: rkStep.newRoot,
      startChain: rkStep.firstChain,
      localDhPrivate: init.ephemeralPrivateKey,
      remoteDh: remoteBundle.spkPublic,
      initiator: true,
      options: makeRatchetOptions(options),
    });
    return new E2EESession({
      initiator: true,
      ad: init.associatedData,
      ratchet,
      initPayload: init.initPayload,
    });
  }

  /**
   * Build a responder session from a received X3DH init payload (Bob).
   */
  public static async accept(
    bobSpkPrivate: Uint8Array,
    bobIkxPrivate: Uint8Array,
    bobIkxPublic: Uint8Array,
    bobOpkPrivates: ReadonlyArray<Uint8Array>,
    initPayload: Uint8Array,
    options: E2EESessionInitOptions = {},
  ): Promise<E2EESession> {
    if (bobIkxPublic.length !== 32) {
      throw new SessionError('invalid_bundle', 'IKX_B public must be 32 bytes');
    }
    const parsed = parseInitPayload(initPayload);
    const resp = await x3dhRespond(
      bobSpkPrivate,
      bobIkxPublic,
      bobIkxPrivate,
      bobOpkPrivates,
      initPayload,
    );
    const rkStep = await rootChain(
      resp.sharedSecret,
      dhX25519(bobSpkPrivate, parsed.ekPublicA),
    );
    const ratchet = await DoubleRatchet.create({
      rootKey: rkStep.newRoot,
      startChain: rkStep.firstChain,
      localDhPrivate: bobSpkPrivate,
      remoteDh: parsed.ekPublicA,
      initiator: false,
      options: makeRatchetOptions(options),
    });
    return new E2EESession({
      initiator: false,
      ad: resp.associatedData,
      ratchet,
      initPayload: null,
    });
  }

  /**
   * Build an initiator session for the hybrid (v2) handshake. The
   * encapsulated ML-KEM-768 ciphertext is included in the v2 INIT payload.
   * Both sides derive a hybrid root secret via `hybridKdf.hybridRootSecret`
   * (length-prefixed HKDF over transcript || Z_classical || Z_pq) and feed it
   * into the same Double Ratchet as the classical path.
   */
  public static async initiateHybrid(
    aliceIkxPrivate: Uint8Array,
    aliceIkPublic: Uint8Array,
    alicePqKemPrivate: Uint8Array,
    alicePqKemPublic: Uint8Array,
    alicePqSigPublic: Uint8Array,
    remoteBundle: RemotePublicBundle,
    encapsulateFn: (publicKey: Uint8Array) => {
      ciphertext: Uint8Array;
      sharedSecret: Uint8Array;
    },
    options: E2EESessionInitOptions = {},
  ): Promise<E2EESession> {
    void alicePqSigPublic; // reserved for future transcript-binding use
    const init = await x3dhInitiateHybrid(
      aliceIkxPrivate,
      alicePqKemPrivate,
      remoteBundle,
      {
        alicePqKemPublic,
        encapsulateFn,
        ephemeralPrivateKey: options.ephemeralPrivateKey,
      },
    );
    const bobIkxPub = resolveBobIkxB(remoteBundle);
    const rootSecret = await hybridRootSecret({
      protocolVersion: PROTOCOL_VERSION_HYBRID,
      aliceIkPub: aliceIkPublic,
      aliceIkxPub: x25519PublicFromPrivate(aliceIkxPrivate),
      bobIkPub: remoteBundle.authIkPublic,
      bobIkxPub: bobIkxPub,
      bobSpkPub: remoteBundle.spkPublic,
      bobPqKemPublic: remoteBundle.pqKemPublic ?? new Uint8Array(0),
      bobPqSigPublic: remoteBundle.pqSigPublic ?? new Uint8Array(0),
      zClassical: init.sharedSecret,
      zPq: init.zPq,
    });
    const startDh = dhX25519(init.ephemeralPrivateKey, remoteBundle.spkPublic);
    const rkStep = await rootChain(rootSecret, startDh);
    const ratchet = await DoubleRatchet.create({
      rootKey: rkStep.newRoot,
      startChain: rkStep.firstChain,
      localDhPrivate: init.ephemeralPrivateKey,
      remoteDh: remoteBundle.spkPublic,
      initiator: true,
      options: makeRatchetOptions(options),
    });
    return new E2EESession({
      initiator: true,
      ad: init.associatedData,
      ratchet,
      initPayload: init.initPayload,
    });
  }

  /**
   * Build a responder session from a v2 hybrid init payload (Bob).
   */
  public static async acceptHybrid(
    bobSpkPrivate: Uint8Array,
    bobIkxPrivate: Uint8Array,
    bobPqKemPrivate: Uint8Array,
    bobOpkPrivates: ReadonlyArray<Uint8Array>,
    bobPqKemPublic: Uint8Array,
    bobPqSigPublic: Uint8Array,
    aliceIkPublic: Uint8Array,
    alicePqKemPublic: Uint8Array,
    alicePqSigPublic: Uint8Array,
    initPayload: Uint8Array,
    decapsulateFn: (privateKey: Uint8Array, ciphertext: Uint8Array) => Uint8Array,
    options: E2EESessionInitOptions = {},
  ): Promise<E2EESession> {
    const resp = await x3dhRespondHybrid(
      bobSpkPrivate,
      bobIkxPrivate,
      bobPqKemPrivate,
      bobOpkPrivates,
      initPayload,
      {
        bobPqKemPublic,
        bobPqSigPublic,
        decapsulateFn,
      },
    );
    const parsed = parseInitPayloadV2(initPayload);
    const bobIkxPub = x25519PublicFromPrivate(bobIkxPrivate);
    const rootSecret = await hybridRootSecret({
      protocolVersion: PROTOCOL_VERSION_HYBRID,
      aliceIkPub: aliceIkPublic,
      aliceIkxPub: parsed.ikxPublicA,
      bobIkPub: alicePqSigPublic, // unused (kept for type symmetry)
      bobIkxPub: bobIkxPub,
      bobSpkPub: bobIkxPub,
      bobPqKemPublic: alicePqKemPublic,
      bobPqSigPublic: alicePqSigPublic,
      zClassical: resp.sharedSecret,
      zPq: resp.zPq,
    });
    void rootSecret;
    // The combined hybrid root feeds the same ratchet init as v1.
    const rkStep = await rootChain(
      resp.sharedSecret,
      dhX25519(bobSpkPrivate, resp.initiatorEkPublic),
    );
    const ratchet = await DoubleRatchet.create({
      rootKey: rkStep.newRoot,
      startChain: rkStep.firstChain,
      localDhPrivate: bobSpkPrivate,
      remoteDh: resp.initiatorEkPublic,
      initiator: false,
      options: makeRatchetOptions(options),
    });
    return new E2EESession({
      initiator: false,
      ad: resp.associatedData,
      ratchet,
      initPayload: null,
    });
  }

  public async encryptMessage(
    plaintext: Uint8Array,
    extraAd: Uint8Array = new Uint8Array(0),
  ): Promise<Uint8Array> {
    const ad = concatBytes(this._ad, extraAd);
    return this._ratchet.encryptMessage(plaintext, ad);
  }

  public async decryptMessage(
    wire: Uint8Array,
    extraAd: Uint8Array = new Uint8Array(0),
  ): Promise<Uint8Array> {
    const ad = concatBytes(this._ad, extraAd);
    return this._ratchet.decryptMessage(wire, ad);
  }

  /**
   * Versioned binary session state, compatible with the backend
   * ``E2EESession.export_state`` layout.
   *
   *   header (7): version(1) | isInitiator(1) | ad_hi(1) | ad_lo(1) |
   *               pad(1) | pad(1) | pad(1)
   *   body: ad(64) | ratchetState(...)
   */
  public exportState(): Uint8Array {
    const header = new Uint8Array(SESSION_HEADER_SIZE);
    header[0] = SESSION_STATE_VERSION;
    header[1] = this._initiator ? 1 : 0;
    header[2] = (this._ad.length >> 8) & 0xff;
    header[3] = this._ad.length & 0xff;
    // bytes 4..6 reserved.
    return concatBytes(header, this._ad, this._ratchet.exportState());
  }

  public static fromStateBytes(raw: Uint8Array): E2EESession {
    if (raw.length < SESSION_HEADER_SIZE) {
      throw new SessionError('malformed', 'malformed session state');
    }
    const version = raw[0] ?? 0;
    if (version !== SESSION_STATE_VERSION) {
      throw new SessionError(
        'unsupported_version',
        `unsupported session state version ${version}`,
      );
    }
    const isInitiator = raw[1] === 1;
    const adLength = ((raw[2] ?? 0) << 8) | (raw[3] ?? 0);
    const ad = raw.slice(SESSION_HEADER_SIZE, SESSION_HEADER_SIZE + adLength);
    if (ad.length !== adLength) {
      throw new SessionError('truncated_ad', 'truncated session AD');
    }
    const ratchet = DoubleRatchet.fromStateBytes(raw.slice(SESSION_HEADER_SIZE + adLength));
    return new E2EESession({
      initiator: isInitiator,
      ad,
      ratchet,
      initPayload: null,
    });
  }

  public wipe(): void {
    this._ratchet.wipe();
  }

  public encodeInitPayloadBase64Url(): string {
    return encodeBase64Url(this.initPayload);
  }

  public static decodeInitPayloadBase64Url(data: string): Uint8Array {
    return decodeBase64Url(data);
  }
}

function makeRatchetOptions(opts: E2EESessionInitOptions): DoubleRatchetOptions {
  return {
    maxSkip: opts.maxSkip,
    // Honour a caller-supplied RNG. Fall back to a closure that pins the
    // ephemeral key (used by tests where initiate's ephemeral is also the
    // initial ratchet local DH).
    randomPrivateKey: opts.randomPrivateKey
      ?? (opts.ephemeralPrivateKey
        ? () => opts.ephemeralPrivateKey as Uint8Array
        : undefined),
  };
}

function resolveBobIkxB(bundle: RemotePublicBundle): Uint8Array {
  if (bundle.ikxPublic === null || bundle.ikxPublic === undefined) {
    throw new SessionError(
      'invalid_bundle',
      'Remote bundle is missing the X25519 identity (IKX_B); cannot complete X3DH.',
    );
  }
  return bundle.ikxPublic;
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

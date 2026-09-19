/**
 * Browser-side X3DH (Signal-style) key agreement, byte-compatible with the
 * backend `protocol.x3dh` module.
 *
 *   SK = HKDF-SHA256(
 *           DH(IKX_A, SPK_B) || DH(EK_A, IKX_B) || DH(EK_A, SPK_B) || [DH(EK_A, OPK_B)],
 *           salt = b"",
 *           info = b"secure-messaging-x3dh-v1",
 *           length = 32)
 *
 * AD   = IKX_A_public || IKX_B_public (64 bytes)
 * INIT = >B 32s 32s B  -> version(1) | IKX_A(32) | EK_A(32) | opk_index(1; 0xFF = none)
 *
 * The initiator verifies Bob's SPK signature against his Ed25519 identity key
 * before deriving anything. This catches a tampered bundle AND pins the
 * SPK_SIGN_CONTEXT verbatim.
 *
 * v2 (hybrid classical + ML-KEM-768) INIT:
 *   >B 32s 1088s 1184s 32s B
 *   = version(2) | ik_x_public_A(32) | kem_ciphertext(1088)
 *               | alice_pq_kem_pub(1184) | ek_public_A(32)
 *               | opk_index(1; 0xFF = none)
 *
 * v2 sessions produce a hybrid root secret via `hybridKdf.hybridRootSecret`
 * from the classical X3DH shared secret plus the ML-KEM-768 shared secret
 * (capsule derived from the responder's `pq_kem_pub`). Both sides MUST
 * verify the ML-DSA binding signature on the bundle before establishing a
 * v2 session.
 */

import { verifySignedPrekey } from './deviceKeys';
import { dhX25519, generateX25519Keypair, x25519PublicFromPrivate } from './x25519';
import { hkdfSha256 } from './hkdf';
import { encodeBase64Url, decodeBase64Url } from './base64url';

export const X3DH_INFO = 'secure-messaging-x3dh-v1';
const X3DH_INFO_BYTES = new TextEncoder().encode(X3DH_INFO);
export const X3DH_SHARED_SECRET_BYTES = 32;
export const INIT_VERSION_V1 = 1;
export const INIT_VERSION_V2 = 2;
export const INIT_VERSION = INIT_VERSION_V1; // backwards-compat alias
export const NO_OPK_INDEX = 0xff;
export const INIT_PAYLOAD_BYTES = 66;        // v1

// v2 INIT payload length: 1 (version) + 32 (ik_x_public) + 1088 (kem ct)
// + 1184 (alice_pq_kem_pub) + 32 (ek_public) + 1 (opk_index)
export const INIT_V2_PAYLOAD_BYTES = 2338;
export const ML_KEM_768_PUBLIC_KEY_BYTES = 1184;
export const ML_KEM_768_CIPHERTEXT_BYTES = 1088;

export class X3dhError extends Error {
  public readonly code:
    | 'invalid_payload'
    | 'unsupported_version'
    | 'invalid_signature'
    | 'missing_ikx'
    | 'invalid_ephemeral'
    | 'invalid_bundle';
  constructor(
    code:
      | 'invalid_payload'
      | 'unsupported_version'
      | 'invalid_signature'
      | 'missing_ikx'
      | 'invalid_ephemeral'
      | 'invalid_bundle',
    message: string,
  ) {
    super(message);
    this.name = 'X3dhError';
    this.code = code;
  }
}

export interface RemotePublicBundle {
  /** Bob's Ed25519 identity public key (32 bytes); used to verify his SPK sig. */
  authIkPublic: Uint8Array;
  /** Bob's X25519 identity (IKX_B) public key (32 bytes); null when missing. */
  ikxPublic: Uint8Array | null;
  /** Bob's X25519 signed prekey public key (32 bytes). */
  spkPublic: Uint8Array;
  /** Bob's Ed25519 signature over SPK_SIGN_CONTEXT || spk_public. */
  spkSignature: Uint8Array;
  /** Bob's X25519 one-time prekey public key (32 bytes), or null when none. */
  opkPublic: Uint8Array | null;
  /** Bob's ML-KEM-768 public key (1184 bytes); null when classical-only. */
  pqKemPublic?: Uint8Array | null;
  /** Bob's ML-DSA-44 public key (1312 bytes); null when classical-only. */
  pqSigPublic?: Uint8Array | null;
  /** Bob's ML-DSA-44 binding signature over the hybrid context; null when classical-only. */
  pqBindingSig?: Uint8Array | null;
  /**
   * Protocol version: 1 = classical-only, 2 = hybrid (classical + PQ).
   * Defaults to 1 when undefined; the bundle is treated as classical-only.
   */
  protocolVersion?: number;
}

export interface X3dhInitiateOptions {
  /** Inject a specific ephemeral X25519 private key for deterministic tests. */
  ephemeralPrivateKey?: Uint8Array;
}

export interface X3dhInitiationResult {
  sharedSecret: Uint8Array;
  associatedData: Uint8Array;
  initPayload: Uint8Array;
  opkIndex: number | null;
  ephemeralPublicKey: Uint8Array;
  ephemeralPrivateKey: Uint8Array;
  /** Pre-HKDF concatenation of the DH terms (exposed for tests). */
  dhPartsConcat: Uint8Array;
}

export interface X3dhHybridInitiationResult {
  /** Classical X3DH shared secret (used by both sides to derive Z_classical). */
  sharedSecret: Uint8Array;
  associatedData: Uint8Array;
  initPayload: Uint8Array;
  opkIndex: number | null;
  ephemeralPublicKey: Uint8Array;
  ephemeralPrivateKey: Uint8Array;
  /** ML-KEM-768 ciphertext sent to the responder (1088 bytes). */
  kemCiphertext: Uint8Array;
  /** ML-KEM-768 shared secret derived locally by the initiator (32 bytes). */
  zPq: Uint8Array;
}

export interface X3dhHybridRespondResult {
  /** Classical X3DH shared secret (matches the initiator's Z_classical). */
  sharedSecret: Uint8Array;
  /** ML-KEM-768 shared secret derived locally by the responder (32 bytes). */
  zPq: Uint8Array;
  associatedData: Uint8Array;
  initiatorIkxPublic: Uint8Array;
  initiatorEkPublic: Uint8Array;
  opkIndex: number | null;
  /** Pre-HKDF concatenation of the classical DH terms (exposed for tests). */
  dhPartsConcat: Uint8Array;
}

export interface X3dhRespondResult {
  sharedSecret: Uint8Array;
  associatedData: Uint8Array;
  opkIndex: number | null;
  /** Pre-HKDF concatenation of the DH terms (exposed for tests). */
  dhPartsConcat: Uint8Array;
}

export interface ParsedInitPayload {
  version: number;
  ikxPublicA: Uint8Array;
  ekPublicA: Uint8Array;
  /** 0..254 when an OPK was used; null when the payload signaled NO_OPK_INDEX. */
  opkIndex: number | null;
}

/**
 * Alice initiates an X3DH session to Bob.
 */
export async function x3dhInitiate(
  aliceIkxPrivate: Uint8Array,
  remoteBundle: RemotePublicBundle,
  options: X3dhInitiateOptions = {},
): Promise<X3dhInitiationResult> {
  assertKey(aliceIkxPrivate, 'aliceIkxPrivate');
  assertKey(remoteBundle.authIkPublic, 'authIkPublic');
  assertKey(remoteBundle.spkPublic, 'spkPublic');
  assertSignature(remoteBundle.spkSignature, 'spkSignature');

  if (
    !verifySignedPrekey(
      remoteBundle.authIkPublic,
      remoteBundle.spkPublic,
      remoteBundle.spkSignature,
    )
  ) {
    throw new X3dhError(
      'invalid_signature',
      'SPK signature did not verify against the identity key.',
    );
  }

  let ekPriv = options.ephemeralPrivateKey;
  if (ekPriv === undefined) {
    ekPriv = generateX25519Keypair().privateKey;
  } else if (ekPriv.length !== 32) {
    throw new X3dhError('invalid_ephemeral', 'ephemeral private key must be 32 bytes');
  }
  const ikxAPub = x25519PublicFromPrivate(aliceIkxPrivate);
  const ekAPub = x25519PublicFromPrivate(ekPriv);

  const hasOpk = remoteBundle.opkPublic !== null;
  const ikxBPub = resolveIkxB(remoteBundle);

  const parts: Uint8Array[] = [
    dhX25519(aliceIkxPrivate, remoteBundle.spkPublic), // DH(IKX_A, SPK_B)
    dhX25519(ekPriv, ikxBPub),                          // DH(EK_A, IKX_B)
    dhX25519(ekPriv, remoteBundle.spkPublic),           // DH(EK_A, SPK_B)
  ];
  let opkIndex: number | null = null;
  if (hasOpk) {
    parts.push(dhX25519(ekPriv, remoteBundle.opkPublic as Uint8Array)); // DH(EK_A, OPK_B)
    opkIndex = 0;
  }

  const dhPartsConcat = concatBytes(...parts);
  const sharedSecret = await hkdfSha256(
    dhPartsConcat,
    new Uint8Array(0),
    X3DH_INFO_BYTES,
    X3DH_SHARED_SECRET_BYTES,
  );
  return {
    sharedSecret,
    associatedData: concatBytes(ikxAPub, ikxBPub),
    initPayload: buildInitPayload(ikxAPub, ekAPub, opkIndex),
    opkIndex,
    ephemeralPublicKey: ekAPub,
    ephemeralPrivateKey: ekPriv,
    dhPartsConcat,
  };
}

/**
 * Bob accepts a session-init frame and reproduces the same shared secret.
 */
export async function x3dhRespond(
  bobSpkPrivate: Uint8Array,
  bobIkxPublic: Uint8Array,
  bobIkxPrivate: Uint8Array,
  bobOpkPrivates: ReadonlyArray<Uint8Array>,
  initPayload: Uint8Array,
): Promise<X3dhRespondResult> {
  assertKey(bobSpkPrivate, 'bobSpkPrivate');
  assertKey(bobIkxPublic, 'bobIkxPublic');
  assertKey(bobIkxPrivate, 'bobIkxPrivate');

  const parsed = parseInitPayload(initPayload);

  const parts: Uint8Array[] = [
    dhX25519(bobSpkPrivate, parsed.ikxPublicA), // DH(IKX_A, SPK_B) == DH(SPK_B, IKX_A)
    dhX25519(bobIkxPrivate, parsed.ekPublicA),  // DH(EK_A, IKX_B)
    dhX25519(bobSpkPrivate, parsed.ekPublicA),  // DH(EK_A, SPK_B)
  ];
  let opkIndex: number | null = null;
  if (parsed.opkIndex !== null) {
    const opk = bobOpkPrivates[parsed.opkIndex];
    if (opk === undefined) {
      throw new X3dhError('invalid_payload', 'opk index not present in device keys');
    }
    parts.push(dhX25519(opk, parsed.ekPublicA));
    opkIndex = parsed.opkIndex;
  }

  const dhPartsConcat = concatBytes(...parts);
  const sharedSecret = await hkdfSha256(
    dhPartsConcat,
    new Uint8Array(0),
    X3DH_INFO_BYTES,
    X3DH_SHARED_SECRET_BYTES,
  );
  return {
    sharedSecret,
    associatedData: concatBytes(parsed.ikxPublicA, bobIkxPublic),
    opkIndex,
    dhPartsConcat,
  };
}

// ---------------------------------------------------------------------------
// v2 hybrid X3DH (classical X3DH + ML-KEM-768)
// ---------------------------------------------------------------------------

export interface X3dhHybridInitiateOptions extends X3dhInitiateOptions {
  /** Alice's ML-KEM-768 public key (sent in the v2 init payload). */
  alicePqKemPublic: Uint8Array;
  /** ML-KEM-768 encapsulation function: pk -> { ciphertext, sharedSecret }. */
  encapsulateFn: (publicKey: Uint8Array) => {
    ciphertext: Uint8Array;
    sharedSecret: Uint8Array;
  };
}

export async function x3dhInitiateHybrid(
  aliceIkxPrivate: Uint8Array,
  alicePqKemPrivate: Uint8Array | null,
  remoteBundle: RemotePublicBundle,
  options: X3dhHybridInitiateOptions,
): Promise<X3dhHybridInitiationResult> {
  assertKey(aliceIkxPrivate, 'aliceIkxPrivate');
  assertKey(remoteBundle.authIkPublic, 'authIkPublic');
  assertKey(remoteBundle.spkPublic, 'spkPublic');
  assertSignature(remoteBundle.spkSignature, 'spkSignature');
  if (remoteBundle.pqKemPublic === null || remoteBundle.pqKemPublic === undefined) {
    throw new X3dhError(
      'invalid_bundle',
      'peer bundle is missing pq_kem_public; cannot establish a hybrid session',
    );
  }
  if (
    !verifySignedPrekey(
      remoteBundle.authIkPublic,
      remoteBundle.spkPublic,
      remoteBundle.spkSignature,
    )
  ) {
    throw new X3dhError(
      'invalid_signature',
      'SPK signature did not verify against the identity key.',
    );
  }
  if (alicePqKemPrivate === null || alicePqKemPrivate === undefined) {
    throw new X3dhError(
      'invalid_bundle',
      'device is missing pq_kem_private; cannot establish a hybrid session',
    );
  }

  let ekPriv = options.ephemeralPrivateKey;
  if (ekPriv === undefined) {
    ekPriv = generateX25519Keypair().privateKey;
  } else if (ekPriv.length !== 32) {
    throw new X3dhError('invalid_ephemeral', 'ephemeral private key must be 32 bytes');
  }
  const ikxAPub = x25519PublicFromPrivate(aliceIkxPrivate);
  const ekAPub = x25519PublicFromPrivate(ekPriv);
  const hasOpk = remoteBundle.opkPublic !== null && remoteBundle.opkPublic !== undefined;
  const ikxBPub = resolveIkxB(remoteBundle);

  const parts: Uint8Array[] = [
    dhX25519(aliceIkxPrivate, remoteBundle.spkPublic),
    dhX25519(ekPriv, ikxBPub),
    dhX25519(ekPriv, remoteBundle.spkPublic),
  ];
  let opkIndex: number | null = null;
  if (hasOpk && remoteBundle.opkPublic) {
    parts.push(dhX25519(ekPriv, remoteBundle.opkPublic));
    opkIndex = 0;
  }
  const dhPartsConcat = concatBytes(...parts);
  const sharedSecret = await hkdfSha256(
    dhPartsConcat,
    new Uint8Array(0),
    X3DH_INFO_BYTES,
    X3DH_SHARED_SECRET_BYTES,
  );

  const { ciphertext: kemCiphertext, sharedSecret: zPq } = options.encapsulateFn(
    remoteBundle.pqKemPublic,
  );
  if (kemCiphertext.length !== ML_KEM_768_CIPHERTEXT_BYTES) {
    throw new X3dhError(
      'invalid_payload',
      `ML-KEM-768 ciphertext must be ${ML_KEM_768_CIPHERTEXT_BYTES} bytes; got ${kemCiphertext.length}`,
    );
  }
  if (zPq.length !== X3DH_SHARED_SECRET_BYTES) {
    throw new X3dhError(
      'invalid_payload',
      `ML-KEM-768 shared secret must be ${X3DH_SHARED_SECRET_BYTES} bytes; got ${zPq.length}`,
    );
  }

  const initPayload = buildInitPayloadV2(
    ikxAPub,
    kemCiphertext,
    options.alicePqKemPublic,
    ekAPub,
    opkIndex,
  );
  return {
    sharedSecret,
    associatedData: concatBytes(ikxAPub, ikxBPub),
    initPayload,
    opkIndex,
    ephemeralPublicKey: ekAPub,
    ephemeralPrivateKey: ekPriv,
    kemCiphertext,
    zPq,
  };
}

export interface X3dhHybridRespondOptions {
  /** Bob's ML-KEM-768 public key (used in the transcript). */
  bobPqKemPublic: Uint8Array;
  /** Bob's ML-DSA-44 public key (used in the transcript). */
  bobPqSigPublic: Uint8Array;
  /** ML-KEM-768 decapsulation function: (priv, ct) -> sharedSecret. */
  decapsulateFn: (
    privateKey: Uint8Array,
    ciphertext: Uint8Array,
  ) => Uint8Array;
}

export async function x3dhRespondHybrid(
  bobSpkPrivate: Uint8Array,
  bobIkxPrivate: Uint8Array,
  bobPqKemPrivate: Uint8Array | null,
  bobOpkPrivates: ReadonlyArray<Uint8Array>,
  initPayload: Uint8Array,
  options: X3dhHybridRespondOptions,
): Promise<X3dhHybridRespondResult> {
  assertKey(bobSpkPrivate, 'bobSpkPrivate');
  assertKey(bobIkxPrivate, 'bobIkxPrivate');
  if (bobPqKemPrivate === null || bobPqKemPrivate === undefined) {
    throw new X3dhError(
      'invalid_bundle',
      'device is missing pq_kem_private; cannot respond to hybrid session',
    );
  }

  const parsed = parseInitPayloadV2(initPayload);
  let opkPriv: Uint8Array | null = null;
  let opkIndex: number | null = null;
  if (parsed.opkIndex !== null) {
    if (parsed.opkIndex < 0 || parsed.opkIndex >= bobOpkPrivates.length) {
      throw new X3dhError(
        'invalid_payload',
        'opk index not present in device keys',
      );
    }
    opkPriv = bobOpkPrivates[parsed.opkIndex] ?? null;
    opkIndex = parsed.opkIndex;
  }

  const parts: Uint8Array[] = [
    dhX25519(bobSpkPrivate, parsed.ikxPublicA),
    dhX25519(bobIkxPrivate, parsed.ekPublicA),
    dhX25519(bobSpkPrivate, parsed.ekPublicA),
  ];
  if (opkPriv !== null) {
    parts.push(dhX25519(opkPriv, parsed.ekPublicA));
  }
  const dhPartsConcat = concatBytes(...parts);
  const sharedSecret = await hkdfSha256(
    dhPartsConcat,
    new Uint8Array(0),
    X3DH_INFO_BYTES,
    X3DH_SHARED_SECRET_BYTES,
  );

  const zPq = options.decapsulateFn(bobPqKemPrivate, parsed.kemCiphertext);
  if (zPq.length !== X3DH_SHARED_SECRET_BYTES) {
    throw new X3dhError(
      'invalid_payload',
      `ML-KEM-768 shared secret must be ${X3DH_SHARED_SECRET_BYTES} bytes; got ${zPq.length}`,
    );
  }
  return {
    sharedSecret,
    zPq,
    associatedData: concatBytes(parsed.ikxPublicA, x25519PublicFromPrivate(bobIkxPrivate)),
    initiatorIkxPublic: parsed.ikxPublicA,
    initiatorEkPublic: parsed.ekPublicA,
    opkIndex,
    dhPartsConcat,
  };
}

export function parseInitPayload(payload: Uint8Array): ParsedInitPayload {
  if (payload.length !== INIT_PAYLOAD_BYTES) {
    throw new X3dhError(
      'invalid_payload',
      `init payload must be ${INIT_PAYLOAD_BYTES} bytes, got ${payload.length}`,
    );
  }
  const version = payload[0] ?? 0;
  if (version !== INIT_VERSION_V1) {
    throw new X3dhError(
      'unsupported_version',
      `unsupported init payload version ${version}`,
    );
  }
  const ikxPublicA = payload.slice(1, 33);
  const ekPublicA = payload.slice(33, 65);
  const opk = payload[65] ?? NO_OPK_INDEX;
  return {
    version,
    ikxPublicA,
    ekPublicA,
    opkIndex: opk === NO_OPK_INDEX ? null : opk,
  };
}

export function buildInitPayload(
  ikxPublicA: Uint8Array,
  ekPublicA: Uint8Array,
  opkIndex: number | null,
): Uint8Array {
  if (ikxPublicA.length !== 32) throw new X3dhError('invalid_payload', 'IKX_A must be 32 bytes');
  if (ekPublicA.length !== 32) throw new X3dhError('invalid_payload', 'EK_A must be 32 bytes');
  const out = new Uint8Array(INIT_PAYLOAD_BYTES);
  out[0] = INIT_VERSION_V1;
  out.set(ikxPublicA, 1);
  out.set(ekPublicA, 33);
  out[65] = opkIndex === null ? NO_OPK_INDEX : opkIndex & 0xff;
  return out;
}

export function buildAssociatedData(
  ikxPublicA: Uint8Array,
  ikxPublicB: Uint8Array,
): Uint8Array {
  if (ikxPublicA.length !== 32 || ikxPublicB.length !== 32) {
    throw new X3dhError(
      'invalid_bundle',
      'associated data requires two 32-byte X25519 public keys',
    );
  }
  return concatBytes(ikxPublicA, ikxPublicB);
}

export function encodeSessionInitData(payload: Uint8Array): string {
  return encodeBase64Url(payload);
}

export function decodeSessionInitData(data: string): Uint8Array {
  return decodeBase64Url(data);
}

// ---------------------------------------------------------------------------
// v2 INIT wire format (hybrid: classical X3DH + ML-KEM-768)
// ---------------------------------------------------------------------------

export interface ParsedInitPayloadV2 {
  version: number; // 2
  ikxPublicA: Uint8Array; // 32 bytes
  kemCiphertext: Uint8Array; // 1088 bytes (ML-KEM-768)
  alicePqKemPublic: Uint8Array; // 1184 bytes (ML-KEM-768)
  ekPublicA: Uint8Array; // 32 bytes
  opkIndex: number | null;
}

/**
 * Pack a v2 init payload. The wire format includes the ML-KEM-768 ciphertext
 * produced by Alice encapsulating to Bob's `pq_kem_public` plus Alice's own
 * ML-KEM-768 public key (so Bob can verify the binding if needed; the device
 * already has Alice's bundle which carries Alice's public keys).
 */
export function buildInitPayloadV2(
  ikxPublicA: Uint8Array,
  kemCiphertext: Uint8Array,
  alicePqKemPublic: Uint8Array,
  ekPublicA: Uint8Array,
  opkIndex: number | null,
): Uint8Array {
  if (ikxPublicA.length !== 32) {
    throw new X3dhError('invalid_payload', 'IKX_A must be 32 bytes');
  }
  if (kemCiphertext.length !== ML_KEM_768_CIPHERTEXT_BYTES) {
    throw new X3dhError(
      'invalid_payload',
      `kem_ciphertext must be ${ML_KEM_768_CIPHERTEXT_BYTES} bytes; got ${kemCiphertext.length}`,
    );
  }
  if (alicePqKemPublic.length !== ML_KEM_768_PUBLIC_KEY_BYTES) {
    throw new X3dhError(
      'invalid_payload',
      `alice_pq_kem_public must be ${ML_KEM_768_PUBLIC_KEY_BYTES} bytes; got ${alicePqKemPublic.length}`,
    );
  }
  if (ekPublicA.length !== 32) {
    throw new X3dhError('invalid_payload', 'EK_A must be 32 bytes');
  }
  const out = new Uint8Array(INIT_V2_PAYLOAD_BYTES);
  out[0] = INIT_VERSION_V2;
  out.set(ikxPublicA, 1);
  out.set(kemCiphertext, 1 + 32);
  out.set(alicePqKemPublic, 1 + 32 + ML_KEM_768_CIPHERTEXT_BYTES);
  out.set(ekPublicA, 1 + 32 + ML_KEM_768_CIPHERTEXT_BYTES + ML_KEM_768_PUBLIC_KEY_BYTES);
  out[INIT_V2_PAYLOAD_BYTES - 1] = opkIndex === null ? NO_OPK_INDEX : opkIndex & 0xff;
  return out;
}

export function parseInitPayloadV2(payload: Uint8Array): ParsedInitPayloadV2 {
  if (payload.length !== INIT_V2_PAYLOAD_BYTES) {
    throw new X3dhError(
      'invalid_payload',
      `v2 init payload must be ${INIT_V2_PAYLOAD_BYTES} bytes; got ${payload.length}`,
    );
  }
  const version = payload[0] ?? 0;
  if (version !== INIT_VERSION_V2) {
    throw new X3dhError(
      'unsupported_version',
      `unsupported v2 init payload version ${version}`,
    );
  }
  const ikxPublicA = payload.slice(1, 33);
  const kemCiphertext = payload.slice(33, 33 + ML_KEM_768_CIPHERTEXT_BYTES);
  const alicePqKemPublic = payload.slice(
    33 + ML_KEM_768_CIPHERTEXT_BYTES,
    33 + ML_KEM_768_CIPHERTEXT_BYTES + ML_KEM_768_PUBLIC_KEY_BYTES,
  );
  const ekPublicA = payload.slice(
    33 + ML_KEM_768_CIPHERTEXT_BYTES + ML_KEM_768_PUBLIC_KEY_BYTES,
    33 + ML_KEM_768_CIPHERTEXT_BYTES + ML_KEM_768_PUBLIC_KEY_BYTES + 32,
  );
  const opk = payload[INIT_V2_PAYLOAD_BYTES - 1] ?? NO_OPK_INDEX;
  return {
    version: INIT_VERSION_V2,
    ikxPublicA,
    kemCiphertext,
    alicePqKemPublic,
    ekPublicA,
    opkIndex: opk === NO_OPK_INDEX ? null : opk,
  };
}

/**
 * Detect the protocol version of an arbitrary init payload without parsing
 * the whole thing. Returns 1, 2, or throws on malformed input.
 */
export function detectInitVersion(payload: Uint8Array): number {
  if (payload.length < 1) {
    throw new X3dhError('invalid_payload', 'empty init payload');
  }
  return payload[0] ?? 0;
}

function resolveIkxB(bundle: RemotePublicBundle): Uint8Array {
  if (bundle.ikxPublic !== null) return bundle.ikxPublic;
  // REST gap: the bundle never carries IKX_B. Surface via X3dhError; do not
  // invent behavior (would break DH(EK_A, IKX_B)).
  throw new X3dhError(
    'missing_ikx',
    'Remote bundle is missing the X25519 identity (IKX_B); cannot complete X3DH.',
  );
}

function assertKey(buf: Uint8Array | null | undefined, name: string): void {
  if (!(buf instanceof Uint8Array) || buf.length !== 32) {
    throw new X3dhError('invalid_bundle', `${name} must be a 32-byte Uint8Array`);
  }
}

function assertSignature(buf: Uint8Array | null | undefined, name: string): void {
  if (!(buf instanceof Uint8Array) || buf.length !== 64) {
    throw new X3dhError('invalid_bundle', `${name} must be a 64-byte Uint8Array`);
  }
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}
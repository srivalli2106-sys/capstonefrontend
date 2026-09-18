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
 */

import { verifySignedPrekey } from './deviceKeys';
import { dhX25519, generateX25519Keypair, x25519PublicFromPrivate } from './x25519';
import { hkdfSha256 } from './hkdf';
import { encodeBase64Url, decodeBase64Url } from './base64url';

export const X3DH_INFO = 'secure-messaging-x3dh-v1';
const X3DH_INFO_BYTES = new TextEncoder().encode(X3DH_INFO);
export const X3DH_SHARED_SECRET_BYTES = 32;
export const INIT_VERSION = 1;
export const NO_OPK_INDEX = 0xff;
export const INIT_PAYLOAD_BYTES = 66;

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

export function parseInitPayload(payload: Uint8Array): ParsedInitPayload {
  if (payload.length !== INIT_PAYLOAD_BYTES) {
    throw new X3dhError(
      'invalid_payload',
      `init payload must be ${INIT_PAYLOAD_BYTES} bytes, got ${payload.length}`,
    );
  }
  const version = payload[0] ?? 0;
  if (version !== INIT_VERSION) {
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
  out[0] = INIT_VERSION;
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
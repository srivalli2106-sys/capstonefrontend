import { describe, expect, it } from 'vitest';
import {
  INIT_PAYLOAD_BYTES,
  INIT_VERSION,
  NO_OPK_INDEX,
  X3DH_INFO,
  X3DH_SHARED_SECRET_BYTES,
  X3dhError,
  buildAssociatedData,
  buildInitPayload,
  decodeSessionInitData,
  encodeSessionInitData,
  parseInitPayload,
  x3dhInitiate,
  x3dhRespond,
  type RemotePublicBundle,
} from '../src/crypto/x3dh';
import { X3DHSession } from '../src/crypto/session';
import {
  buildDevicePublicBundle,
  type DeviceKeysPrivate,
} from '../src/crypto/deviceKeys';
import { bytesToHex, hexToBytes } from '../src/crypto/hex';

function block32(start: number): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) out[i] = (start + i) % 256;
  return out;
}

const IKX_A_PRIV = block32(1);            // alice X25519 IKX private
const EK_A_PRIV = block32(129);           // alice ephemeral (with-OPK case)
const EK_A2_PRIV = block32(161);          // alice ephemeral (no-OPK case)
const AUTH_SEED_A = block32(200);         // alice Ed25519 seed

const IKX_B_PRIV = block32(33);
const SPK_B_PRIV = block32(65);
const OPK_B_PRIV = block32(97);
const AUTH_SEED_B = block32(232);

const IKX_A_PUB = '07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c';
const IKX_B_PUB = '5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b';
const SPK_B_PUB = '64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466';
const OPK_B_PUB = '244fe3b963e899dd295baffce248d3530f3a9a7479ba063002680ebfe7adad49';
const SPK_SIG =
  'fe80d335e8cb953ca979482407af28188a4734b5bf88e1064fd9f3ad7f0f3c7015ac0ca6ae442aecb4ba646ccb5d79725312b4790ecca9492f8e457ee407d402';

// With-OPK pinned outputs.
const FIXED_EK_PUB = '883186b800b41d5cf0429695da9b3cc4f328ebcd184a6e482fa578c103f06c77';
const FIXED_SK = '3e14176e1b52478848696c849fdec4ed229cbe9c8b676b418b44c417361820b1';
const FIXED_AD =
  '07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c' +
  '5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b';
const FIXED_INIT =
  '01' + IKX_A_PUB + FIXED_EK_PUB + '00';
const FIXED_DH =
  '26c2c17fdb82161cb21ad16e721315355b64d1763119b10bfc962530dc7cc16' +
  '3e9f4479ab6d9665ef4a4cb22856a439921c5f1d8676fd87b2df8c0bdd618cf2a' +
  '988acb3701da55f5018f2eafcaac667a32a1c1c06f7fb11ead040d671686cd3cd' +
  'bcc0f8cb8de72509d228b2c6d0bdbd383180949491cda1cdde85fd048cf762d';

// No-OPK pinned outputs (independent ephemeral EK_A2).
const FIXED_EK2_PUB = 'ad438bfae31f6c093d61d4339255ea798092c9fadd07b97827f4b0ae9dee7c1c';
const FIXED_SK_NO_OPK = 'c856b84f39ee9c31901bac16ec02a2db552cb7542ebd3c18da81e5635641ba02';
const FIXED_INIT_NO_OPK = '01' + IKX_A_PUB + FIXED_EK2_PUB + 'ff';
const FIXED_DH_NO_OPK =
  '26c2c17fdb82161cb21ad16e721315355b64d1763119b10bfc962530dc7cc16' +
  '3da2095b601278f896bb6cb929f6e517de16281d3db9e03e5a0aa11d7e9057769' +
  'd3f89214b6f7251e0ae22636fc1ad75fbe8205a644a4349c5512d5914540d018';

function aliceBundle(): { device: DeviceKeysPrivate; ikPubHex: string } {
  const bundle = buildDevicePublicBundle(AUTH_SEED_A, {
    ikxPrivate: IKX_A_PRIV,
    spkPrivate: block32(7), // alice's own SPK is unused for initiate/respond
    opkPrivate: null,
  });
  return {
    device: { ikxPrivate: IKX_A_PRIV, spkPrivate: block32(7), opkPrivate: null },
    ikPubHex: bytesToHex(bundle.ikPublic),
  };
}

function bobDevice(): DeviceKeysPrivate {
  return { ikxPrivate: IKX_B_PRIV, spkPrivate: SPK_B_PRIV, opkPrivate: OPK_B_PRIV };
}

function remoteBundle(): RemotePublicBundle {
  // Build a valid bundle using the same fixed materials so the SPK sig
  // verifies cleanly. We use AUTH_SEED_B + bobDevice() so the signature
  // matches the pinned value.
  const built = buildDevicePublicBundle(AUTH_SEED_B, bobDevice());
  return {
    authIkPublic: built.ikPublic,
    ikxPublic: hexToBytes(IKX_B_PUB),
    spkPublic: built.spkPublic,
    spkSignature: built.spkSignature,
    opkPublic: built.opkPublics[0],
  };
}

function remoteBundleNoOpk(): RemotePublicBundle {
  const device = { ikxPrivate: IKX_B_PRIV, spkPrivate: SPK_B_PRIV, opkPrivate: null };
  const built = buildDevicePublicBundle(AUTH_SEED_B, device);
  return {
    authIkPublic: built.ikPublic,
    ikxPublic: hexToBytes(IKX_B_PUB),
    spkPublic: built.spkPublic,
    spkSignature: built.spkSignature,
    opkPublic: null,
  };
}

describe('X3DH constants', () => {
  it('uses the documented info string verbatim', () => {
    expect(X3DH_INFO).toBe('secure-messaging-x3dh-v1');
    expect(INIT_VERSION).toBe(1);
    expect(NO_OPK_INDEX).toBe(0xff);
    expect(INIT_PAYLOAD_BYTES).toBe(66);
    expect(X3DH_SHARED_SECRET_BYTES).toBe(32);
  });
});

describe('buildInitPayload / parseInitPayload', () => {
  it('round-trips with an OPK index', () => {
    const payload = buildInitPayload(hexToBytes(IKX_A_PUB), hexToBytes(FIXED_EK_PUB), 0);
    expect(payload.length).toBe(66);
    expect(bytesToHex(payload)).toBe(FIXED_INIT);
    const parsed = parseInitPayload(payload);
    expect(parsed.version).toBe(1);
    expect(bytesToHex(parsed.ikxPublicA)).toBe(IKX_A_PUB);
    expect(bytesToHex(parsed.ekPublicA)).toBe(FIXED_EK_PUB);
    expect(parsed.opkIndex).toBe(0);
  });

  it('encodes NO_OPK_INDEX when opkIndex is null', () => {
    const payload = buildInitPayload(hexToBytes(IKX_A_PUB), hexToBytes(FIXED_EK2_PUB), null);
    expect(payload[65]).toBe(NO_OPK_INDEX);
    expect(bytesToHex(payload)).toBe(FIXED_INIT_NO_OPK);
    const parsed = parseInitPayload(payload);
    expect(parsed.opkIndex).toBeNull();
  });

  it('buildAssociatedData concatenates IKX_A || IKX_B (64 bytes)', () => {
    const ad = buildAssociatedData(hexToBytes(IKX_A_PUB), hexToBytes(IKX_B_PUB));
    expect(bytesToHex(ad)).toBe(FIXED_AD);
  });

  it('rejects malformed payloads', () => {
    expect(() => parseInitPayload(new Uint8Array(10))).toThrow(X3dhError);
    const bad = new Uint8Array(INIT_PAYLOAD_BYTES);
    bad[0] = 99;
    let caught: unknown = null;
    try {
      parseInitPayload(bad);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(X3dhError);
    expect((caught as X3dhError).code).toBe('unsupported_version');
  });
});

describe('x3dhInitiate (with OPK)', () => {
  it('matches the Python reference byte-for-byte (SK, AD, payload, DH parts)', async () => {
    const result = await x3dhInitiate(IKX_A_PRIV, remoteBundle(), {
      ephemeralPrivateKey: EK_A_PRIV,
    });
    expect(result.sharedSecret.length).toBe(32);
    expect(bytesToHex(result.sharedSecret)).toBe(FIXED_SK);
    expect(bytesToHex(result.associatedData)).toBe(FIXED_AD);
    expect(bytesToHex(result.initPayload)).toBe(FIXED_INIT);
    expect(bytesToHex(result.dhPartsConcat)).toBe(FIXED_DH);
    expect(result.opkIndex).toBe(0);
    expect(bytesToHex(result.ephemeralPublicKey)).toBe(FIXED_EK_PUB);
  });

  it('rejects a tampered SPK signature', async () => {
    const bundle = remoteBundle();
    const sig = new Uint8Array(bundle.spkSignature);
    sig[0] = (sig[0] ?? 0) ^ 0xff;
    const tampered = { ...bundle, spkSignature: sig };
    await expect(x3dhInitiate(IKX_A_PRIV, tampered, { ephemeralPrivateKey: EK_A_PRIV }))
      .rejects.toMatchObject({ code: 'invalid_signature' });
  });

  it('rejects a bundle with a wrong identity key (sig of another auth)', async () => {
    const bundle = remoteBundle();
    const wrongBundle: RemotePublicBundle = {
      ...bundle,
      authIkPublic: buildDevicePublicBundle(AUTH_SEED_A, aliceBundle().device).ikPublic,
    };
    await expect(x3dhInitiate(IKX_A_PRIV, wrongBundle, { ephemeralPrivateKey: EK_A_PRIV }))
      .rejects.toMatchObject({ code: 'invalid_signature' });
  });

  it('rejects a missing IKX_B (current REST contract gap)', async () => {
    const bundle: RemotePublicBundle = { ...remoteBundle(), ikxPublic: null };
    await expect(x3dhInitiate(IKX_A_PRIV, bundle, { ephemeralPrivateKey: EK_A_PRIV }))
      .rejects.toMatchObject({ code: 'missing_ikx' });
  });

  it('rejects an ephemeral of wrong length', async () => {
    await expect(x3dhInitiate(IKX_A_PRIV, remoteBundle(), { ephemeralPrivateKey: new Uint8Array(16) }))
      .rejects.toMatchObject({ code: 'invalid_ephemeral' });
  });
});

describe('x3dhInitiate (no OPK)', () => {
  it('matches the pinned 3-term SK, AD, payload, and DH parts', async () => {
    const result = await x3dhInitiate(IKX_A_PRIV, remoteBundleNoOpk(), {
      ephemeralPrivateKey: EK_A2_PRIV,
    });
    expect(result.opkIndex).toBeNull();
    expect(bytesToHex(result.sharedSecret)).toBe(FIXED_SK_NO_OPK);
    expect(bytesToHex(result.associatedData)).toBe(FIXED_AD);
    expect(bytesToHex(result.initPayload)).toBe(FIXED_INIT_NO_OPK);
    expect(bytesToHex(result.dhPartsConcat)).toBe(FIXED_DH_NO_OPK);
    expect(result.dhPartsConcat.length).toBe(96);
  });

  it('differs from the with-OPK shared secret (sanity)', async () => {
    const withOpk = await x3dhInitiate(IKX_A_PRIV, remoteBundle(), {
      ephemeralPrivateKey: EK_A_PRIV,
    });
    const noOpk = await x3dhInitiate(IKX_A_PRIV, remoteBundleNoOpk(), {
      ephemeralPrivateKey: EK_A2_PRIV,
    });
    expect(bytesToHex(withOpk.sharedSecret)).not.toBe(bytesToHex(noOpk.sharedSecret));
  });
});

describe('x3dhRespond', () => {
  it('reproduces the same SK, AD, and opk index as the initiator', async () => {
    const init = await x3dhInitiate(IKX_A_PRIV, remoteBundle(), {
      ephemeralPrivateKey: EK_A_PRIV,
    });
    const response = await x3dhRespond(
      SPK_B_PRIV,
      hexToBytes(IKX_B_PUB),
      IKX_B_PRIV,
      [OPK_B_PRIV],
      init.initPayload,
    );
    expect(bytesToHex(response.sharedSecret)).toBe(FIXED_SK);
    expect(bytesToHex(response.associatedData)).toBe(FIXED_AD);
    expect(response.opkIndex).toBe(0);
    expect(bytesToHex(response.dhPartsConcat)).toBe(FIXED_DH);
  });

  it('reproduces the same SK on the no-OPK path', async () => {
    const init = await x3dhInitiate(IKX_A_PRIV, remoteBundleNoOpk(), {
      ephemeralPrivateKey: EK_A2_PRIV,
    });
    const response = await x3dhRespond(
      SPK_B_PRIV,
      hexToBytes(IKX_B_PUB),
      IKX_B_PRIV,
      [],
      init.initPayload,
    );
    expect(bytesToHex(response.sharedSecret)).toBe(FIXED_SK_NO_OPK);
    expect(response.opkIndex).toBeNull();
    expect(bytesToHex(response.dhPartsConcat)).toBe(FIXED_DH_NO_OPK);
  });

  it('rejects an OPK index the responder does not hold', async () => {
    const init = await x3dhInitiate(IKX_A_PRIV, remoteBundle(), {
      ephemeralPrivateKey: EK_A_PRIV,
    });
    await expect(
      x3dhRespond(SPK_B_PRIV, hexToBytes(IKX_B_PUB), IKX_B_PRIV, [], init.initPayload),
    ).rejects.toMatchObject({ code: 'invalid_payload' });
  });
});

describe('X3DHSession', () => {
  it('initiator session exposes initPayload + ephemeral', async () => {
    const init = await X3DHSession.initiate(aliceBundle().device, remoteBundle(), {
      ephemeralPrivateKey: EK_A_PRIV,
      peerUserId: 'bob',
    });
    expect(init.role).toBe('initiator');
    expect(init.peerUserId).toBe('bob');
    expect(init.initPayload).not.toBeNull();
    expect(bytesToHex(init.sharedSecret)).toBe(FIXED_SK);
    expect(init.opkIndex).toBe(0);
    init.wipe();
    expect(init.isLocked).toBe(true);
    expect(Array.from(init.sharedSecret).every((b) => b === 0)).toBe(true);
  });

  it('accept session reproduces the same SK and has no initPayload', async () => {
    const init = await X3DHSession.initiate(aliceBundle().device, remoteBundle(), {
      ephemeralPrivateKey: EK_A_PRIV,
    });
    const accept = await X3DHSession.accept(bobDevice(), init.initPayload!, {
      peerUserId: 'alice',
    });
    expect(accept.role).toBe('responder');
    expect(accept.peerUserId).toBe('alice');
    expect(accept.initPayload).toBeNull();
    expect(bytesToHex(accept.sharedSecret)).toBe(FIXED_SK);
    expect(accept.opkIndex).toBe(0);
  });
});

describe('envelope data base64url (session_init)', () => {
  it('66-byte init payload encodes to 88 unpadded base64url chars and round-trips', () => {
    const payload = buildInitPayload(hexToBytes(IKX_A_PUB), hexToBytes(FIXED_EK_PUB), 0);
    const data = encodeSessionInitData(payload);
    expect(data.length).toBe(88);
    expect(data).toMatch(/^[A-Za-z0-9_-]+$/);
    const back = decodeSessionInitData(data);
    expect(bytesToHex(back)).toBe(FIXED_INIT);
  });

  it('tolerates padding on decode', () => {
    const payload = buildInitPayload(hexToBytes(IKX_A_PUB), hexToBytes(FIXED_EK2_PUB), null);
    const data = encodeSessionInitData(payload);
    const padded = data + '==='.slice(0, (4 - (data.length % 4)) % 4);
    const back = decodeSessionInitData(padded);
    expect(bytesToHex(back)).toBe(FIXED_INIT_NO_OPK);
  });
});

// Defensive cleanup of unused helpers.
void aliceBundle;
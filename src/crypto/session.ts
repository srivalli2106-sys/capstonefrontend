/**
 * In-memory X3DH session abstraction (no Double Ratchet yet).
 *
 * Phase 5 ships ONLY the X3DH key-agreement result. Phase 6 will add the
 * symmetric-turn Double Ratchet + skipped-key buffer; that work is intentionally
 * out of scope here.
 */

import type { DeviceKeysPrivate } from './deviceKeys';
import { x25519PublicFromPrivate } from './x25519';
import {
  x3dhInitiate,
  x3dhRespond,
  type RemotePublicBundle,
  type X3dhInitiationResult,
  type X3dhRespondResult,
} from './x3dh';

export type X3DHRole = 'initiator' | 'responder';

export class X3DHSession {
  public readonly role: X3DHRole;
  public readonly peerUserId: string | null;
  public readonly sharedSecret: Uint8Array;
  public readonly associatedData: Uint8Array;
  public readonly initPayload: Uint8Array | null;
  public readonly opkIndex: number | null;
  private locked = false;

  private constructor(args: {
    role: X3DHRole;
    peerUserId: string | null;
    sharedSecret: Uint8Array;
    associatedData: Uint8Array;
    initPayload: Uint8Array | null;
    opkIndex: number | null;
  }) {
    this.role = args.role;
    this.peerUserId = args.peerUserId;
    this.sharedSecret = args.sharedSecret;
    this.associatedData = args.associatedData;
    this.initPayload = args.initPayload;
    this.opkIndex = args.opkIndex;
  }

  /**
   * Alice initiates a session to Bob. The returned session's `initPayload`
   * is the 66-byte X3DH init frame that MUST be wrapped in a `session_init`
   * envelope (envelope data is the base64url of `initPayload`).
   */
  public static async initiate(
    aliceDeviceKeys: DeviceKeysPrivate,
    remoteBundle: RemotePublicBundle,
    options: { ephemeralPrivateKey?: Uint8Array; peerUserId?: string } = {},
  ): Promise<X3DHSession> {
    const result: X3dhInitiationResult = await x3dhInitiate(
      aliceDeviceKeys.ikxPrivate,
      remoteBundle,
      { ephemeralPrivateKey: options.ephemeralPrivateKey },
    );
    return new X3DHSession({
      role: 'initiator',
      peerUserId: options.peerUserId ?? null,
      sharedSecret: result.sharedSecret,
      associatedData: result.associatedData,
      initPayload: result.initPayload,
      opkIndex: result.opkIndex,
    });
  }

  /**
   * Bob accepts an X3DH init frame and builds the matching session. The
   * `initPayload` argument is the raw 66-byte frame (NOT the base64url
   * envelope data).
   */
  public static async accept(
    bobDeviceKeys: DeviceKeysPrivate,
    initPayload: Uint8Array,
    options: { peerUserId?: string } = {},
  ): Promise<X3DHSession> {
    const result: X3dhRespondResult = await x3dhRespond(
      bobDeviceKeys.spkPrivate,
      x25519PublicFromPrivate(bobDeviceKeys.ikxPrivate),
      bobDeviceKeys.ikxPrivate,
      collectOpkPrivates(bobDeviceKeys),
      initPayload,
    );
    return new X3DHSession({
      role: 'responder',
      peerUserId: options.peerUserId ?? null,
      sharedSecret: result.sharedSecret,
      associatedData: result.associatedData,
      initPayload: null,
      opkIndex: result.opkIndex,
    });
  }

  public wipe(): void {
    if (this.locked) return;
    this.sharedSecret.fill(0);
    this.locked = true;
  }

  public get isLocked(): boolean {
    return this.locked;
  }
}

function collectOpkPrivates(device: DeviceKeysPrivate): ReadonlyArray<Uint8Array> {
  return device.opkPrivate === null ? [] : [device.opkPrivate];
}
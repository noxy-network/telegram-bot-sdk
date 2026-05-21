import type { NOXY_DEVICE_KEY_PAIR_TYPE, NOXY_DEVICE_PQ_KEY_PAIR_TYPE } from './constants.js';

export type WalletAddress = `0x${string}`;

export type Signature = Uint8Array | string;

/** Relay `identity_type` strings (see Noxy device proto). */
export const NOXY_IDENTITY_TYPE = {
  WALLET: 'wallet',
  EMAIL: 'email',
  PHONE: 'phone',
  USER_ID: 'user_id',
} as const;

export type NoxyRelayIdentityType =
  (typeof NOXY_IDENTITY_TYPE)[keyof typeof NOXY_IDENTITY_TYPE];

export type NoxyWalletIdentity = {
  identityType?: typeof NOXY_IDENTITY_TYPE.WALLET;
  address: WalletAddress;
  signer: (data: Uint8Array) => Promise<Signature>;
};

export type NoxyEmailIdentity = {
  identityType: typeof NOXY_IDENTITY_TYPE.EMAIL;
  identityId: string;
};

export type NoxyPhoneIdentity = {
  identityType: typeof NOXY_IDENTITY_TYPE.PHONE;
  identityId: string;
};

export type NoxyUserIdIdentity = {
  identityType: typeof NOXY_IDENTITY_TYPE.USER_ID;
  identityId: string;
};

export type NoxyIdentity =
  | NoxyWalletIdentity
  | NoxyEmailIdentity
  | NoxyPhoneIdentity
  | NoxyUserIdIdentity;

export function relayIdentityTypeOf(identity: NoxyIdentity): NoxyRelayIdentityType {
  if ('address' in identity) {
    return identity.identityType ?? NOXY_IDENTITY_TYPE.WALLET;
  }
  return identity.identityType;
}

export function logicalIdentityIdOf(identity: NoxyIdentity): string {
  if ('address' in identity) {
    return identity.address;
  }
  return identity.identityId.trim();
}

export type NoxyDeviceKeyType = typeof NOXY_DEVICE_KEY_PAIR_TYPE | typeof NOXY_DEVICE_PQ_KEY_PAIR_TYPE;

export interface NoxyDeviceDescriptor {
  identityId: string;
  identityType?: NoxyRelayIdentityType;
  appId: string;
  isRevoked: boolean;
  issuedAt: number;
}

export interface NoxyDevicePublicKeys {
  publicKey: Uint8Array;
  pqPublicKey: Uint8Array;
}

export interface NoxyDevicePrivateKeys {
  privateKey: Uint8Array;
  pqPrivateKey: Uint8Array;
}

export type NoxyDevice = NoxyDeviceDescriptor &
  NoxyDevicePublicKeys & {
    identitySignature: Uint8Array | null;
  };

export const NoxyDecisionOutcomeValues = {
  APPROVE: 'APPROVE',
  REJECT: 'REJECT',
} as const;

export type NoxyDecisionChoice =
  (typeof NoxyDecisionOutcomeValues)[keyof typeof NoxyDecisionOutcomeValues];

export type NoxyEncryptedDecision = {
  kyberCt: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
};

import type { NOXY_DEVICE_KEY_PAIR_TYPE, NOXY_DEVICE_PQ_KEY_PAIR_TYPE } from './constants.js';

export type WalletAddress = `0x${string}`;

export type Signature = Uint8Array | string;

export type NoxyIdentity = {
  address: WalletAddress;
  signer: (data: Uint8Array) => Promise<Signature>;
};

export type NoxyDeviceKeyType = typeof NOXY_DEVICE_KEY_PAIR_TYPE | typeof NOXY_DEVICE_PQ_KEY_PAIR_TYPE;

export interface NoxyDeviceDescriptor {
  identityId: WalletAddress;
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

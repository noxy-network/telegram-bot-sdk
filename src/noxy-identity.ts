import { randomBytes } from '@noble/hashes/utils.js';
import { hexToBytes, toHex, verifyMessage } from 'viem';
import type { Hash } from 'viem';
import type { NoxyIdentity, NoxyWalletIdentity } from './types.js';
import { NOXY_IDENTITY_TYPE, relayIdentityTypeOf } from './types.js';
import { NoxyIdentityError } from './errors.js';

function toBytes(sig: Uint8Array | string): Uint8Array {
  if (typeof sig === 'string') {
    const s = (sig.startsWith('0x') ? sig : `0x${sig}`) as `0x${string}`;
    return hexToBytes(s);
  }
  return sig;
}

export async function validateIdentity(identity: NoxyIdentity): Promise<void> {
  if (relayIdentityTypeOf(identity) !== NOXY_IDENTITY_TYPE.WALLET) {
    return;
  }

  const signer = (identity as NoxyWalletIdentity).signer;
  if (!signer) throw new NoxyIdentityError('Signer function is required for wallet identities');

  const payload = randomBytes(32);
  let signature: Uint8Array | string;
  try {
    signature = await signer(payload);
  } catch (e) {
    throw new NoxyIdentityError(`Signer failed: ${(e as Error).message}`);
  }
  if (signature == null) throw new NoxyIdentityError('Signer returned empty signature');

  const w = identity as NoxyWalletIdentity;
  const sigHex = typeof signature === 'string' ? (signature as Hash) : toHex(signature);
  const ok = await verifyMessage({
    address: w.address,
    message: { raw: payload },
    signature: sigHex,
  });
  if (!ok) throw new NoxyIdentityError('Signer validation failed: signature does not match address');
}

export async function signWithIdentity(identity: NoxyIdentity, data: Uint8Array): Promise<Uint8Array> {
  if (relayIdentityTypeOf(identity) !== NOXY_IDENTITY_TYPE.WALLET) {
    throw new NoxyIdentityError('signWithIdentity is only supported for wallet identities');
  }
  const sig = await (identity as NoxyWalletIdentity).signer(data);
  return toBytes(sig);
}

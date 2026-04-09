import { randomBytes } from '@noble/hashes/utils.js';
import { hexToBytes, toHex, verifyMessage } from 'viem';
import type { Hash } from 'viem';
import type { NoxyIdentity } from './types.js';
import { NoxyIdentityError } from './errors.js';

function toBytes(sig: Uint8Array | string): Uint8Array {
  if (typeof sig === 'string') {
    const s = (sig.startsWith('0x') ? sig : `0x${sig}`) as `0x${string}`;
    return hexToBytes(s);
  }
  return sig;
}

export async function validateIdentity(identity: NoxyIdentity): Promise<void> {
  const { address, signer } = identity;
  if (!signer) throw new NoxyIdentityError('Signer function is required');

  const payload = randomBytes(32);
  let signature: Uint8Array | string;
  try {
    signature = await signer(payload);
  } catch (e) {
    throw new NoxyIdentityError(`Signer failed: ${(e as Error).message}`);
  }
  if (signature == null) throw new NoxyIdentityError('Signer returned empty signature');

  const sigHex = typeof signature === 'string' ? (signature as Hash) : toHex(signature);
  const ok = await verifyMessage({
    address,
    message: { raw: payload },
    signature: sigHex,
  });
  if (!ok) throw new NoxyIdentityError('Signer validation failed: signature does not match address');
}

export async function signWithIdentity(identity: NoxyIdentity, data: Uint8Array): Promise<Uint8Array> {
  const sig = await identity.signer(data);
  return toBytes(sig);
}

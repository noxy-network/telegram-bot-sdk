import { base64 } from '@scure/base';
import { JSONParse } from 'json-with-bigint';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { gcm } from '@noble/ciphers/webcrypto.js';
import type { NoxyEncryptedDecision } from './types.js';
import { NoxyKyberProvider } from './noxy-kyber.provider.js';
import type { NoxyDeviceModule } from './noxy-device.js';
import { NoxyGeneralError } from './errors.js';

function toBytes(v: Uint8Array | string | number[] | undefined, name: string): Uint8Array {
  if (v === undefined) throw new NoxyGeneralError(`Missing ${name} in encrypted decision`);
  if (v instanceof Uint8Array) return v;
  if (typeof v === 'string') return base64.decode(v);
  return new Uint8Array(v);
}

export async function decryptDecision(
  device: NoxyDeviceModule,
  envelope: NoxyEncryptedDecision
): Promise<Record<string, unknown> | null> {
  const keys = await device.loadDevicePrivateKeys();
  const pqPrivateKey = keys?.pqPrivateKey;
  if (!pqPrivateKey) return null;

  const kyber_ct = toBytes(envelope.kyberCt as unknown as Uint8Array, 'kyber_ct');
  const nonce = toBytes(envelope.nonce, 'nonce');
  const ciphertext = toBytes(envelope.ciphertext, 'ciphertext');

  const kyber = await NoxyKyberProvider.create();
  const sharedSecret = kyber.decapsulate(pqPrivateKey, kyber_ct);
  const key = hkdf(sha256, sharedSecret, undefined, undefined, 32);
  const decipher = gcm(key, nonce);
  const plaintext = await decipher.decrypt(ciphertext);
  return JSONParse(new TextDecoder().decode(plaintext)) as Record<string, unknown>;
}

export function resolveDecisionId(
  decision: Record<string, unknown>,
  relayMessageId: string | undefined,
): string | undefined {
  const fromPayload =
    (decision['decision_id'] as string | undefined) ??
    (decision['decisionId'] as string | undefined) ??
    (decision['message_id'] as string | undefined);
  if (fromPayload != null && String(fromPayload).length > 0) return String(fromPayload);
  if (relayMessageId && relayMessageId.length > 0) return relayMessageId;
  return undefined;
}

export function deliveryAckDecisionId(
  relayMessageId: string | undefined,
  payload: Record<string, unknown>,
): string | undefined {
  if (relayMessageId && relayMessageId.length > 0) return relayMessageId;
  const d =
    (payload['decision_id'] as string | undefined) ??
    (payload['decisionId'] as string | undefined) ??
    (payload['message_id'] as string | undefined);
  if (d && d.length > 0) return d;
  return undefined;
}

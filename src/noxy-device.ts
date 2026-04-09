import { keygenAsync, signAsync } from '@noble/ed25519';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { concatBytes, randomBytes } from '@noble/hashes/utils.js';
import { hexToBytes, isBytes, isHex } from 'viem';
import type { Signature } from './types.js';
import type { NoxyDevice, NoxyDevicePrivateKeys, WalletAddress } from './types.js';
import { NOXY_DEVICE_VERSION } from './constants.js';
import { NoxyKyberProvider } from './noxy-kyber.provider.js';
import type { NoxyFileStorage } from './noxy-storage.js';
import type { NoxyIdentity } from './types.js';

function signatureToBytes(sig: Signature | null): Uint8Array | null {
  if (sig === null) return null;
  if (isBytes(sig)) return new Uint8Array(sig);
  const hex = (typeof sig === 'string' && (sig.startsWith('0x') ? sig : `0x${sig}`)) as `0x${string}`;
  if (isHex(hex)) return hexToBytes(hex);
  return null;
}

export class NoxyDeviceModule {
  #device: NoxyDevice | undefined;
  readonly #storage: NoxyFileStorage;

  constructor(storage: NoxyFileStorage) {
    this.#storage = storage;
  }

  get publicKey(): Uint8Array | undefined {
    return this.#device?.publicKey;
  }

  get pqPublicKey(): Uint8Array | undefined {
    return this.#device?.pqPublicKey;
  }

  get isRevoked(): boolean | undefined {
    return this.#device?.isRevoked;
  }

  async buildIdentitySignatureHash(device: NoxyDevice): Promise<Uint8Array> {
    const encoder = new TextEncoder();
    const domain = encoder.encode(NOXY_DEVICE_VERSION);
    const appIdBytes = encoder.encode(device.appId);
    const identityIdBytes = encoder.encode(device.identityId);
    const issuedAtBytes = new Uint8Array(8);
    new DataView(issuedAtBytes.buffer).setBigUint64(0, BigInt(device.issuedAt), false);
    return keccak_256(
      concatBytes(domain, appIdBytes, identityIdBytes, device.publicKey, device.pqPublicKey, issuedAtBytes)
    );
  }

  async load(identityId: WalletAddress, appId: string): Promise<NoxyDevice | undefined> {
    const pk = this.#storage.devicePk(appId, identityId);
    const all = await this.#storage.loadDevices();
    const raw = all[pk] as Record<string, unknown> | undefined;
    if (!raw) return undefined;
    const device = this.#deserializeDevice(raw);
    this.#device = device;
    return device;
  }

  #deserializeDevice(raw: Record<string, unknown>): NoxyDevice {
    return {
      appId: String(raw.appId),
      identityId: raw.identityId as WalletAddress,
      isRevoked: Boolean(raw.isRevoked),
      issuedAt: Number(raw.issuedAt),
      publicKey: new Uint8Array(raw.publicKey as number[]),
      pqPublicKey: new Uint8Array(raw.pqPublicKey as number[]),
      identitySignature:
        raw.identitySignature == null
          ? null
          : new Uint8Array(raw.identitySignature as number[]),
    };
  }

  async #persistDevice(): Promise<void> {
    if (!this.#device) return;
    const pk = this.#storage.devicePk(this.#device.appId, this.#device.identityId);
    const all = await this.#storage.loadDevices();
    all[pk] = {
      appId: this.#device.appId,
      identityId: this.#device.identityId,
      isRevoked: this.#device.isRevoked,
      issuedAt: this.#device.issuedAt,
      publicKey: Array.from(this.#device.publicKey),
      pqPublicKey: Array.from(this.#device.pqPublicKey),
      identitySignature: this.#device.identitySignature ? Array.from(this.#device.identitySignature) : null,
    };
    await this.#storage.saveDevices(all);
  }

  async register(appId: string, identity: NoxyIdentity): Promise<NoxyDevice> {
    const { publicKey, secretKey } = await keygenAsync();
    const kyber = await NoxyKyberProvider.create();
    const pq = kyber.keypair();

    const deviceData: NoxyDevice = {
      appId,
      identityId: identity.address,
      identitySignature: null,
      isRevoked: false,
      issuedAt: Date.now(),
      publicKey,
      pqPublicKey: pq.publicKey,
    };

    const hash = await this.buildIdentitySignatureHash(deviceData);
    const sig = await identity.signer(hash);
    const identitySig = signatureToBytes(sig);
    if (!identitySig) {
      throw new Error('Invalid identity signature from signer');
    }
    deviceData.identitySignature = identitySig;

    this.#device = deviceData;
    await this.#persistDevice();

    const priv: NoxyDevicePrivateKeys = {
      privateKey: secretKey,
      pqPrivateKey: pq.secretKey,
    };
    await this.#persistPrivateKeys(priv);
    return deviceData;
  }

  async #persistPrivateKeys(keys: NoxyDevicePrivateKeys): Promise<void> {
    if (!this.#device) return;
    const pk = this.#storage.devicePk(this.#device.appId, this.#device.identityId);
    const payload = new TextEncoder().encode(
      JSON.stringify({
        privateKey: Array.from(keys.privateKey),
        pqPrivateKey: Array.from(keys.pqPrivateKey),
      })
    );
    await this.#storage.saveEncryptedDeviceKeys(pk, payload);
  }

  async loadDevicePrivateKeys(): Promise<NoxyDevicePrivateKeys | undefined> {
    if (!this.#device) return undefined;
    const pk = this.#storage.devicePk(this.#device.appId, this.#device.identityId);
    const data = await this.#storage.loadDecryptedDeviceKeys(pk);
    if (!data) return undefined;
    const keys = JSON.parse(new TextDecoder().decode(data)) as {
      privateKey: number[];
      pqPrivateKey: number[];
    };
    return {
      privateKey: new Uint8Array(keys.privateKey),
      pqPrivateKey: new Uint8Array(keys.pqPrivateKey),
    };
  }

  async revoke(): Promise<void> {
    if (!this.#device) return;
    this.#device.isRevoked = true;
    await this.#persistDevice();
  }

  async rotateKeys(): Promise<void> {
    if (!this.#device) return;
    const { publicKey, secretKey } = await keygenAsync();
    const kyber = await NoxyKyberProvider.create();
    const pq = kyber.keypair();
    this.#device = {
      ...this.#device,
      publicKey,
      pqPublicKey: pq.publicKey,
    };
    await this.#persistDevice();
    await this.#persistPrivateKeys({
      privateKey: secretKey,
      pqPrivateKey: pq.secretKey,
    });
  }

  async getDeviceSignature(): Promise<Uint8Array | undefined> {
    if (!this.#device) return undefined;
    const keys = await this.loadDevicePrivateKeys();
    if (!keys) return undefined;
    const encoder = new TextEncoder();
    const domain = encoder.encode(NOXY_DEVICE_VERSION);
    const appIdBytes = encoder.encode(this.#device.appId);
    const identityIdBytes = encoder.encode(this.#device.identityId);
    const dateBytes = new Uint8Array(8);
    new DataView(dateBytes.buffer).setBigUint64(0, BigInt(Date.now()), false);
    const bytes = concatBytes(domain, appIdBytes, identityIdBytes, dateBytes, randomBytes(16));
    return signAsync(bytes, keys.privateKey);
  }
}

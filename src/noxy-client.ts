import type { NoxyEncryptedDecision, NoxyIdentity, NoxyDecisionChoice, WalletAddress } from './types.js';
import type { NoxyNetworkOptions } from './noxy-network-options.js';
import { NoxyDeviceModule } from './noxy-device.js';
import { NoxyNetworkModule } from './noxy-network.js';
import { NoxyFileStorage, type NoxyFileStorageOptions } from './noxy-storage.js';
import { validateIdentity } from './noxy-identity.js';
import { decryptDecision, deliveryAckDecisionId, resolveDecisionId } from './noxy-decision-crypto.js';
import { NoxyDecisionProcessingError, NoxyInitializationError } from './errors.js';

export type NoxyTelegramClientOptions = {
  identity: NoxyIdentity;
  network: NoxyNetworkOptions;
  storage: NoxyFileStorageOptions;
};

export interface NoxyTelegramClient {
  on(
    handler: (decisionId: string | undefined, decision: Record<string, unknown>) => void | Promise<void>
  ): Promise<void>;
}

export class NoxyTelegramClient implements NoxyTelegramClient {
  readonly #identity: NoxyIdentity;
  readonly #networkOptions: NoxyNetworkOptions;
  readonly #device: NoxyDeviceModule;
  readonly #network: NoxyNetworkModule;

  private constructor(
    identity: NoxyIdentity,
    network: NoxyNetworkOptions,
    device: NoxyDeviceModule,
    net: NoxyNetworkModule
  ) {
    this.#identity = identity;
    this.#networkOptions = network;
    this.#device = device;
    this.#network = net;
  }

  static async create(options: NoxyTelegramClientOptions): Promise<NoxyTelegramClient> {
    await validateIdentity(options.identity);
    const storage = new NoxyFileStorage(options.storage);
    const device = new NoxyDeviceModule(storage);
    const net = new NoxyNetworkModule({
      appId: options.network.appId,
      relayUrl: options.network.relayUrl,
    });
    return new NoxyTelegramClient(options.identity, options.network, device, net);
  }

  get address(): WalletAddress {
    return this.#identity.address;
  }

  get isDeviceActive(): boolean {
    return this.#device.isRevoked === false;
  }

  get isRelayConnected(): boolean {
    return this.#network.isConnected;
  }

  get isNetworkReady(): boolean {
    return this.#network.isReady;
  }

  async initialize(): Promise<void> {
    await this.#network.connect();

    let device = await this.#device.load(this.#identity.address, this.#networkOptions.appId);
    if (!device) {
      device = await this.#device.register(this.#networkOptions.appId, this.#identity);
    }

    const requiresRegistration = await this.#network.authenticateDevice(device);

    if (requiresRegistration) {
      const sig = device.identitySignature;
      if (!sig) {
        throw new NoxyInitializationError('Device has no identity signature for relay registration');
      }
      await this.#network.announceDevice(
        { publicKey: device.publicKey, pqPublicKey: device.pqPublicKey },
        device.identityId,
        sig
      );
    }
  }

  async on(
    handler: (decisionId: string | undefined, decision: Record<string, unknown>) => void | Promise<void>
  ): Promise<void> {
    await this.#device.loadDevicePrivateKeys();
    const wrapped = async (
      envelope: NoxyEncryptedDecision,
      relayMessageId: string | undefined
    ): Promise<void> => {
      try {
        const decrypted = await decryptDecision(this.#device, envelope);
        if (!decrypted) return;
        const decisionId = resolveDecisionId(decrypted, relayMessageId);
        await Promise.resolve(handler(decisionId, decrypted));
        const ackId = deliveryAckDecisionId(relayMessageId, decrypted);
        if (ackId) {
          setImmediate(() => {
            void this.#network.sendDecisionAck(ackId).catch(() => {});
          });
        }
      } catch (err) {
        throw new NoxyDecisionProcessingError(
          'Failed to decrypt decision or run handler',
          'NOXY_DECISION_PROCESSING_ERROR',
          err
        );
      }
    };

    if (this.#network.isReady) {
      await this.#network.subscribeToDecisions(wrapped);
    } else {
      if (!this.#network.isConnected) await this.#network.connect();
      await this.#restoreRelaySession(wrapped);
    }

    this.#network.setReconnectRestore(async () => {
      await this.#restoreRelaySession(wrapped);
    });
  }

  async #restoreRelaySession(
    wrapped: (
      envelope: NoxyEncryptedDecision,
      relayMessageId: string | undefined
    ) => void | Promise<void>
  ): Promise<void> {
    await this.#device.loadDevicePrivateKeys();
    const device = await this.#device.load(this.#identity.address, this.#networkOptions.appId);
    if (!device) {
      throw new NoxyInitializationError('Device not found after relay reconnect');
    }
    const requiresRegistration = await this.#network.authenticateDevice(device);
    if (requiresRegistration) {
      const sig = device.identitySignature;
      if (!sig) {
        throw new NoxyInitializationError('Device has no identity signature for relay registration');
      }
      await this.#network.announceDevice(
        { publicKey: device.publicKey, pqPublicKey: device.pqPublicKey },
        device.identityId,
        sig
      );
    }
    await this.#network.subscribeToDecisions(wrapped);
  }

  async sendDecisionOutcome(
    decisionId: string,
    outcome: NoxyDecisionChoice,
    receivedAt?: number | bigint
  ): Promise<void> {
    const ts =
      receivedAt !== undefined
        ? typeof receivedAt === 'bigint'
          ? Number(receivedAt)
          : receivedAt
        : Date.now();
    await this.#network.sendDecisionOutcome(decisionId, outcome, ts);
  }

  async revokeDevice(): Promise<void> {
    const sig = await this.#device.getDeviceSignature();
    if (!sig) throw new Error('Unable to revoke device');
    await this.#device.revoke();
    await this.#network.revokeDevice(this.#identity.address, sig);
  }

  async rotateKeys(): Promise<void> {
    const sig = await this.#device.getDeviceSignature();
    if (!sig) throw new Error('Unable to rotate keys');
    await this.#device.rotateKeys();
    const pk = this.#device.publicKey;
    const pq = this.#device.pqPublicKey;
    if (!pk || !pq) throw new Error('Missing device public keys after rotate');
    await this.#network.rotateDeviceKeys({ publicKey: pk, pqPublicKey: pq }, this.#identity.address, sig);
  }

  async close(): Promise<void> {
    await this.#network.disconnect();
  }
}

import * as grpc from '@grpc/grpc-js';
import { base64 } from '@scure/base';
import { v4 as uuidv4 } from 'uuid';
import { randomBytes } from '@noble/hashes/utils.js';
import { NOXY_DEVICE_RELAY_TYPE_TELEGRAM } from './constants.js';
import { loadDeviceServiceClient, parseRelayTarget, relayChannelCredentials } from './load-proto.js';
import {
  NoxyDecisionOutcomeValues,
  type NoxyDecisionChoice,
  type NoxyDevice,
  type NoxyEncryptedDecision,
  type WalletAddress,
} from './types.js';
import { NoxyGeneralError } from './errors.js';

type DeviceResponse = Record<string, unknown>;
type DeviceRequest = Record<string, unknown>;

function toUint8Sync(v: unknown): Uint8Array {
  if (Buffer.isBuffer(v)) return new Uint8Array(v);
  if (v instanceof Uint8Array) return v;
  if (typeof v === 'string') return base64.decode(v);
  throw new NoxyGeneralError('Invalid binary field in relay response');
}

export class NoxyNetworkModule {
  readonly #appId: string;
  readonly #relayUrl: string;
  #client: grpc.Client | null = null;
  #call: grpc.ClientDuplexStream<DeviceRequest, DeviceResponse> | null = null;
  #sessionId: string | undefined;
  #networkDeviceId: string | undefined;
  readonly #pending = new Map<
    string,
    { resolve: (r: DeviceResponse) => void; reject: (e: Error) => void }
  >();
  #decisionHandler:
    | ((envelope: NoxyEncryptedDecision, relayMessageId: string | undefined) => void | Promise<void>)
    | null = null;
  #intentionalClose = false;
  #reconnectRestore: (() => Promise<void>) | null = null;
  #reconnectLoopPromise: Promise<void> | null = null;

  constructor(options: { appId: string; relayUrl: string }) {
    this.#appId = options.appId;
    this.#relayUrl = options.relayUrl;
  }

  get isConnected(): boolean {
    return this.#call != null;
  }

  get isReady(): boolean {
    return this.isConnected && this.#sessionId != null && this.#networkDeviceId != null;
  }

  get currentSessionId(): string | undefined {
    return this.#sessionId;
  }

  get currentDeviceId(): string | undefined {
    return this.#networkDeviceId;
  }

  async connect(): Promise<void> {
    if (this.#call) return;
    const DeviceService = loadDeviceServiceClient();
    const { host, port } = parseRelayTarget(this.#relayUrl);
    const creds = relayChannelCredentials(this.#relayUrl);
    this.#client = new DeviceService(`${host}:${port}`, creds, {
      'grpc.keepalive_time_ms': 30_000,
    });
    const duplex = (
      this.#client as unknown as {
        handleMessage(): grpc.ClientDuplexStream<DeviceRequest, DeviceResponse>;
      }
    ).handleMessage();
    this.#call = duplex;

    this.#call.on('data', (response: DeviceResponse) => {
      void this.#onStreamData(response);
    });
    this.#call.on('error', (err: Error) => {
      void this.#onStreamFatal(err);
    });
    this.#call.on('end', () => {
      void this.#onStreamFatal(new Error('Noxy relay stream ended'));
    });
  }

  setReconnectRestore(handler: (() => Promise<void>) | null): void {
    this.#reconnectRestore = handler;
  }

  #teardownTransport(err: Error): void {
    this.#rejectAllPending(err);
    try {
      this.#call?.end();
    } catch {}
    this.#call = null;
    try {
      this.#client?.close();
    } catch {}
    this.#client = null;
    this.#sessionId = undefined;
    this.#networkDeviceId = undefined;
  }

  async #onStreamFatal(err: Error): Promise<void> {
    if (this.#intentionalClose) return;
    this.#teardownTransport(err);
    if (!this.#reconnectRestore) return;
    this.#scheduleReconnectLoop();
  }

  #scheduleReconnectLoop(): void {
    if (this.#reconnectLoopPromise != null) return;
    this.#reconnectLoopPromise = this.#reconnectLoop().finally(() => {
      this.#reconnectLoopPromise = null;
    });
  }

  async #reconnectLoop(): Promise<void> {
    let attempt = 0;
    while (!this.#intentionalClose && this.#reconnectRestore != null) {
      const delay =
        attempt === 0 ? 0 : Math.min(30_000, 1000 * 2 ** Math.min(attempt - 1, 5));
      if (delay > 0) {
        await new Promise<void>((r) => setTimeout(r, delay));
      }
      if (this.#intentionalClose || this.#reconnectRestore == null) break;
      if (this.#call != null) return;
      try {
        await this.connect();
        await this.#reconnectRestore();
        return;
      } catch {
        this.#teardownTransport(new Error('Noxy relay reconnect attempt failed'));
      }
      attempt++;
    }
  }

  #rejectAllPending(err: Error): void {
    for (const [, p] of this.#pending) {
      p.reject(err);
    }
    this.#pending.clear();
  }

  #applySessionFromResponse(response: DeviceResponse): void {
    const auth = response.authenticate as { device_id?: string; session_id?: string } | undefined;
    if (auth) {
      if (auth.device_id) this.#networkDeviceId = String(auth.device_id);
      if (auth.session_id) this.#sessionId = String(auth.session_id);
    }
    const reg = response.register_device as { device_id?: string; session_id?: string } | undefined;
    if (reg) {
      if (reg.device_id) this.#networkDeviceId = String(reg.device_id);
      if (reg.session_id) this.#sessionId = String(reg.session_id);
    }
  }

  async #onStreamData(response: DeviceResponse): Promise<void> {
    try {
      const rid = response.request_id as string | undefined;

      if (response.decision_event) {
        const ev = response.decision_event as { kyber_ct?: unknown; nonce?: unknown; ciphertext?: unknown };
        const kyberCt = toUint8Sync(ev.kyber_ct);
        const nonce = toUint8Sync(ev.nonce);
        const ciphertext = toUint8Sync(ev.ciphertext);
        const relayMessageId = (response.message_id as string | undefined) ?? undefined;
        const h = this.#decisionHandler;
        if (h) {
          const envelope: NoxyEncryptedDecision = { kyberCt, nonce, ciphertext };
          await Promise.resolve(h(envelope, relayMessageId));
        }
        return;
      }

      if (response.decision_routed) {
        return;
      }

      if (response.error) {
        const e = response.error as { code?: number; message?: string };
        if (rid) {
          const p = this.#pending.get(rid);
          if (p) {
            this.#pending.delete(rid);
            p.reject(new NoxyGeneralError(`Relay error: ${e.code} ${e.message ?? ''}`));
          }
        }
        return;
      }

      if (rid && this.#pending.has(rid)) {
        this.#applySessionFromResponse(response);
        const p = this.#pending.get(rid)!;
        this.#pending.delete(rid);
        p.resolve(response);
      }
    } catch {}
  }

  async sendAndWait(request: DeviceRequest): Promise<DeviceResponse> {
    const call = this.#call;
    if (!call) throw new NoxyGeneralError('Not connected to relay');

    const requestID = (request.request_id as string) || uuidv4();
    request.request_id = requestID;
    request.app_id = this.#appId;
    if (!request.timestamp) request.timestamp = String(Date.now());
    const nonce = request.nonce as Buffer | Uint8Array | undefined;
    if (!nonce || (nonce instanceof Uint8Array && nonce.length === 0)) {
      request.nonce = Buffer.from(randomBytes(12));
    }

    return new Promise((resolve, reject) => {
      this.#pending.set(requestID, {
        resolve: (r) => resolve(r),
        reject,
      });
      try {
        call.write(request, (err: Error | null) => {
          if (err) {
            this.#pending.delete(requestID);
            reject(err);
          }
        });
      } catch (e) {
        this.#pending.delete(requestID);
        reject(e);
      }
    });
  }

  async authenticateDevice(device: NoxyDevice): Promise<boolean> {
    const resp = await this.sendAndWait({
      authenticate: {
        device_pubkeys: {
          public_key: Buffer.from(device.publicKey),
          pq_public_key: Buffer.from(device.pqPublicKey),
        },
      },
    });

    if (resp.error) {
      const e = resp.error as { message?: string };
      throw new NoxyGeneralError(`Authenticate failed: ${e.message ?? 'unknown'}`);
    }

    const auth = resp.authenticate as { requires_registration?: boolean } | undefined;
    if (!auth) {
      throw new NoxyGeneralError('Unexpected authenticate response');
    }

    if (auth.requires_registration) {
      return true;
    }
    this.#applySessionFromResponse(resp);
    return false;
  }

  async announceDevice(
    devicePubkeys: { publicKey: Uint8Array; pqPublicKey: Uint8Array },
    walletAddress: WalletAddress,
    signature: Uint8Array
  ): Promise<void> {
    const resp = await this.sendAndWait({
      register_device: {
        device_pubkeys: {
          public_key: Buffer.from(devicePubkeys.publicKey),
          pq_public_key: Buffer.from(devicePubkeys.pqPublicKey),
        },
        wallet_address: walletAddress,
        signature: Buffer.from(signature),
        type: NOXY_DEVICE_RELAY_TYPE_TELEGRAM,
      },
    });

    if (resp.error) {
      const e = resp.error as { message?: string };
      throw new NoxyGeneralError(`Register failed: ${e.message ?? 'unknown'}`);
    }
    if (!resp.register_device) {
      throw new NoxyGeneralError('Unexpected register response');
    }
    this.#applySessionFromResponse(resp);
  }

  async subscribeToDecisions(
    handler: (
      envelope: NoxyEncryptedDecision,
      relayMessageId: string | undefined
    ) => void | Promise<void>
  ): Promise<void> {
    if (!this.#call) await this.connect();
    this.#decisionHandler = handler;
    const req: DeviceRequest = {
      subscribe_decisions: { subscribe: true },
    };
    if (this.#networkDeviceId) req.device_id = this.#networkDeviceId;
    if (this.#sessionId) req.session_id = this.#sessionId;
    await this.sendAndWait(req);
  }

  async sendDecisionOutcome(
    decisionId: string,
    outcome: NoxyDecisionChoice,
    receivedAt?: number
  ): Promise<void> {
    const protoOutcome = outcome === NoxyDecisionOutcomeValues.APPROVE ? 0 : 1;
    const req: DeviceRequest = {
      decision_outcome: {
        decision_id: decisionId,
        outcome: protoOutcome,
        received_at: String(receivedAt ?? Date.now()),
      },
    };
    if (this.#networkDeviceId) req.device_id = this.#networkDeviceId;
    if (this.#sessionId) req.session_id = this.#sessionId;
    await this.sendAndWait(req);
  }

  async sendDecisionAck(decisionId: string, receivedAt?: number): Promise<void> {
    const req: DeviceRequest = {
      decision_ack: {
        decision_id: decisionId,
        received_at: String(receivedAt ?? Date.now()),
      },
    };
    if (this.#networkDeviceId) req.device_id = this.#networkDeviceId;
    if (this.#sessionId) req.session_id = this.#sessionId;
    await this.sendAndWait(req);
  }

  async revokeDevice(walletAddress: WalletAddress, signature: Uint8Array): Promise<void> {
    await this.sendAndWait({
      revoke_device: {
        wallet_address: walletAddress,
        signature: Buffer.from(signature),
      },
    });
  }

  async rotateDeviceKeys(
    newPubkeys: { publicKey: Uint8Array; pqPublicKey: Uint8Array },
    walletAddress: WalletAddress,
    signature: Uint8Array
  ): Promise<void> {
    await this.sendAndWait({
      rotate_device_keys: {
        new_pubkeys: {
          public_key: Buffer.from(newPubkeys.publicKey),
          pq_public_key: Buffer.from(newPubkeys.pqPublicKey),
        },
        wallet_address: walletAddress,
        signature: Buffer.from(signature),
      },
    });
  }

  async disconnect(): Promise<void> {
    this.#intentionalClose = true;
    this.#reconnectRestore = null;
    this.#decisionHandler = null;
    this.#teardownTransport(new Error('Disconnected'));
  }
}

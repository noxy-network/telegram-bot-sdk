import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { base64 } from '@scure/base';

export type NoxyFileStorageOptions = {
  /** Directory for persisted device data and encrypted keys */
  dataDir: string;
  /** 16, 24, or 32 bytes; if omitted, a key is generated and stored in dataDir */
  encryptionKey?: Uint8Array;
};

const DEVICES_FILE = 'devices.json';
const KEY_FILE = '.noxy-storage-key';

async function ensureDir(dir: string): Promise<void> {
  await mkdir(dir, { recursive: true });
}

function aesGcmEncrypt(key: Uint8Array, plaintext: Uint8Array): { iv: Uint8Array; ciphertext: Uint8Array } {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const ciphertext = new Uint8Array(Buffer.concat([enc, tag]));
  return { iv, ciphertext };
}

function aesGcmDecrypt(key: Uint8Array, iv: Uint8Array, ciphertextWithTag: Uint8Array): Uint8Array {
  if (ciphertextWithTag.length < 16) throw new Error('Invalid ciphertext');
  const tag = Buffer.from(ciphertextWithTag.subarray(ciphertextWithTag.length - 16));
  const enc = Buffer.from(ciphertextWithTag.subarray(0, ciphertextWithTag.length - 16));
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return new Uint8Array(Buffer.concat([decipher.update(enc), decipher.final()]));
}

export class NoxyFileStorage {
  readonly #dataDir: string;
  #encryptionKey: Uint8Array | null;

  constructor(options: NoxyFileStorageOptions) {
    this.#dataDir = options.dataDir;
    this.#encryptionKey = options.encryptionKey ?? null;
  }

  async #resolveKey(): Promise<Uint8Array> {
    if (this.#encryptionKey) return this.#encryptionKey;
    await ensureDir(this.#dataDir);
    const keyPath = path.join(this.#dataDir, KEY_FILE);
    try {
      const raw = await readFile(keyPath, 'utf8');
      const buf = base64.decode(raw.trim());
      if (![16, 24, 32].includes(buf.length)) throw new Error('Invalid stored encryption key length');
      this.#encryptionKey = buf;
      return buf;
    } catch {
      const k = randomBytes(32);
      await writeFile(keyPath, base64.encode(k), 'utf8');
      this.#encryptionKey = k;
      return k;
    }
  }

  devicePk(appId: string, identityId: string): string {
    return `${appId}_${identityId}`;
  }

  async loadDevices(): Promise<Record<string, unknown>> {
    await ensureDir(this.#dataDir);
    const f = path.join(this.#dataDir, DEVICES_FILE);
    try {
      const raw = await readFile(f, 'utf8');
      return JSON.parse(raw) as Record<string, unknown>;
    } catch {
      return {};
    }
  }

  async saveDevices(devices: Record<string, unknown>): Promise<void> {
    await ensureDir(this.#dataDir);
    const f = path.join(this.#dataDir, DEVICES_FILE);
    await writeFile(f, JSON.stringify(devices, null, 2), 'utf8');
  }

  async saveEncryptedDeviceKeys(pk: string, data: Uint8Array): Promise<void> {
    const key = await this.#resolveKey();
    const { iv, ciphertext } = aesGcmEncrypt(key, data);
    await ensureDir(this.#dataDir);
    const payload = JSON.stringify({
      iv: Array.from(iv),
      ciphertext: Array.from(ciphertext),
    });
    await writeFile(path.join(this.#dataDir, `keys-${pk}.json`), payload, 'utf8');
  }

  async loadDecryptedDeviceKeys(pk: string): Promise<Uint8Array | undefined> {
    const key = await this.#resolveKey();
    const f = path.join(this.#dataDir, `keys-${pk}.json`);
    try {
      const raw = JSON.parse(await readFile(f, 'utf8')) as { iv: number[]; ciphertext: number[] };
      const iv = new Uint8Array(raw.iv);
      const ciphertext = new Uint8Array(raw.ciphertext);
      return aesGcmDecrypt(key, iv, ciphertext);
    } catch {
      return undefined;
    }
  }
}

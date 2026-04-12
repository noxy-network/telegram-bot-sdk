import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import KyberModule from './kyber/kyber.js';
import { NoxyKyberProviderError } from './errors.js';

const PK_SIZE = 1184;
const SK_SIZE = 2400;
const CT_SIZE = 1088;
const SS_SIZE = 32;

function ensureWasmBinary(): ArrayBuffer {
  const g = globalThis as unknown as Record<string, ArrayBuffer | undefined>;
  if (g.__NOXY_KYBER_WASM_BINARY__) {
    return g.__NOXY_KYBER_WASM_BINARY__;
  }
  const dir = path.dirname(fileURLToPath(import.meta.url));
  const wasmPath = path.join(dir, 'kyber', 'kyber.wasm');
  const buf = readFileSync(wasmPath);
  const wasmBinary = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  g.__NOXY_KYBER_WASM_BINARY__ = wasmBinary;
  return wasmBinary;
}

export class NoxyKyberProvider {
  private mod: Awaited<ReturnType<typeof KyberModule>>;

  private static instance: Promise<NoxyKyberProvider> | undefined;

  private constructor(mod: Awaited<ReturnType<typeof KyberModule>>) {
    this.mod = mod;
  }

  static async create(): Promise<NoxyKyberProvider> {
    if (NoxyKyberProvider.instance !== undefined) return NoxyKyberProvider.instance;
    NoxyKyberProvider.instance = (async () => {
      const wasmBinary = ensureWasmBinary();
      const mod = await KyberModule({
        wasmBinary,
        locateFile: (p: string) => {
          const dir = path.dirname(fileURLToPath(import.meta.url));
          return pathToFileURL(path.join(dir, 'kyber', p)).href;
        },
      });
      return new NoxyKyberProvider(mod);
    })();
    return NoxyKyberProvider.instance;
  }

  static reset(): void {
    NoxyKyberProvider.instance = undefined;
  }

  keypair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
    this.assertReady();

    const pkPtr = this.mod._malloc(PK_SIZE);
    const skPtr = this.mod._malloc(SK_SIZE);

    try {
      this.mod._kyber_keypair(pkPtr, skPtr);

      return {
        publicKey: this.read(pkPtr, PK_SIZE),
        secretKey: this.read(skPtr, SK_SIZE),
      };
    } finally {
      this.zeroAndFree(pkPtr, PK_SIZE);
      this.zeroAndFree(skPtr, SK_SIZE);
    }
  }

  encapsulate(publicKey: Uint8Array): {
    ciphertext: Uint8Array;
    sharedSecret: Uint8Array;
  } {
    this.assertReady();
    this.assertSize(publicKey, PK_SIZE, 'publicKey');

    const pkPtr = this.allocAndWrite(publicKey);
    const ctPtr = this.mod._malloc(CT_SIZE);
    const ssPtr = this.mod._malloc(SS_SIZE);

    try {
      this.mod._kyber_enc(ctPtr, ssPtr, pkPtr);

      return {
        ciphertext: this.read(ctPtr, CT_SIZE),
        sharedSecret: this.read(ssPtr, SS_SIZE),
      };
    } finally {
      this.zeroAndFree(pkPtr, PK_SIZE);
      this.zeroAndFree(ctPtr, CT_SIZE);
      this.zeroAndFree(ssPtr, SS_SIZE);
    }
  }

  decapsulate(secretKey: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    this.assertReady();
    this.assertSize(secretKey, SK_SIZE, 'secretKey');
    this.assertSize(ciphertext, CT_SIZE, 'ciphertext');

    const skPtr = this.allocAndWrite(secretKey);
    const ctPtr = this.allocAndWrite(ciphertext);
    const ssPtr = this.mod._malloc(SS_SIZE);

    try {
      this.mod._kyber_dec(ssPtr, ctPtr, skPtr);
      return this.read(ssPtr, SS_SIZE);
    } finally {
      this.zeroAndFree(skPtr, SK_SIZE);
      this.zeroAndFree(ctPtr, CT_SIZE);
      this.zeroAndFree(ssPtr, SS_SIZE);
    }
  }

  private allocAndWrite(buf: Uint8Array): number {
    const ptr = this.mod._malloc(buf.length);
    this.mod.HEAPU8.set(buf, ptr);
    return ptr;
  }

  private read(ptr: number, len: number): Uint8Array {
    return new Uint8Array(this.mod.HEAPU8.buffer, ptr, len).slice();
  }

  private zeroAndFree(ptr: number, len: number) {
    this.mod.HEAPU8.fill(0, ptr, ptr + len);
    this.mod._free(ptr);
  }

  private assertReady() {
    if (!this.mod) {
      throw new NoxyKyberProviderError({
        code: 'KYBER_PROVIDER_NOT_INITIALIZED',
        message: 'KyberProvider not initialized',
      });
    }
  }

  private assertSize(buf: Uint8Array, expected: number, name: string) {
    if (buf.length !== expected) {
      throw new NoxyKyberProviderError({
        code: 'KYBER_PROVIDER_INVALID_SIZE',
        message: `${name} must be ${expected} bytes, got ${buf.length}`,
      });
    }
  }
}

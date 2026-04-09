interface KyberModuleOptions {
  wasmBinary?: ArrayBuffer;
  locateFile?: (path: string, scriptDirectory: string) => string;
}

interface KyberModuleInstance {
  _malloc: (size: number) => number;
  _free: (ptr: number) => void;
  _kyber_keypair: (pk: number, sk: number) => void;
  _kyber_enc: (ct: number, ss: number, pk: number) => void;
  _kyber_dec: (ss: number, ct: number, sk: number) => void;
  HEAPU8: Uint8Array;
}

declare function KyberModule(
  opts?: KyberModuleOptions
): Promise<KyberModuleInstance>;

export default KyberModule;

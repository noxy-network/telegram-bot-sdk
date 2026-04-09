import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export function loadDeviceServiceClient(): grpc.ServiceClientConstructor {
  const protoPath = path.join(__dirname, '..', 'proto', 'noxy.device.proto');
  const packageDefinition = protoLoader.loadSync(protoPath, {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true,
    includeDirs: [path.join(__dirname, '..', 'proto')],
  });
  const pkg = grpc.loadPackageDefinition(packageDefinition) as {
    noxy?: { device?: { DeviceService: grpc.ServiceClientConstructor } };
  };
  const Ctor = pkg.noxy?.device?.DeviceService;
  if (!Ctor) {
    throw new Error('Failed to load noxy.device.DeviceService from proto');
  }
  return Ctor;
}

export function parseRelayTarget(relayUrl: string): { host: string; port: number } {
  const u = new URL(relayUrl);
  const host = u.hostname;
  const port = u.port ? Number(u.port) : u.protocol === 'https:' ? 443 : 80;
  return { host, port };
}

export function relayChannelCredentials(relayUrl: string): grpc.ChannelCredentials {
  const u = new URL(relayUrl);
  if (u.protocol === 'https:') {
    return grpc.credentials.createSsl();
  }
  if (u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1')) {
    return grpc.credentials.createInsecure();
  }
  throw new Error('relayUrl must use https://, or http:// for localhost only');
}

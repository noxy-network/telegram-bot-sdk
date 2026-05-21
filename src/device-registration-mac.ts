import { createHash, createHmac } from 'node:crypto';

const PREFIX = 'NOXY_DEVICE_REGISTER_V1';
const SEP = '\u001f';

function sha256Hex(buf: Uint8Array): string {
  return createHash('sha256').update(Buffer.from(buf)).digest('hex');
}

export type DeviceRegistrationMacParams = {
  appId: string;
  identityType: string;
  logicalIdentityId: string;
  publicKey: Uint8Array;
  pqPublicKey: Uint8Array;
  deviceType: string;
};

export function signDeviceRegistrationMacForWallet(
  secret: string,
  appId: string,
  logicalIdentityId: string,
  publicKey: Uint8Array,
  pqPublicKey: Uint8Array,
  deviceType: string
): Uint8Array {
  return signDeviceRegistrationMac(secret, {
    appId,
    identityType: 'wallet',
    logicalIdentityId,
    publicKey,
    pqPublicKey,
    deviceType,
  });
}

export function signDeviceRegistrationMacForEmail(
  secret: string,
  appId: string,
  logicalIdentityId: string,
  publicKey: Uint8Array,
  pqPublicKey: Uint8Array,
  deviceType: string
): Uint8Array {
  return signDeviceRegistrationMac(secret, {
    appId,
    identityType: 'email',
    logicalIdentityId,
    publicKey,
    pqPublicKey,
    deviceType,
  });
}

export function signDeviceRegistrationMacForPhone(
  secret: string,
  appId: string,
  logicalIdentityId: string,
  publicKey: Uint8Array,
  pqPublicKey: Uint8Array,
  deviceType: string
): Uint8Array {
  return signDeviceRegistrationMac(secret, {
    appId,
    identityType: 'phone',
    logicalIdentityId,
    publicKey,
    pqPublicKey,
    deviceType,
  });
}

export function signDeviceRegistrationMacForUserId(
  secret: string,
  appId: string,
  logicalIdentityId: string,
  publicKey: Uint8Array,
  pqPublicKey: Uint8Array,
  deviceType: string
): Uint8Array {
  return signDeviceRegistrationMac(secret, {
    appId,
    identityType: 'user_id',
    logicalIdentityId,
    publicKey,
    pqPublicKey,
    deviceType,
  });
}

export function signDeviceRegistrationMac(secret: string, params: DeviceRegistrationMacParams): Uint8Array {
  const msg =
    PREFIX +
    SEP +
    params.appId +
    SEP +
    params.identityType +
    SEP +
    params.logicalIdentityId +
    SEP +
    sha256Hex(params.publicKey) +
    SEP +
    sha256Hex(params.pqPublicKey) +
    SEP +
    params.deviceType;
  const mac = createHmac('sha256', Buffer.from(secret.trim(), 'utf8')).update(msg, 'utf8').digest();
  return new Uint8Array(mac);
}

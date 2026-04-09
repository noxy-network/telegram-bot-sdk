import { NoxyTelegramClient, NoxyDecisionOutcomeValues, NOXY_DEVICE_RELAY_TYPE_TELEGRAM } from '../dist/index.js';

if (typeof NoxyTelegramClient.create !== 'function') throw new Error('NoxyTelegramClient.create missing');
if (NoxyDecisionOutcomeValues.APPROVE !== 'APPROVE') throw new Error('NoxyDecisionOutcomeValues');
if (NOXY_DEVICE_RELAY_TYPE_TELEGRAM !== 'telegram') throw new Error('NOXY_DEVICE_RELAY_TYPE_TELEGRAM');

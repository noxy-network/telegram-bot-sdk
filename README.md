# 📦 @noxy-network/telegram-bot-sdk

Telegram Bot SDK to integrate with the [Noxy](https://noxy.network) **Decision Layer**: subscribe to encrypted decision requests, present them to the user, and respond with decision — all with wallet-based identity.

It connects your bot to the **Noxy Network** relay over **gRPC (TLS)** so users can **approve or reject** requests from Telegram, with payloads **encrypted** for your registered device.

If you are new to Noxy: think of it as a **decision layer** between your bot and operations—your bot receives **decision** events from the network, shows them in Telegram, then sends back **decision outcome**.

**Before you integrate:** Create your app at [noxy.network](https://noxy.network). When the app is created, you receive an **app id** and an **app token** (auth token). This SDK uses the **app id** (`appId` in `network`). The **app token** is for agent/orchestrator SDKs (Go, Rust, Python, Node, etc.), not for this package.

## What you need

- **Node.js 18+**
- A **wallet-backed identity** (Ethereum address + signer) your bot uses to authenticate with the relay
- Your **app id** and the **relay URL** from Noxy (for example `https://relay.noxy.network`; the app id comes from creating the app above)
- A **directory on disk** where the SDK can store device keys (created and encrypted automatically)

Telegram itself is **not** handled by this package. Use [GrammY](https://grammy.dev), Telegraf, or any other library for `getUpdates`, webhooks, keyboards, and messages. This SDK only handles **Noxy ↔ your server**.

## Install

```bash
npm install @noxy-network/telegram-bot-sdk
# or
pnpm add @noxy-network/telegram-bot-sdk
# or
yarn add @noxy-network/telegram-bot-sdk
```

## Basic flow

1. Call **`initialize()`**—it connects to the relay, loads or registers a **device**, and authenticates.
2. Call **`on()`** with a handler `(decisionId, decision)` — `decision` is decrypted JSON from the relay; `decisionId` is resolved for use with **`sendDecisionOutcome()`**.
3. After the user acts in Telegram, call **`sendDecisionOutcome()`** with **`NoxyDecisionOutcomeValues.APPROVE`** or **`NoxyDecisionOutcomeValues.REJECT`** (or the strings `'APPROVE'` / `'REJECT'`).
4. When shutting down, call **`close()`** to disconnect from the relay.

## Example

```typescript
import { NoxyDecisionOutcomeValues, NoxyTelegramClient } from '@noxy-network/telegram-bot-sdk';

const client = await NoxyTelegramClient.create({
  identity: {
    address: '0x…',
    signer: async (data) => wallet.signMessage({ message: { raw: data } }),
  },
  network: {
    appId: 'your-app-id',
    relayUrl: 'https://relay.noxy.network',
  },
  storage: { dataDir: './.noxy-data' },
});

await client.initialize();

await client.on(async (decisionId, decision) => {
  // Update Telegram UI, wait for user tap, then:
  if (decisionId) await client.sendDecisionOutcome(decisionId, NoxyDecisionOutcomeValues.APPROVE);
});

await client.close();
```

## Protocol and transport

The relay speaks **gRPC over HTTP/2**. The client keeps a **bidirectional stream** open, sends authentication and registration messages, subscribes to **decisions**, and can send **acknowledgements** and **outcomes**. Reference **`.proto`** files are published under `proto/` in the npm package.

## Developing this package

```bash
pnpm install
pnpm run build
pnpm run typecheck
```

## License

MIT © Noxy Network

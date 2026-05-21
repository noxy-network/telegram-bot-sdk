# 📦 @noxy-network/telegram-bot-sdk

Telegram Bot SDK for [Noxy](https://noxy.network).

## What is Noxy?

[Noxy](https://noxy.network) adds **human-in-the-loop** guardrails between automation and sensitive actions: your integration receives encrypted prompts from the relay, you surface them (e.g. in Telegram), the **user makes a decision**, and you **`sendDecisionOutcome`**—without plaintext prompts on the relay.

This package connects your server to the **Noxy relay over gRPC (TLS)** so payloads stay **encrypted** for your registered device. Telegram UI (**GrammY**, Telegraf, etc.) is up to you; this SDK only handles **Noxy ↔ your server**.

## Before you integrate

Create your app at [noxy.network](https://noxy.network). On the dashboard, copy **APP_ID** into **`network.appId`** and **APP_SIGNING_SECRET** into **`network.appSigningSecret`**. Agent backends use a separate **app token**, not these values.

## Features

- **Human-in-the-loop** — Decrypted prompts in your handler; **`sendDecisionOutcome`** publishes the user’s outcome to the relay.
- **gRPC** — Bidirectional stream to the relay (subscribe, ack, outcomes). Proto references ship under `proto/` in the npm package.
- **Relay identities** — **`wallet`**, **`email`**, **`phone`**, **`user_id`** — see [Relay identity types](#relay-identity-types).
- **Local device keys** — Encrypted on-disk storage under your chosen **`dataDir`**.

## Relay identity types

The relay **`identity_type`** values are **`wallet`**, **`email`**, **`phone`**, and **`user_id`**. In TypeScript use **`NOXY_IDENTITY_TYPE`** (`USER_ID` corresponds to wire **`user_id`**).

### Initializing identities

**Wallet** — `address` + `signer` (optional explicit `identityType: NOXY_IDENTITY_TYPE.WALLET`). Registration still uses **`network.appSigningSecret`** (**APP_SIGNING_SECRET**).

**Email / phone / user_id** — `identityType` + **`identityId`** only (no signer). Registration uses **`network.appSigningSecret`** (**APP_SIGNING_SECRET**) for every kind.

Use **`logicalIdentityId`** on the client for the stable string across kinds.

## What you need

- **Node.js 18+**
- A configured **relay identity** (see [Relay identity types](#relay-identity-types))
- Your dashboard **APP_ID**, **APP_SIGNING_SECRET**, and **relay URL** (e.g. `https://relay.noxy.network`)
- A **directory on disk** for encrypted device keys (`storage.dataDir`)

Telegram chat UX is **not** handled here — use [GrammY](https://grammy.dev), Telegraf, or similar.

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
3. After the user decides in Telegram, call **`sendDecisionOutcome()`** with the appropriate **`NoxyDecisionOutcomeValues`** case (for example **`APPROVE`** / **`REJECT`**, or the strings `'APPROVE'` / `'REJECT'`), matching whatever your integration exposes today.
4. When shutting down, call **`close()`** to disconnect from the relay.

## Example (wallet)

```typescript
import { NoxyDecisionOutcomeValues, NoxyTelegramClient, NOXY_IDENTITY_TYPE } from '@noxy-network/telegram-bot-sdk';

const client = await NoxyTelegramClient.create({
  identity: {
    identityType: NOXY_IDENTITY_TYPE.WALLET,
    address: '0x…',
    signer: async (data) => wallet.signMessage({ message: { raw: data } }),
  },
  network: {
    appId: 'your-app-id',
    relayUrl: 'https://relay.noxy.network',
    appSigningSecret: 'paste-app-signing-secret-here',
  },
  storage: { dataDir: './.noxy-data' },
});

await client.initialize();

await client.on(async (decisionId, decision) => {
  if (decisionId) await client.sendDecisionOutcome(decisionId, NoxyDecisionOutcomeValues.APPROVE);
});

await client.close();
```

## Example (opaque user id on relay as `user_id`)

```typescript
import { NoxyTelegramClient, NOXY_IDENTITY_TYPE } from '@noxy-network/telegram-bot-sdk';

const client = await NoxyTelegramClient.create({
  identity: {
    identityType: NOXY_IDENTITY_TYPE.USER_ID,
    identityId: 'service-account-or-internal-user-id',
  },
  network: {
    appId: 'your-app-id',
    relayUrl: 'https://relay.noxy.network',
    appSigningSecret: 'paste-app-signing-secret-here',
  },
  storage: { dataDir: './.noxy-data' },
});

await client.initialize();
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

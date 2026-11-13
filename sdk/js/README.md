# @blox/sdk

Connect a site or app to a Blox phone keystore (see the repository README and BLOX.md §9).

```ts
// wagmi: one import, one connector
import { blox } from "@blox/sdk/wagmi";
createConfig({ chains, connectors: [injected(), blox({ name: "Example" })], transports });

// or directly
import { Blox } from "@blox/sdk";
const b = new Blox({ name: "Example" });
const { account } = await b.connect();
const { txHash } = await b.send({ chain: 8453, to: "0x…", value: 10n ** 16n });
```

- In browsers the connection's keys are non-extractable WebCrypto keys kept in IndexedDB;
  elsewhere they are raw keys (`@noble/curves`) in the store you pass (`MemoryStore` built in).
- `createProvider(opts)` gives an EIP-1193 provider for ethers, web3-react or plain viem.
- Errors are `BloxError` with a `code` (`rejected`, `failed`, `timeout`, `disconnected`, …).

## Development

```sh
cargo build -p blox-relay -p blox-mock-keystore   # from the repository root
deno task test                                    # needs anvil for the integration tests
npm run build                                     # tsc → dist/
```

`demo/` is a wagmi page on Sepolia built from the source with `deno task demo` (no npm); see
`demo/README.md`.

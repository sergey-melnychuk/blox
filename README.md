# Blox

Blox makes your phone the authority over your keys. Sites and apps hold no keys and need no
wallet: they say what they want done ("call this contract with this calldata and 0.01 ETH on
Base"), and the Blox app fills in nonce, gas and fees from its own endpoint, shows the
complete transaction, signs it if you approve, and broadcasts it (or returns it signed).

A site connects to one of your signers once, with a QR code. After that its requests go
through a relay, which keeps them for 5 minutes for the phone to pick up. The relay is blind:
everything is end-to-end encrypted, and it accepts writes only from connected parties.

The full design is in [BLOX.md](BLOX.md). The implementation status is in [PLAN.md](PLAN.md).

> **Not audited.** Blox handles keys and signing but has had no security audit yet. Use it on
> test networks with test funds only. Report vulnerabilities privately: [SECURITY.md](SECURITY.md).
>
> **Status:** the protocol, relay, Rust requester, mock keystore and web SDK are implemented
> and tested (including against anvil and through `@wagmi/core`). The Android app has sent
> on Sepolia through the public relay from the demo site in Firefox, and connected from
> Safari on iOS; the full device checks (BLOX.md §13.4) are pending, and there is no release
> yet.

| Part | Where |
|---|---|
| Protocol (envelopes, tokens, offers, connections) | `crates/blox-proto` |
| EVM decoding, filling, signing, checks | `crates/blox-evm` |
| Relay | `crates/blox-relay` → binary `blox-relay` |
| Rust requester | `crates/blox-client` |
| Mock keystore (tests, local runs) | `crates/blox-mock-keystore` |
| Android bindings | `crates/blox-ffi` (UniFFI) |
| Android app | `android/` |
| Web SDK, wagmi connector, demo | `sdk/js` |
| Wire-format test vectors | `test-vectors/` |

## Integrating a site or app

**A site on wagmi** adds one dependency and one line:

```ts
import { blox } from "@blox/sdk/wagmi";

export const config = createConfig({
  chains: [mainnet, base],
  connectors: [injected(), blox({ name: "Example", relay: "https://relay.example.com" })],
  transports: { [mainnet.id]: http(), [base.id]: http() },
});
```

`sendTransaction`, `signMessage`, `signTypedData`, `switchChain` and reconnecting work as
usual. What reaches the phone is intent only: a nonce, gas or fees the site sets are dropped,
and the phone fills its own. Reads go to the site's own RPC.

**Other stacks** wrap the EIP-1193 provider:
`new BrowserProvider(createProvider({ name: "Example", relay: "https://relay.example.com" }))`.

**Directly:**

```ts
import { Blox } from "@blox/sdk";
const blox = new Blox({ name: "Example", relay: "https://relay.example.com" });
const { account } = await blox.connect();                       // QR code once
const { txHash } = await blox.send({ chain: 8453, to: "0x…", value: 10n ** 16n, data: "0x…" });
const { raw } = await blox.signTransaction({ chain: 8453, to: "0x…" });   // you broadcast
const { signature } = await blox.personalSign({ chain: 8453, message: "hello" });
await blox.disconnect();
```

What the user sees: a QR code the first time (scan it in the Blox app, pick a signer and how
long to remember the site, approve with a fingerprint); afterwards a small "Approve in the
Blox app" notice while each request waits on the phone.

**Login on your server.** Pass a 16-byte nonce from your server to `connect({ nonce })`; a new
connection returns `{ account, statement, signature }`, which your server checks with
`verifyConnection(…, { nonce })` (TypeScript) or `blox_client::verify_connection` (Rust).
This proves the account. It does not prove which site the user meant to connect to: a
phishing page can show your QR code (BLOX.md §3.3).

**Rust apps and backends** use `blox_client::Requester` (see
`crates/blox-client/examples/send.rs`).

## Running locally

[RUN.md](RUN.md) runs the whole flow on one machine with anvil and the mock keystore, and with
the Android app.

## Running a relay

```sh
BLOX_LISTEN=localhost:8080 cargo run --release -p blox-relay
```

To self-host, run it under systemd (or Docker) with Caddy in front for TLS:
[DEPLOY.md](DEPLOY.md) has the whole runbook (build, unit, Caddyfile, log rotation,
checks, upgrades), with the files in [`deploy/`](deploy/).

Limits (message TTL 5 minutes, queue sizes, rate limits, token lifetime) are flags and
environment variables; `blox-relay --help` lists them and `GET /v1/info` publishes them. The
relay keeps everything in memory and logs only route templates, status codes and latency.

## The app

**Installing and verifying.** Releases are reproducible builds signed with an offline key.
Each release publishes SHA-256 checksums and the signing certificate's fingerprint; check
an APK with

```sh
sha256sum blox-*.apk
apksigner verify --print-certs blox-*.apk     # compare the certificate SHA-256 digest
```

and rebuild it from the tagged source to compare the bytes (everything but the signature).

**Signers.** Add one or more signers; each is a new recovery phrase that you write down and
confirm. Each signer's seed is encrypted under its own Android Keystore key (StrongBox or the
secure environment) that needs your fingerprint or PIN for every use. Remove a signer from
its screen (you confirm by typing the end of its address); its key is deleted first.

**Endpoints.** Add an endpoint for every network you use (Settings). The app checks it with
`eth_chainId`. Transactions are filled from and sent through it; requests never choose it.

**Connections.** Each signer's screen lists the sites connected to it, with when they last
sent a request, and a Disconnect button. Connections also end on their own after the time you
chose (1, 30 or 90 days).

**Backups and restoring.** The recovery phrase is the only backup: nothing is backed up to the
cloud, on purpose. If you remove the phone's screen lock, Android invalidates the keys that
protect the seeds; restore each signer from its phrase (the address must match).

## Security model, briefly

- **The phone decides.** It builds every transaction from the request's intent and its own
  endpoint, shows all of it, and signs only what it showed. Dangerous calls (unlimited
  approvals, operator approvals, Permit/Permit2) need a typed confirmation.
- **The relay** sees IP addresses, timing, sizes, and which (unnamed) connection keys talk to
  which signer's inbox; it never sees accounts or contents, and can only delay or drop
  messages.
- **Connected sites** learn the signer's account. Separate signers stay unlinkable.
- **The endpoint you choose** sees your IP and transactions, as with any wallet.
- **Requesters' names are claims.** Check what the phone shows, not who it says it's from.
- **QR codes work once.** If someone else answers your QR code first, the site shows their
  account, not yours, and your phone says the code was already used.
- **What is trusted:** the app's release key and build, Android and its Keystore, and the
  endpoints you configure (for chain state only).

BLOX.md §3 has the full threat model.

## Development

```sh
cargo test --workspace                     # Rust; the anvil tests skip if anvil is missing
cd sdk/js && deno task test                # TypeScript SDK (build the relay and mock keystore first)
```

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

Blox does not accept outside code contributions. Bug reports and feature requests are welcome
as issues; security problems go through [SECURITY.md](SECURITY.md).

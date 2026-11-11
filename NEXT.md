# Next steps

**Plan change (2026-11-10):** the phone fills, signs and broadcasts (or returns the signed
transaction); sites and apps connect to one signer once with a QR code and then send intent
through the relay, which authorizes writes with connection tokens and keeps messages 5 minutes.
The JSON-RPC adapter (`blox rpc`) is retired. See BLOX.md §16.

**Done so far:** M1, M2 (retired), M3, M4, the Rust side of M5
(`blox-ffi`), M6 except browser checks, and M7's files. The Android app (M5) is written but
not yet compiled. Step-by-step status, notes and what's left: PLAN.md.

## M3: connections (Rust)

- [x] `blox-proto`: Ed25519 connection tokens (§4.3), request signatures (§4.4), the new envelope with `bind` / `message` (§4.5), the QR payload with ticket and PSK (§5.1), the connection statement with its exact format (§5.2), relay URL normalization (§4.3); test vectors with fixed ephemeral keys
- [x] `blox-relay`: inboxes keyed by Ed25519 keys, several readers per inbox, signed reads and acks, token-checked writes, tickets, revocation, TTL 5 min, the §8.4 limits (incl. 4 queued per writer), CORS; `{ "error": code }` bodies and `now` in `/v1/info` (§8.2); logging rules for the new headers
- [x] `blox-client`: `Requester::connect`, a connection store (file by default), `disconnect`, `verify_connection`, relay time (§4.8)
- [x] `blox-mock-keystore`: signers with transport keys, connect (revoke on missing `bound`), connection list, disconnect
- [x] Gates: §13.2 relay and connection checks, §13.3
- [x] Remove `blox-adapter` and `blox-cli`

## M4: requests (Rust)

- [x] Messages (§6): `evm.send`, `evm.sign_tx`, `cancel`, `sent` / `signed_tx` / `signed` / `failed` / `rejected`, reasons `no_endpoint` and `would_fail`
- [x] `blox-evm`: build the transaction from intent plus endpoint data (`intent`, `fill`, `keystore`, `check`; the adapter-era `TxRequest` is gone), the estimate-gas check, display updates
- [x] `blox-client`: `send`, `sign_transaction`, `personal_sign`, `sign_typed_data` with the §9.5 checks
- [x] Mock keystore with an anvil endpoint and two signers; acknowledge requests only once answered, store answers for redelivery (§10.6, §10.8); port the anvil tests to the §13.1 gates
- [x] Rewrite `RUN.md`

## M5: Android

`[~]` = written, not compiled yet.

- [~] Signers: add (generate + backup check), remove (ends connections, auth + typed confirmation, deletes the wrapping key and transport keys), view phrase; one wrapping key per signer; transport keys under `blox.transport.wrap.v1`
- [~] Import only in debug builds (anvil test phrase); restore of existing signers in all builds
- [~] Connect screen (signer picker, remember-for, biometric, statement signature); connection list per signer with disconnect
- [~] Reading inboxes in the foreground; requests grouped by connection, cancelled and duplicate-looking requests; stored answers for redelivered requests (§10.6)
- [~] Settings: chain endpoints (checked with `eth_chainId`), relay list with the consent prompt
- [~] `ChainRpc` foreign trait (`EndpointRpc`; Rust side done and tested; OkHttp implementation written); filling and sending in Rust
- [~] Review screen: filled fields, endpoint host, would-fail and no-endpoint states, "Sent · hash" / "Returned to the site"
- [~] Audit log (JSON lines, exported as text; Room and a viewer later)
- [ ] Build the app, on-device checks (§13.4), an instrumented test of the bindings against `test-vectors/`
- [ ] Carried over: the recovery phrase held as a `String` in Compose state

## M6: Web SDK

- [x] `@blox/sdk` (no wasm): WebCrypto non-extractable keys in IndexedDB in browsers, `@noble` raw keys elsewhere, Web Locks for connecting and one request in flight, `sessionStorage` cancel after reload (§9.2, §9.6)
- [x] The modal (shadow root, request toast), `verifyConnection`
- [x] EIP-1193 provider (§9.3 method and error tables) and the wagmi connector `@blox/sdk/wagmi`
- [x] Deno test with `@wagmi/core` against the Rust relay, mock keystore and anvil; a wagmi demo page
- [ ] Browser checks (IndexedDB, Web Locks, Safari) and the one-dependency check in fresh Vite and Next.js apps

## M7: Deploy and release

- [x] Dockerfile and Caddyfile, README (§14.2)
- [ ] Deploy `relay.example.com`, reproducible signed APK

## Later

- v2 (BLOX.md §12): push and a background listener, per-connection policies, simulation with yevm (license first), importing mnemonics in release builds, more accounts per signer, iOS
- yevm-gate: use the SDK instead of `blox-adapter`

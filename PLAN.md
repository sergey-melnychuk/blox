# Implementation plan

Implements BLOX.md (connections, relay authorization, phone-filled requests, web SDK).
One commit per step; this file is updated in the same commit with the
step's status and anything implementation-specific worth knowing.

Status: `[ ]` to do · `[~]` in progress · `[x]` done · `[!]` needs the user (can't be done or
verified on this machine).

**This machine:** Rust 1.99, Foundry 1.8.3 (anvil), Deno 1.46 (runs the TypeScript SDK and its
tests), network access. **No Android SDK/NDK and no browser:** Kotlin is written but not
compiled here, and browser-only APIs (IndexedDB, Web Locks, the modal) are written against the
standards and tested only where Deno provides them.

**Rule for every step:** `cargo test --workspace` (and `deno test` once the SDK exists) passes
before the commit. Crates that a step's protocol change would break are temporarily excluded
from the workspace (`[workspace] exclude`) and brought back in a later step; the exclusions are
listed below while they exist.

---

## Step 0 — Spec and plan  `[x]`
- Commit BLOX.md, NEXT.md and this plan.

## M3 — connections (Rust)

### 3.1 Protocol primitives in `blox-proto` (additive)  `[x]`
- `ed25519-dalek` dependency. `ident`: Ed25519 signing/verifying keys (secret bytes for storage,
  `Debug` hides values), `InboxId` (the verifying key, base64url, 43 chars).
- `relay_url::normalize` (§4.3) and the QR relay field mapping (§5.1).
- `token`: body encoding, `token_id`, signing by each party, verification, `Blox-Token` header (§4.3).
- `reqsig`: `Authorization: Blox <ts>.<sig>` build and verify, with the clock error kept
  distinct from a bad signature (§4.4).
- `statement`: render the connection statement exactly (§5.2).
- `api`: the relay's JSON shapes and error codes (§8.2), shared by the relay and the clients.
- Unit tests for each.

### 3.2 Retire the JSON-RPC adapter  `[x]`
- Delete `blox-adapter` and `blox-cli` (and the `cast`/`forge` tests). `TxRequest`/`Fill` stay
  in `blox-evm` for M4.

### 3.3 Relay v1: inboxes with signature checks  `[x]`
- Routes of §8.2: write (token or ticket), signed SSE read with several readers per inbox,
  signed ack, ticket registration, revocation, `/v1/info` with `now`.
- Store: per-writer quota (4), readers per inbox (8), tickets (hash → inbox, expiry, used),
  revocations (token_id → expiry), sweeps for all of them.
- Rate limits per IP and per writer key; revoke counts as a write.
- `{ "error": code }` bodies; CORS (tower-http); logging rules for the new headers.
- Limits and CLI flags from §8.4; TTL 5 min.
- Relay API tests rewritten: the §13.2 relay checks and §13.3.
- The old mock-keystore session tests (old relay API) are removed here; 3.6 replaces them.

### 3.4 Connection protocol in `blox-proto`  `[x]`
- Envelope: `spk` always present, `bind` sealed with HPKE `auth_psk`, `message` with `auth`,
  AAD bound to the recipient's inbox key (§4.5).
- Messages: `bind`, `bound`, `sign_request`, `sign_response`, `cancel`, `unbind` (§4.6, §6).
- Offer (QR payload) with ticket and PSK (§5.1).
- Sans-IO state machines: requester connect attempt (offer → bind check → countersign → bound),
  keystore accept (offer → token + statement + bind; bound → connection), and a live
  `Connection` that seals to and opens from its peer. Replay set with 10-minute retention.
- The account signature on the statement is checked by the caller (needs secp256k1, which
  lives in `blox-evm`).
- Remove the old session modules (`mailbox`, `session`, `peer`); regenerate `test-vectors/`.
- `blox-evm`: the minimum to compile against the new messages (drop the adapter-era
  `verify.rs`; `prepare` takes the connection's account instead of a request field). 4.1
  rewrites it properly.
- Temporarily exclude `blox-client`, `blox-mock-keystore`, `blox-ffi` from the workspace.

### 3.5 Rust requester (`blox-client`)  `[x]`
- Relay client: signed requests, relay time offset (§4.8) with one retry after `401 clock`,
  error codes mapped to client errors, SSE reader that reconnects.
- `blox-evm`: sign and verify the connection statement (EIP-191).
- `Requester`: connect (QR callback, ticket registration, bind checks incl. the account
  signature via `blox-evm`), connection store (file with 0600, memory), generic
  `request(SignRequest) -> SignResponse` with one request in flight, cancel on timeout,
  `disconnect` (unbind + revoke), `verify_connection` for servers.
- Back in the workspace (with `blox-evm` as a dependency).

### 3.6 Mock keystore and the M3 integration tests  `[x]`
- `blox-mock-keystore`: signers with transport keys, accept an offer, wait for `bound` (revoke
  after the timeout), connection registry, inbox readers, dispatch by `spk`, answer requests
  with a handler, `cancel`, `unbind`, disconnect.
- Integration tests through a real relay: connect; restart from the store; two connections to
  one signer are isolated; two requesters sharing one store; cancel; disconnect from either side
  (403 afterwards); a used ticket; a missing `bound` revokes; spk/statement tampering; 10-minute
  client clock skew; the log-leak test.
- Back in the workspace.

## M4 — requests (Rust)

### 4.1 `blox-evm`: intent, filling, signing, checks  `[x]`
- Strict decoding of `evm.send` / `evm.sign_tx` payloads (no extra fields), `personal_sign`,
  `typed_data`; refusals of §6.3.
- `ChainRpc` trait (synchronous, JSON in and out, so UniFFI can expose it as a foreign trait)
  and the filler of §10.4: nonce rule, type 2 vs legacy, priority fee fallback, gas × 1.2,
  `would_fail`, balance warning.
- Signing and responses (`sent`, `signed_tx`, `signed`, `failed`), the statement signature, and
  the requester-side checks of §9.5 (replacing the adapter-era `verify.rs`).
- Display: signer, endpoint host ("Sent via" / "Returned to the site").

### 4.2 Requester calls  `[x]`
- `send`, `sign_transaction`, `personal_sign`, `sign_typed_data` on `Requester`, with the §9.5
  checks and `bad_response`.

### 4.3 Mock keystore with anvil  `[x]`
- Real filling and broadcasting against an anvil endpoint, two signers, acknowledgement only
  after answering, stored answers for redelivery (§10.6, §10.8).
- The §13.1 gates that need no phone or browser: send, consecutive nonces, sign_tx then
  broadcast by the requester, type 2 and legacy (`--hardfork berlin`), would_fail,
  no_endpoint, decode_failed, two signers, message signatures, offline-then-online within 5 min,
  crash redelivery. Skip with a message when anvil is missing.

### 4.4 Runnable mock keystore, example requester, `RUN.md`  `[x]`
- `blox-mock-keystore` binary: reads offer URIs on stdin, auto-approves with test signers,
  fills and sends through a given endpoint. Used by `RUN.md` and by the SDK's Deno tests.
- `blox-client` example that connects and sends; `RUN.md` rewritten for relay + mock keystore +
  anvil.

## M5 — Android

### 5.1 `blox-ffi` for the connection protocol  `[x]`
- Back in the workspace. UniFFI API for the app: transport keys, offer parsing, accept and
  bound, inbox dispatch, request preparation and filling through a `ChainRpc` foreign trait,
  signing and sending, stored answers, relay request signatures, mnemonic helpers. Rust tests
  drive it like the app would.

### 5.2 Android app  `[~]` builds; instrumented test passes; device checks pending
- Multiple signers (one wrapping key each), transport keys, settings (endpoints, relays), connect
  screen, connection list, inbox reading, request queue and review screen, audit log.
- Written on Linux without the Android SDK; built locally (see the notes). The bindings
  pass `test-vectors/` in an instrumented test on a phone. The other §13.4 device checks are
  pending.

## M6 — web SDK

### 6.1 Protocol in TypeScript  `[x]`
- `sdk/js`: base64url, Base45, padding, HPKE (`auth`, `auth_psk`) over WebCrypto, Ed25519
  request signatures, tokens, offer, statement. Passes `test-vectors/` under `deno test`.

### 6.2 Requester  `[x]`
- Relay client (fetch + SSE parsing, relay time), connect, requests with one in flight, cancel
  (incl. `sessionStorage` after reload), disconnect, storage (IndexedDB with non-extractable
  keys; memory for tests), Web Locks where available, EVM checks (`@noble`), `verifyConnection`.
- Deno integration test against the Rust relay and mock keystore (with anvil).

### 6.3 Provider, wagmi connector, modal  `[x]`
- EIP-1193 provider (§9.3 tables), `@blox/sdk/wagmi`, the modal and toast in a closed shadow
  root with an embedded QR encoder.
- Deno test with `@wagmi/core` against relay + mock keystore + anvil.

### 6.4 Demo page  `[x]` (browser checks `[!]`)
- A static wagmi demo page.
- **Browser checks** (IndexedDB non-extractable keys, Safari, the one-dependency Vite/Next.js
  check) `[!]`: need a browser and a phone.

## M7 — release

### 7.1 Deployment files and README  `[x]`
- `deploy/Dockerfile`, `deploy/Caddyfile`, README per §14.2.
- **Deploying `relay.example.com`, the release key and reproducible signed APKs** `[!]`: the user's.

---

## Notes
(Implementation-specific details are added here as steps complete.)

- **3.1:** `ed25519-dalek` 3 with strict verification (`verify_strict`) and weak keys refused,
  so a token or request can't be satisfied by a small-order key. The token's id covers only
  the body, so the half-signed and the countersigned token have the same id and one revocation
  covers both. `statement::iso8601` is a small civil-date conversion, to avoid a date crate.
- **3.2:** `RUN.md` carries an "outdated" banner until 4.4 rewrites it.
- **3.3:** The signed `path` is the API path from `/v1/` (spec §4.4 now says so), so a relay
  served under a base path works when the proxy strips the prefix. Readers register for
  wake-ups before reading the queue (`Notify::notified().enable()`), so a push between the
  read and the wait is never missed with several readers. A ticket write is checked and queued
  under one lock, and the ticket is marked used only if the message was queued. Revocation
  entries are kept until the token's own expiry, capped at the max lifetime from now. Request
  bodies over the limit get the JSON `too_large` error (the body extractor's rejection is
  mapped). The relay's header check is local until 3.4 moves it into `blox-proto`.
  `AppState::with_clock_offset` shifts the relay clock for client clock-skew tests.
  The ignored `thousand_readers_latency` gate passes in release mode (about 1 s for 1,000
  readers). The old mock-keystore session and log-leak tests are deleted; 3.6 replaces them.
- **3.4:** `connection::{ConnectAttempt, accept_offer, PendingConnection, Connection}` are
  sans-IO; every function that needs the time takes it (relay time). `Connection::new`
  rebuilds a connection from a stored token and X25519 secret, and insists on both token
  signatures, so a half-signed token never becomes a live connection. `open_bind` returns a
  `BindCandidate`; the caller checks the account signature (EIP-191, in `blox-evm`) before
  `accept`. A `bind` must have the token's `k` as `spk`, a statement identical to the one
  rebuilt from the token, the requester's own keys and relay, `issued_at` within 300 s, and
  at most 90 days of lifetime. The offer refuses labels over 32 bytes and a weak `S`. The
  default-relay QR URI is 188 characters. `test-vectors/proto-v1.json` was regenerated:
  tokens, token id, request signature, relay URLs, statement, bind/message envelopes, offer.
  `blox-evm` got the minimum to compile (`verify.rs` deleted, `prepare` without the account
  field); 4.1 rewrites it. **Workspace exclusions now:** `blox-client`, `blox-mock-keystore`,
  `blox-ffi`.
- **3.5:** `RelayClient` signs with relay time: it syncs from `/v1/info` before the first
  signed call and again after a `401 clock`, then retries once. `Requester::request` is
  generic (`SignRequest` → `SignResponse`); M4 adds the typed calls. It subscribes to inbox `S`
  before posting, so a fast answer can't be missed, and it pre-seals the `cancel` at request
  time, so a timed-out or dropped call can still withdraw it (the guard's `Drop` spawns the
  post). Responses to other requesters on the same connection (another tab) are left
  unacknowledged; undecryptable or stale messages are acknowledged and dropped; a replay is
  skipped. Contest detection (§5.3) looks at binds already delivered when the first valid one
  is handled; with an honest relay the ticket makes a second bind impossible, so this is
  covered by a unit-level check rather than an integration test. A stored connection is used
  only if it is unexpired and for the configured relay. `FileStore` writes 0600 via a temp
  file and rename. `verify_connection` (server login) parses the statement's `Account`,
  `Nonce`, `Issued` (≤ 300 s old) and `Expires` lines. **Workspace exclusions now:**
  `blox-mock-keystore`, `blox-ffi`.
- **3.6:** `MockKeystore` mirrors what the app does (§10.6): one reader per (relay, signer),
  dispatch by `spk` (a pending connect's `bound` first, then live connections), requests
  acknowledged only once answered/cancelled, answers stored and re-sent when a request is
  redelivered (recognised by the envelope's digest, since the replay set refuses it), a
  handler returning `None` models a user who hasn't acted. `go_offline`/`go_online` model the
  app being closed/opened. Test hooks: `bound_timeout`, `wrong_statement_key`. 11 integration
  tests + the log-leak test pass (repeated runs stable). Not covered by an integration test:
  a second valid `bind` (`contested`), which needs a misbehaving relay — the honest relay's
  single-use ticket makes it impossible; the client's check is a few lines in `connect_new`.
  **Workspace exclusions now:** `blox-ffi` (until 5.1).
- **4.1:** Modules: `intent` (strict payload decoding; `to` must be present, `null` deploys),
  `rpc` (`ChainRpc` trait: method + JSON params → JSON result, errors split into
  `Unreachable` and JSON-RPC `Rpc`), `fill` (§10.4; the filler also checks `eth_chainId`
  against the request's chain, so a mis-configured endpoint can't fill for another chain),
  `sign` (`Prepared::Tx { broadcast }`), `keystore` (review → approve → broadcast, with
  `Approved::Broadcast` returning raw + hash so the caller records them before sending,
  §10.8), `check` (§9.5 requester checks, replacing the adapter-era `verify.rs`), `display`
  (signer "label · address", "Sent via" / "Filled from … (returned to the site, not sent)",
  fill warnings). The JSON-RPC `TxRequest` builder from the adapter era is gone; `Fill` was
  replaced by the filler. A JSON-RPC error from `eth_estimateGas` is `would_fail`; any other
  failure is "unreachable" (Retry/Reject). The priority-fee fallback is taken only on a
  JSON-RPC error, not on a network error.
- **4.2:** `Requester::{send, sign_transaction, personal_sign, sign_typed_data}` take a
  `TxCall` (chain id, `to`, value, data) or a message, run `blox_evm::check::check` on the
  answer (a failed check is `BadResponse`), and turn `rejected` / `failed` into
  `Error::Rejected(reason)` / `Error::Failed { tx_hash, error }`. `check` accepts a
  `rejected` answer before decoding the request, so a request the phone refused as
  malformed reports the phone's reason. Requests carry `origin { name, url }` from
  `Config` (`origin_url` is new). Mock handlers get the message `ts` and relay `now`.
- **4.3:** `MockKeystore::app(signers, endpoints, options)` runs the app's flow with
  `blox_evm::keystore` (review → auto-approve → sign → record → broadcast); `would_fail` and
  an unreachable endpoint are answered as rejections. `rpc::HttpRpc` implements `ChainRpc`
  with async reqwest + `Handle::block_on`, so it must be called from `spawn_blocking` (the
  mock does). Before broadcasting, the mock stores a `failed` answer carrying the hash; a
  crash between signing and broadcasting therefore answers `failed` with that hash after the
  restart, and the next request reuses the nonce (the transaction never reached the
  endpoint). `crash_once(Crash::…)` + `go_offline`/`go_online` simulate the two crash points.
  The anvil tests (10) start their own anvil on a free port and skip with a message when it
  is missing; receipts are polled because anvil mines asynchronously.
- **4.4:** `blox-mock-keystore` binary: stdin takes `BLOX:` lines, stdout gives JSON lines
  (`ready`, `connected`, `error`); flags `--endpoint CHAIN=URL`, `--signers`, `--signer`,
  `--days`, `--mnemonic`. `examples/send.rs` (blox-client) draws the QR in the terminal or
  prints it (`--print-uri`), stores the connection in a 0600 file, and sends a transaction,
  a message, or disconnects. A smoke run with real processes (anvil, relay, mock keystore,
  example) connected, sent and mined a transaction, signed a message from the stored
  connection without a QR, and disconnected. `tests/qr_size.rs` pins the QR size: version 8
  for a typical offer, at most version 10. `RUN.md` is rewritten (without a phone; with the
  app, marked as pending 5.2). M4 is complete.
- **5.1:** The FFI is sans-IO: Kotlin does storage and HTTP, Rust everything else. API:
  `generate_transport_keys`, `sign_relay_request` (Authorization header), `parse_offer`,
  `normalize_relay_url`, `relay_host`; `Inbox` per (relay, signer) built from the transport
  secrets and stored `ConnectionRecord`s, with `accept_offer` (needs the unlocked mnemonic;
  returns the `bind` to post with the ticket), `abandon_connect` (the half-signed token to
  revoke), `on_envelope` → `Incoming::{Connected, Request, Redelivered, Cancelled, Unbound,
  Dropped}`, `answer`, `unbind`; `IncomingRequest::review(label, endpoint, host,
  last_sent_nonce, now)` → `ReviewOutcome::{Ready, Reject, WouldFail, Unreachable}`;
  `ReviewedRequest::approve(mnemonic, index)` → `ApproveOutcome::{Answer, Broadcast {…,
  if_interrupted}}`; `broadcast_transaction`; `EndpointRpc` is a UniFFI foreign trait
  (`call(method, params_json) → result_json`, errors `Unreachable`/`Rpc`). Redeliveries are
  recognised by envelope digest within a process; after an app restart the app finds the
  stored answer by request id. Kotlin bindings generate (4.6k lines) with the UniFFI CLI.
  The workspace has no exclusions any more.
- **5.2 (written, not compiled):** ~2,400 lines of Kotlin against the generated binding
  signatures (checked by hand: names, `UInt`/`ULong`, sealed classes, suspend calls).
  - `vault/SignerVault`: one wrapping key per signer (`blox.seed.wrap.v1.<id>`), transport
    keys under `blox.transport.wrap.v1` (no authentication), restore for listed signers,
    removal deletes the key first; migrates the earlier single seed as signer "Main".
  - `store/Stores.kt`: `Settings` (endpoints, relays with the default always listed),
    `Connections`, `Answers` (10 minutes, `commit()` so an answer is on disk before it is
    sent or broadcast), `AuditLog` (JSON lines, exported as text through the share sheet —
    not Room/SQLite as §10.9 suggests).
  - `relay/RelayClient` (signed requests, relay time, retry after `clock`, ticket post),
    `relay/HttpEndpoint` (`EndpointRpc` over OkHttp).
  - `keystore/Keystore`: readers per (relay, signer) while in the foreground (closed 30 s
    after going to the background), dispatch of `Incoming`, review/approve/broadcast with
    the stored `if_interrupted` answer first, expiry, cancel, unbind, the connect flow
    (relay consent → signer + remember-for → biometric → bind with ticket → wait for
    `bound`, revoke after 120 s), disconnect, signer and relay removal.
  - UI: home (requests grouped by connection, signers, Scan, status line), add signer
    (create with a backup check, or import an existing phrase), connect, review (duplicate notice,
    withdrawn, would-fail, Retry), signer (connections with Disconnect, view phrase,
    restore, remove with typed confirmation), settings (endpoints checked with
    `eth_chainId`, relays, audit export).
  - **Built locally** (AGP 9.4.1, Kotlin 2.2.10, NDK 30.0.16248370): the hand-written
    Kotlin compiled without changes and without warnings. The one error was in the
    *generated* bindings: a UniFFI error variant with a field named `message` collides with
    `Throwable.message` in Kotlin, so `RpcFailure`'s field is now `detail` (FFI only; the
    wire format is unchanged). `Scanner.kt` uses ZXing's `MultiFormatReader`, the only reader
    that honours `ALSO_INVERTED` (light-on-dark codes).
  - **Import and UI pass:** importing an existing phrase is a separate way to add a signer
    in every build (less safe, portable; BLOX.md §10.2), stored with `imported` and shown on
    the signer. The screens share one layout (`ui/Components.kt`): a top bar with Back, content
    in one 20 dp gutter, the screen's actions pinned at the bottom above the keyboard, titled
    sections on cards, full-width fields, label/value rows with one label column, a two-column
    phrase grid, and a fixed light/dark palette (`ui/Theme.kt`). Edge-to-edge with transparent
    bars. `-Pblox.screenshots` (debug only) drops `FLAG_SECURE` for UI work. Captions cut to
    the minimum (titles and choices say it). The backup check can be skipped.
  - **Key material wiped** (BLOX.md §10.2): `blox_evm::sign::signer_from_mnemonic` now
    derives itself (bip39 for the word list and checksum, PBKDF2-HMAC-SHA512 and BIP-32 on
    `hmac`/`sha2` with `zeroize` and `k256`) instead of alloy's `MnemonicBuilder`, whose
    coins-bip39 leaves the seed and chain codes in memory; a test checks it gives alloy's keys
    for 12/24-word phrases at several indices. `blox-ffi` has a global allocator that wipes
    every block on free (UniFFI's buffers carry the phrase). The app draws phrases from bytes
    (`SecretPhrase`, one character at a time, so neither a `String` nor the text layout cache
    holds a word) and wipes them on Hide or leaving. The instrumented test passes on the phone
    with both.
  - **End to end on the phone** (a test phone; RUN.md "With the Android app",
    `scripts/local-services.sh --no-keystore` on the LAN): signers Main (created) and Anvil
    (imported), both TEE; endpoint 31337 added and checked; scan → new relay → connect with
    Anvil; two sends mined (nonce 0 and 1, type 2, gas 25,200), a `personal_sign` that
    `cast wallet verify` accepts, and disconnect from the site. Fixed on the way: Home kept a
    stale connection count after a site disconnected (its lists were read outside the
    recomposing content lambda).
  - **Instrumented test** (`app/src/androidTest/.../BindingsVectorsTest.kt`, 6 tests, passed
    on a test phone): the generated bindings against
    `test-vectors/proto-v1.json` (relay URLs, request signatures, offer, mnemonic → account,
    `acceptOffer` and `abandonConnect`, and a request round trip: open the keystore-bound
    `sign_request`, redelivery, review with a Kotlin `EndpointRpc`, approve, broadcast,
    a JSON-RPC error thrown from Kotlin becomes `failed`, answer). The keystore's X25519 key is
    derived in Kotlin with RFC 9180 DeriveKeyPair from the vectors' IKM. Run it with
    `adb install -r` and `am instrument`, not `connectedDebugAndroidTest`: that task uninstalls
    the app afterwards, which deletes every signer's key (it did, once; android/README.md).
  - **Not done yet:** the other §13.4 device checks.
- **6.1:** `sdk/js/src`: `bytes`, `b64`, `base45`, `pad`, `relayUrl`, `keys` (two backends),
  `hpke` (RFC 9180 auth / auth_psk on `@noble/hashes` HMAC + WebCrypto AES-GCM), `wire`
  (tokens, request signatures, envelopes, offer, statement, messages). **Deno 1.46's WebCrypto
  X25519 `deriveBits` fails with "Invalid key" for every key** (Ed25519 works), so the SDK
  has a `raw` backend on `@noble/curves` for Node/Deno/servers (keys stored as bytes, as
  §9.6 allows for backends) and uses WebCrypto non-extractable keys in browsers, failing
  with `UnsupportedBrowser` there if WebCrypto is missing. The vector test reproduces the
  Rust token bytes, signatures, request signature, statement and offer URI exactly and opens
  the Rust envelopes; the webcrypto round-trip test skips under this Deno. `@noble` versions
  are pinned to viem 2.57's (curves 1.9.1, hashes 1.8.0) so viem sites ship nothing extra.
  `package.json`/`tsconfig.json` build with `tsc` (not run here: no Node).
- **6.2:** `src/relay.ts` (signed fetch, clock retry, SSE over `fetch` streaming),
  `src/store.ts` (`IndexedDbStore` keeping `CryptoKey`s by structured clone, `MemoryStore`),
  `src/evm.ts` (EIP-191, EIP-712 hashing written here, RLP, legacy/type-2 decoding and sender
  recovery on `@noble`, checksums, `checkResponse`), `src/blox.ts` (`Blox`: connect with
  contest detection, one request in flight through Web Locks or a promise chain, cancel
  pre-sealed at request time and sent on timeout, on `pagehide` with `keepalive` and a
  pre-signed request (valid for 60 s), and after a reload from `sessionStorage`; typed calls
  with `checkResponse`; `BloxError` codes; `verifyConnection`). `connect()` now also returns
  the `statement` and `signature` of a new connection, for server login (spec §9.2 updated;
  the Rust `Requester::connection_proof` does the same). The Deno integration test spawns the
  Rust relay, anvil and the mock keystore binary and runs connect, personal_sign,
  typed_data, send (checked on anvil), sign_tx (broadcast by the test), no_endpoint,
  restart from storage, disconnect and a stale copy, ±600 s clock skew, an expired request,
  and server login with a nonce. **Not exercised here:** IndexedDB, Web Locks,
  `sessionStorage`, `pagehide` (no browser).
- **6.3:** `src/qr.ts`: a QR encoder (level M, versions 1–10, one alphanumeric or byte
  segment). Pinned against the Rust `qrcode` crate in `test-vectors/qr-v1.json`: identical
  under the mask the Rust encoder chose; the two penalty implementations can prefer
  different masks (both valid), so the TS encoder may pick another mask than Rust.
  `src/ui.ts`: modal and toast in a closed shadow root, used when no `onQr`/`onStatus` is
  given in a browser (`requestUi: "none"` turns the toast off); Cancel calls
  `Blox.cancel()`, which aborts a connect or withdraws a request (`cancelled`).
  `src/provider.ts`: the §9.3 method and error tables; `eth_sendTransaction` drops nonce,
  gas, fees, type and access list, refuses 7702/blob fields and anything unknown; reads go to
  the site's transports. `src/wagmi.ts`: `blox()` returns the connector function directly
  (`@wagmi/core` is a type-only dependency), reads go through the wagmi config's transports.
  `Blox.restore()` loads a stored connection without a QR (for `eth_accounts` and
  `isAuthorized`). The wagmi test (`@wagmi/core` 3.6.9, viem 2.57.17) connects, sends with
  the caller's nonce/gas replaced by the phone's, signs a message and typed data, switches
  chain (4901 without an endpoint), reconnects a new config from storage without a QR, and
  disconnects. **Not exercised here:** the modal and toast DOM (no browser).
- **6.4:** `sdk/js/demo`: a Vite + wagmi page (connect, send, sign message, typed data,
  switch chain, disconnect) with the connector as the one added line; Vite aliases
  `@blox/sdk` to the SDK source, so no build step is needed. `?mock` prints the QR string for
  the mock keystore. Type-checked with Deno against wagmi 3.6.9 / viem 2.57.17; not run
  (no Node or browser here). Packaging (`npm run build` with `tsc`) is also untested here.
- **7.1:** `deploy/Dockerfile` (multi-stage, `rust:1-slim-bookworm` → distroless `cc` nonroot;
  pin by digest for production), `deploy/Caddyfile` (`flush_interval -1`, no access log),
  `.dockerignore`, and `README.md` per §14.2 with a status note. The image was not built here
  (pulling and running base images wasn't attempted). Deploying `relay.example.com`, the release
  key and signed reproducible APKs remain the user's.
- **7.1, systemd runbook:** `DEPLOY.md` (server, static build with `cargo zigbuild` for
  x86-64 and arm64 musl, install, Caddy from its apt repository, journal rotation with a
  logrotate alternative, checks, upgrade/rollback, troubleshooting, Docker alternative), with
  `deploy/blox-relay.service` (DynamicUser, read-only system, AF_INET/6 only, syscall filter,
  MemoryMax 1G, 65,536 files), `deploy/relay.env`, `deploy/journald-blox.conf`, and the
  Caddyfile's global log excluding the loggers that write client addresses and URIs on errors.
  Tested locally: both static builds; `caddy validate`; the RUN.md flow (connect, send,
  message, disconnect) through Caddy with the relay at debug: neither logged an address
  or an inbox path, including during a 502; Caddy replaces a client's `X-Forwarded-For`.
  Found on the way: `BLOX_TRUST_PROXY=1`, as the Dockerfile and README said, made the relay
  refuse to start (clap took only `true`/`false`); it now takes 1/0, yes/no, on/off too, and
  the start line logs `trust_proxy`. The relay's log has no colour codes off a terminal. The
  unit itself wasn't run (no Linux host here).

- **Fix after 7.1 (flaky anvil tests):** about one run in five hung for the full 300 s
  request timeout. Two causes, both found with tracing:
  1. *Mock keystore race:* the reader handled `bound` but `accept()` added the connection
     later, on another task; a request right behind `bound` was dropped as "not from a live
     connection". The reader now adds the connection itself (as `blox-ffi`'s `Inbox` already
     did).
  2. *Relay client:* with reqwest 0.13.5 / hyper-util 0.1.20 connection reuse, a request now
     and then never reached the relay (the relay saw 47 of 48 `DELETE`s). `RelayClient` now
     opens a fresh connection per call (`pool_max_idle_per_host(0)`, 10 s connect timeout) and
     gives every non-streaming call a 30 s timeout. Afterwards: 25/25 clean runs. Revisit
     pooling with newer hyper-util (a TLS handshake per relay call costs some latency).
- **Fix (test races):** three connection tests failed (one hung 300 s), and one
  anvil test now and then said "anvil did not start":
  1. `connect()` returns once the requester has posted `bound`; the mock records the
     connection when its reader handles it, a moment later. Tests that read
     `ks.connections()` right after connecting now wait for it (`recorded`).
  2. `go_offline()` right after connecting could stop the reader before it handled `bound`,
     and `go_online()` restarted readers only for recorded connections. It now also restarts
     them for connects waiting for `bound` (as the app keeps reading while it waits).
  3. The anvil harness picks a free port and releases it before anvil binds it; with a
     fresh relay connection per call, the port can be taken in between and anvil exits.
     The harness now starts anvil again on a new port.
  Afterwards: 25/25 clean runs of `blox-mock-keystore`.
- **SDK, run locally (Deno 2.9.8, TypeScript 6, Node 26):** all 18 tests pass, now including
  the integration and wagmi tests against the Rust binaries and anvil, and the **WebCrypto
  backend round-trip** (Deno 2's X25519 works, so the browser key path is exercised outside a
  browser too). Changes: newer `lib.dom` types want `Uint8Array<ArrayBuffer>` for WebCrypto
  and `fetch` bodies, so `own()` says so and the two `fetch` bodies go through it; the test
  harness finds anvil on the `PATH` (Homebrew) instead of silently skipping;
  `"nodeModulesDir": "auto"` so `deno task test` works on a fresh checkout under Deno 2;
  `deno.lock` is now format v5 (same versions). `npm run build` (tsc 5.9) builds `dist/`
  with `.js` imports.
- **Local services script:** `scripts/local-services.sh` starts anvil, the relay (plain HTTP)
  and the mock keystore (or not, with `--no-keystore`, for the app), all release builds, and
  stops them together. The keystore reads a FIFO the script holds open, so
  `echo 'BLOX:…' > target/local/keystore.in` reaches it. A local run through it:
  connect, send (mined), message signatures and a second send from the stored connection
  (consecutive nonce, type 2, gas = estimate × 1.2), disconnect.

## Picking this up on another machine

1. **Rust:** `cargo test --workspace` (the anvil tests need Foundry; `foundryup -i v1.8.3` was
   used here). `cargo clippy --workspace --all-targets` is clean.
2. **Android:** see `android/README.md` (setup) and RUN.md ("With the Android app"). Build with
   `./gradlew :app:assembleDebug`; the Gradle build runs cargo-ndk and generates the Kotlin
   bindings. Expect compiler fixes in `android/app/src/main/java/...`: the Kotlin was written
   against the generated signatures but never compiled.
3. **iOS (v2 in the spec):** the same Rust core works; Swift bindings come from
   `cargo run -p blox-ffi --bin uniffi-bindgen -- generate --library <libblox_ffi.dylib/.a>
   --language swift --out-dir <dir>`. `blox-ffi`'s API is platform-neutral (`EndpointRpc` is the
   only foreign trait); the vault and storage are per-platform (BLOX.md §12.4).
4. **Web SDK:** `cd sdk/js && deno task test` (after `cargo build -p blox-relay -p
   blox-mock-keystore`); `demo/` with Node for the browser checks below.

## Left for the user `[!]`

1. **Android (5.2):** the app builds and the instrumented vectors test passes; run the §13.4
   device checks (StrongBox and TEE devices, fingerprint/face/PIN, screen-lock removal and
   restore).
2. **Browser (6.x):** run `sdk/js/demo` (`npm install && npm run dev`) in Chrome, Firefox and
   Safari; check IndexedDB keys are non-extractable (`crypto.subtle.exportKey` fails), Web
   Locks across tabs, cancel on reload/`pagehide`; the one-dependency check in fresh Vite and
   Next.js apps.
3. **Release (7):** build and run the relay image, deploy behind Caddy at `relay.example.com`,
   create the offline release key, reproducible signed APKs with published checksums.
4. **Open product question:** the Permit2 danger flag makes every Uniswap swap need a typed
   confirmation; v2 per-connection policies could relax it (BLOX.md §12.2).

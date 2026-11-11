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

### 4.1 `blox-evm`: intent, filling, signing, checks  `[ ]`
- Strict decoding of `evm.send` / `evm.sign_tx` payloads (no extra fields), `personal_sign`,
  `typed_data`; refusals of §6.3.
- `ChainRpc` trait (synchronous, JSON in and out, so UniFFI can expose it as a foreign trait)
  and the filler of §10.4: nonce rule, type 2 vs legacy, priority fee fallback, gas × 1.2,
  `would_fail`, balance warning.
- Signing and responses (`sent`, `signed_tx`, `signed`, `failed`), the statement signature, and
  the requester-side checks of §9.5 (replacing the adapter-era `verify.rs`).
- Display: signer, endpoint host ("Sent via" / "Returned to the site").

### 4.2 Requester calls  `[ ]`
- `send`, `sign_transaction`, `personal_sign`, `sign_typed_data` on `Requester`, with the §9.5
  checks and `bad_response`.

### 4.3 Mock keystore with anvil  `[ ]`
- Real filling and broadcasting against an anvil endpoint, two signers, acknowledgement only
  after answering, stored answers for redelivery (§10.6, §10.8).
- The §13.1 gates that need no phone or browser: send, consecutive nonces, sign_tx then
  broadcast by the requester, type 2 and legacy (`--hardfork berlin`), would_fail,
  no_endpoint, decode_failed, two signers, message signatures, offline-then-online within 5 min,
  crash redelivery. Skip with a message when anvil is missing.

### 4.4 Runnable mock keystore, example requester, `RUN.md`  `[ ]`
- `blox-mock-keystore` binary: reads offer URIs on stdin, auto-approves with test signers,
  fills and sends through a given endpoint. Used by `RUN.md` and by the SDK's Deno tests.
- `blox-client` example that connects and sends; `RUN.md` rewritten for relay + mock keystore +
  anvil.

## M5 — Android

### 5.1 `blox-ffi` for the connection protocol  `[ ]`
- Back in the workspace. UniFFI API for the app: transport keys, offer parsing, accept and
  bound, inbox dispatch, request preparation and filling through a `ChainRpc` foreign trait,
  signing and sending, stored answers, relay request signatures, mnemonic helpers. Rust tests
  drive it like the app would.

### 5.2 Android app  `[!]`
- Multiple signers (one wrapping key each), transport keys, settings (endpoints, relays), connect
  screen, connection list, inbox reading, request queue and review screen, audit log.
- **Written here but not compiled:** no Android SDK on this machine. Building and the §13.4
  device checks are for the user.

## M6 — web SDK

### 6.1 Protocol in TypeScript  `[ ]`
- `sdk/js`: base64url, Base45, padding, HPKE (`auth`, `auth_psk`) over WebCrypto, Ed25519
  request signatures, tokens, offer, statement. Passes `test-vectors/` under `deno test`.

### 6.2 Requester  `[ ]`
- Relay client (fetch + SSE parsing, relay time), connect, requests with one in flight, cancel
  (incl. `sessionStorage` after reload), disconnect, storage (IndexedDB with non-extractable
  keys; memory for tests), Web Locks where available, EVM checks (`@noble`), `verifyConnection`.
- Deno integration test against the Rust relay and mock keystore (with anvil).

### 6.3 Provider, wagmi connector, modal  `[ ]`
- EIP-1193 provider (§9.3 tables), `@blox/sdk/wagmi`, the modal and toast in a closed shadow
  root with an embedded QR encoder.
- Deno test with `@wagmi/core` against relay + mock keystore + anvil.

### 6.4 Demo page  `[ ]`
- A static wagmi demo page.
- **Browser checks** (IndexedDB non-extractable keys, Safari, the one-dependency Vite/Next.js
  check) `[!]`: need a browser and a phone.

## M7 — release

### 7.1 Deployment files and README  `[ ]`
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

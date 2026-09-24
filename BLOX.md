# Blox — Signer Relay: Technical Specification

> **For the coding agent:** This spec is self-contained. Implement from scratch in Rust
> (relay, adapter, shared protocol/decoder core) and a native Android app in Kotlin (keystore).
> Read every section before writing a line. The security properties in §3 and §4 are
> non-negotiable; implementation notes marked *(hint)* are suggestions, not constraints.
>
> **Release scope:**
> - **v1** is everything in §1–§11 and §13–§14: one-shot signing sessions started by a QR scan,
>   on Android only, for EVM chains only.
> - **v2** (§12) adds pairing, notifications, WalletConnect and iOS.
> - **v3** (§12.5) adds Solana, Bitcoin and other non-EVM chains.
>
> v2 and v3 are planned only. Do not implement them, but do not make choices that block them.
> §15 (relationship to FURY) is informational: it constrains design choices but adds no v1 work.

---

## 1. Overview

Blox separates **key storage** from **the wallet**. The keys live in a *keystore*: a native
Android app in v1, with iOS later. The keystore offers **signing as a service**. Wallets and
tools see the user's address and nothing else about the keys. When they need a signature,
the keystore decodes the request, shows it to the user, signs, and returns the signature.
Keys never leave the keystore.

```
 any tool / wallet ──▶ Adapter ──▶ Relay ──▶ Keystore (Android app)
 (cast, forge, viem,   (local,     (public    (decode · display · sign)
  hardhat, scripts)     localhost)  VPS, blind)
                          │
                          └──▶ upstream JSON-RPC (reads, nonce/gas/fees, broadcast)
```

| Component | Runs on | Role |
|---|---|---|
| **Keystore** | Android app (iOS later) | Holds the seed. Joins sessions by QR. Decodes, displays and signs. |
| **Relay** | Public VPS behind TLS (anyone can run one) | Stores and forwards opaque encrypted messages between mailboxes. Holds no keys and cannot read anything. |
| **Adapter** | The user's machine, bound to loopback | Presents the keystore to existing tooling as a standard Ethereum JSON-RPC signer. |

### 1.1 How it is used (v1)
1. A tool asks the adapter for a signature, for example with `cast send --unlocked …`.
2. The adapter prints a QR code in its terminal.
3. The user opens the app and scans the QR code.
4. The request appears on the phone within a second or two. The user checks it and approves with a biometric.
5. The adapter verifies the signature and broadcasts the transaction.
6. The session stays open for further requests while the app is on the session screen. That way
   a `forge script` with ten transactions needs one scan and ten approvals.
7. The session closes, and both sides forget everything about it.

There is no pairing, no background service and no notifications. The phone is in the
user's hand whenever it signs.

### 1.2 Goals
- Keys never leave the keystore. Wallets and tools only ever learn addresses and signatures.
- Existing EVM tooling works **without modification** (`cast send --unlocked`, `forge script --unlocked`, viem/ethers HTTP transports, Hardhat).
- The relay is **blind**, self-hostable and open source. A compromised relay can deny service and see traffic metadata (§3.3). It cannot read or forge messages.
- The protocol does not depend on the transport. This relay is one transport; QR/UR, USB, BLE and WalletConnect can be added later without changing the signing messages.
- The protocol is not tied to one chain. Chains and accounts use CAIP identifiers, and payload kinds are namespaced (§6).

### 1.3 Principle: signer/wallet separation
Everything in this spec follows from one rule. **The wallet is untrusted and holds only
addresses. The signer holds the keys, has its own screen, and decides.**

| | Wallet (adapter + tooling) | Signer (keystore) |
|---|---|---|
| Knows | Addresses, balances, chain state | Seed and keys only |
| Does | Builds, fills, simulates and broadcasts transactions | Decodes the raw request, shows it, gets consent, signs |
| Trusts | Nothing the signer returns without verifying it (§9.5) | Nothing the wallet *says* about a request, only its bytes (§10.4) |

- The **only** interface between the two is the signing request and response (§6). Keys
  never cross it, and neither does a "sign this hash" shortcut.
- Transports (this relay, and later QR/UR, Nostr or WalletConnect) are interchangeable
  because the interface is this narrow.
- The same rule applies to identity keys, not just funds. See §15 for FURY.

### 1.4 Not in v1
- Persistent pairing, background receiving, notifications, push (all planned for v2, §12).
- WalletConnect and dapp "Connect wallet" compatibility (planned for v2, §12).
- Auto-approval policies. Every request needs a human approval.
- An iOS app (v2). The shared Rust core (§10.1) is designed so an iOS app can reuse it.
- Non-EVM chains (v3). The format reserves space for them; no decoders ship in v1 or v2.

---

## 2. Architecture

### 2.1 Mailboxes
The relay has no sessions and no accounts. It has **mailboxes**:

- The owner generates a random 32-byte `read_secret`. The mailbox address is derived from it:
  `mailbox_id = SHA-256("blox/v1/mailbox" ‖ read_secret)`, encoded as unpadded base64url (43 chars).
- **Anyone who knows `mailbox_id` can write to it.** Writes are rate-limited and bounded (§8.4).
- **Only the holder of `read_secret` can read or acknowledge messages.** The relay checks this by hashing the secret presented in the `Authorization` header.
- The relay keeps nothing about a mailbox except its queued messages. A mailbox exists on
  the relay only while it has queued messages or a connected reader.

Every session uses **two new mailboxes**: `MA`, owned by the adapter, and `MK`, owned by the
keystore. Mailboxes are never reused, so the relay cannot link sessions by mailbox ID.

### 2.2 Session lifecycle
1. **Open:** the adapter creates a session and shows its QR code (§5.1).
2. **Join:** the keystore scans the QR code and sends `hello` to `MA` (§5.2).
3. **Sign:** the adapter sends `sign_request`s to `MK`, and the keystore answers each with a `sign_response` to `MA` (§6, §7).
4. **Close:** either side sends `close`, or a timeout fires (§5.4). Both sides wipe the session's keys and IDs.

---

## 3. Threat Model

### 3.1 Assets
- Seed and private keys. They must never leave the keystore.
- Signing requests and signatures. They must not be readable by the relay or the network.
- The link between a user and their activity. The relay should learn as little as possible (§3.3).

### 3.2 Adversaries and mitigations

| Adversary | Capability | Mitigation |
|---|---|---|
| **Relay operator / compromised relay** | Full access to relay memory and traffic | End-to-end HPKE in auth_psk mode (§4). The PSK travels only in the QR code, which the relay never sees, so the relay cannot put itself in the middle. |
| **Network attacker** | Watches or modifies traffic on either leg | TLS, plus end-to-end encryption and authentication |
| **QR observer** | Sees or photographs the session QR | Only the first join is accepted. A second join **aborts** the session and warns in the terminal (§5.3). An attacker who wins the race sees at most the first request's contents, and can never produce a signature that passes verification (§9.4). |
| **Malicious or compromised adapter host** | Sends any signing request it wants | The keystore decodes the **raw bytes itself** and shows them to the user. Content the adapter describes is never trusted. Dangerous kinds are refused (§10.5). |
| **Other local process** | Calls the adapter's RPC | Every request still needs approval on the phone. An optional bearer token is available (§9.7). |
| **Malicious web page** | CSRF / DNS rebinding against `localhost:8545` | Checks on the `Host` and `Origin` headers (§9.7) |
| **Other apps on the phone** | Overlays, screen capture, claiming URL schemes, reading backups | `FLAG_SECURE`, hidden overlays, in-app scanner only, backups disabled (§10.2, §10.6) |
| **Keystore substituting content** | Returns a signature over something other than what was asked | The adapter verifies every response (§9.4). |

### 3.3 What the relay necessarily learns (documented limitations)
- Client IP addresses, timing, and message sizes (sizes are bucketed by padding, §4.5).
- That two mailboxes are active at about the same time, which suggests a session between them.
- It can deny service: drop, delay or reorder messages. Replay is detected end to end (§4.6).

### 3.4 Trusted components (explicitly)
- **Whoever controls the app's release signing key and build pipeline controls the keystore.**
  A malicious build can steal the seed. Releases are therefore reproducible, signed with an
  offline key, and published with checksums and the certificate fingerprint (§10.1).
- The Android OS and the hardware-backed Keystore (TEE or StrongBox).

### 3.5 Out of scope
- A compromised or rooted phone OS.
- A transaction that is well formed but economically harmful, which the user approves
  after seeing it decoded correctly.

---

## 4. Cryptography

### 4.1 Primitives
- **HPKE (RFC 9180)** with suite:
  - KEM: `DHKEM(X25519, HKDF-SHA256)` (0x0020)
  - KDF: `HKDF-SHA256` (0x0001)
  - AEAD: `AES-256-GCM` (0x0002)
  - Mode: **`mode_auth_psk` (0x03) for every message**
- There is one implementation: `blox-proto` in Rust (`hpke` crate *(hint)*). The adapter uses it
  directly, and the mobile apps use it through UniFFI (§10.1). `test-vectors/` pins the wire format
  for any future independent implementation.
- Hashing: SHA-256. Randomness comes from the OS CSPRNG.

### 4.2 Session keys
Everything is **per session** and ephemeral. Nothing is written to disk on either side.
- Adapter: an X25519 keypair `(a_sk, a_pk)`, `read_secret_A` (which gives `MA`), and a 32-byte `psk`.
- Keystore: an X25519 keypair `(k_sk, k_pk)` and `read_secret_K` (which gives `MK`).
- All of it is wiped when the session ends (§5.4). These keys are for transport only and have
  nothing to do with chain keys.

### 4.3 Envelope (the bytes the relay stores and forwards)

```
offset  size  field
0       1     version = 0x01
1       1     type    = 0x01 hello | 0x02 message   (0x03–0x0F reserved for v2 pairing)
2       32    spk     sender X25519 pubkey — PRESENT ONLY when type = 0x01
..      32    enc     HPKE encapsulated key
..      ..    ct      HPKE ciphertext (includes 16-byte tag)
```

- HPKE `mode_auth_psk`:
  - `psk` = the session PSK from the QR code
  - `psk_id` = `"blox/v1/session"`
  - the sender authenticates with its session static key: `a_sk` from the adapter, `k_sk` from the keystore
- `info` = `"blox/v1/hello"` for type 0x01, `"blox/v1/msg"` for type 0x02.
- `aad` = `"blox/v1" ‖ raw 32-byte recipient mailbox_id`. This ties each envelope to its mailbox.
- Opening an envelope:
  - The adapter opens `hello` with `spk`, and after that uses the `k_pk` it has accepted.
  - The keystore opens envelopes with `a_pk`, taken from the QR code.
- Each envelope is sealed once (single-shot HPKE). No nonces are managed by hand.

### 4.4 Plaintext message

UTF-8 JSON object, then padding (§4.5):

```json
{
  "id":   "<16 random bytes, base64url>",
  "ts":   1760000000,
  "type": "hello | sign_request | sign_response | close",
  "re":   "<id of the message being answered, or omitted>",
  "body": { }
}
```

### 4.5 Padding
Append `0x80` to the plaintext, then zero bytes up to the next bucket size:
**1 KiB, 4 KiB, 16 KiB, 64 KiB, 256 KiB**. A plaintext larger than 256 KiB − 1 byte is an error.
The receiver strips trailing zeros and the `0x80` marker.

### 4.6 Replay and freshness
- The receiver rejects a message if `|now − ts| > 300 s`, or if its `id` has already been seen in this session.
- The adapter accepts **at most one** `sign_response` per request `id`. It matches responses by `re`.

### 4.7 Properties
- **Forward secrecy per session.** All transport keys are ephemeral and wiped at close. Traffic
  recorded during a session can't be decrypted later, even if either device is compromised afterwards.
- **The PSK matters only while the session is live.** Someone who has both the QR image and
  control of the relay *during* the session could put themselves in the middle. The PSK alone
  never decrypts anything, because HPKE also needs a private key.
- The keystore trusts `a_pk` because it came from the QR code. The adapter trusts the first valid
  `hello`, which requires the PSK. It also checks every signature against the requested account (§9.4).

---

## 5. Session Protocol

### 5.1 Adapter opens a session
Triggered by the first signing call that arrives while no session is active (§9.3).
1. Generate `(a_sk, a_pk)`, `read_secret_A` → `MA`, and `psk`.
2. Build the session payload (JSON, base64url-encoded):
   ```json
   { "v": 1, "relay": "https://relay.example.com", "apk": "<a_pk>",
     "ma": "<MA>", "psk": "<psk>", "label": "laptop" }
   ```
   `label` defaults to the hostname and can be set with `--label`.
3. Print the QR code in the adapter's terminal (Unicode half-blocks, `qrcode` crate). Its
   content is `blox:s?p=<payload>`. Under it, print the label, the relay host and
   `Waiting for phone… (120 s)`. The QR code is meant **only for the app's own scanner** (§10.6).
4. Open the reader stream on `MA`. If no valid `hello` arrives within 120 s, fail the
   pending calls (-32603 `"no signer joined"`) and discard the session.

### 5.2 Keystore joins
1. The user taps **Scan** and scans the QR code with the in-app scanner. The app accepts only `blox:s` payloads.
2. Generate `(k_sk, k_pk)` and `read_secret_K` (→ `MK`). Open the reader stream on `MK`.
3. Send `hello` (envelope type 0x01, `spk = k_pk`) to `MA` with body `{ "mk": "<MK>" }`.
   The keystore reveals no addresses at this point. The adapter learns the address only from
   signed responses.
4. Show "Connected to *laptop* · relay.example" and wait for requests.

### 5.3 Adapter accepts
- The **first** valid `hello` sets `k_pk` and `MK` for the session. The adapter then sends any queued requests.
- If a **second** valid `hello` arrives (it must have come from someone else with the QR code):
  - send `close { "reason": "contested" }` to both `MK`s
  - fail the pending calls
  - print `⚠ A second device joined this session. Someone may have seen your QR code. Session aborted.`
- The keystore that receives `close(contested)` shows "Session aborted: another device joined".

### 5.4 Close
A session ends on the first of these events:
- either side sends `close` (body `{ "reason": "done | contested | timeout | shutdown" }`)
- **idle timeout:** 120 s with no request in flight
- **hard cap:** 15 min after `hello`
- the keystore app leaves the foreground for more than 30 s
- the adapter shuts down (it sends `close` if it can)

On close, both sides stop reading, wipe the keys, PSK, secrets and seen-ID set, and forget the
mailbox IDs. The next signing call opens a new session with a new QR code.

---

## 6. Signing Messages

### 6.1 Identifiers
- Chains use **CAIP-2** (`eip155:1`, later `solana:<ref>`, `bip122:<ref>`).
- Accounts use **CAIP-10** (`eip155:1:0x…`).
- Payload `kind` values are namespaced: `<namespace>.<kind>`.

### 6.2 `sign_request` body
```json
{
  "chain":   "eip155:8453",
  "account": "eip155:8453:0xAbC…",
  "kind":    "evm.tx",
  "payload": { },
  "origin":  { "client": "cast", "note": "optional free text" },
  "expires_at": 1760000300
}
```
- `origin` is **informational and untrusted**. The keystore shows it with the label "claims to be from".
- The default `expires_at` is `ts + 300`. The keystore refuses requests that have expired.

### 6.3 Payload kinds (v1)

| kind | payload | signed object |
|---|---|---|
| `evm.tx` | `{ "tx": "0x<unsigned tx bytes>" }` for type 0 with EIP-155, type 1, or type 2 | the transaction |
| `evm.typed_data` | `{ "data": <EIP-712 JSON object> }` | the EIP-712 hash |
| `evm.personal_sign` | `{ "message": "0x<bytes>" }` | the EIP-191 v0x45 hash |

Reserved, and **refused in v1**:
- `evm.tx` of type 3 (blobs)
- `evm.tx` of type 4 (EIP-7702)
- `evm.eip7702_auth`
- `evm.eth_sign` (signing a raw hash)
- all non-EVM kinds

### 6.4 `sign_response` body
```json
{ "status": "approved", "signature": "0x<r‖s‖v 65 bytes>", "signed_tx": "0x…" }
{ "status": "rejected", "reason": "user | expired | unsupported | decode_failed | account_unknown" }
```
`signed_tx` is present only for `evm.tx`. For `evm.tx`, `v` is the y-parity (typed transactions)
or the EIP-155 `v` (legacy).

---

## 7. End-to-End Flow (EVM transaction)

```
cast ──eth_sendTransaction──▶ adapter
adapter: no session → open one, print QR (§5.1)
user: open app → Scan → keystore sends hello (seal→MA)
adapter: accept hello; fill nonce/gas/fees from upstream; serialize unsigned tx
adapter ──sign_request (seal→MK)──▶ relay ──SSE──▶ keystore
keystore: open, check freshness, decode tx bytes, check chain/account/kind,
          show decoded fields, Approve → BiometricPrompt → sign
keystore ──sign_response (seal→MA)──▶ relay ──SSE──▶ adapter
adapter: verify (§9.4) → eth_sendRawTransaction upstream → return tx hash to cast
… further requests reuse the session until it closes (§5.4)
```

---

## 8. Relay (Rust)

### 8.1 Crates *(hint)*
`axum` (current stable), `tokio`, `tower-http` (limit), `tower_governor` or a small token bucket
written in-house, `sha2`, `base64`, `serde`, `serde_json`, `tracing`, `tracing-subscriber`.
The only crypto is SHA-256 for mailbox IDs.

### 8.2 HTTP API

The base path is `/v1`. Binary fields in JSON are unpadded base64url.

```
POST /v1/m/{mailbox_id}
  Content-Type: application/octet-stream
  Body: envelope bytes (§4.3)
  202 { "seq": <u64> }
  400 malformed mailbox_id or envelope header · 413 too large · 429 rate limit or queue full

GET /v1/m/{mailbox_id}
  Authorization: Bearer <read_secret b64url>
  Accept: text/event-stream
  → SSE stream:
      event: msg
      data: {"seq":17,"body":"<envelope b64url>","age_ms":1234}
    First sends every queued message in seq order, then new messages as they arrive.
    Sends a `: ping` comment every 15 s.
    Only one reader per mailbox: a new reader connection closes the previous one.
  401 secret does not hash to mailbox_id

DELETE /v1/m/{mailbox_id}/{seq}
  Authorization: Bearer <read_secret b64url>
  204 (idempotent; also 204 if already gone) · 401

GET /v1/info    → { "version": "…", "limits": { …§8.4 values… } }
GET /health     → { "ok": true }
```

- Messages stay queued until they are acknowledged (`DELETE`) or reach their TTL. Delivery is
  **at least once**, and the receiver deduplicates by envelope `id` (§4.6). A reader that
  reconnects mid-session loses nothing that hasn't been acknowledged.
- The relay checks only the envelope header (`version`, `type`, minimum length). It never parses anything else.
- The relay knows nothing about sessions. v2 pairing (§12) uses the same API unchanged.

### 8.3 State *(hint)*
```rust
struct Relay { boxes: Mutex<HashMap<MailboxId, Mailbox>>, limits: Limits }
struct Mailbox {
    next_seq: u64,
    queue: VecDeque<Queued>,        // bounded
    notify: Arc<tokio::sync::Notify>,
    reader: Option<ReaderHandle>,   // cancel token for the single active reader
}
struct Queued { seq: u64, body: Bytes, enqueued: Instant }
```
The reader loop keeps a cursor (`last_seq_sent`) and wakes on `notify`. Events are never carried
in a `watch` channel. A `Mailbox` is removed when its queue is empty and it has no reader.
A background task runs every 10 s and removes messages older than the TTL.

### 8.4 Limits (defaults, configurable by env/flags, published in `/v1/info`)

| Limit | Default |
|---|---|
| Max envelope size | 272 KiB |
| Message TTL | 10 min |
| Per-mailbox queue | 32 messages / 2 MiB |
| Per-IP writes | 60 / min |
| Per-IP concurrent readers | 16 |
| Global queued bytes | 512 MiB (then 503 on writes) |

Per-IP counters are kept in memory only and expire within their window. They are never logged.
Behind a reverse proxy, the client IP comes from `X-Forwarded-For` **only if** `--trust-proxy` is set.

### 8.5 Logging and privacy
- Never log bodies, mailbox IDs, secrets, `Authorization` headers, full request paths or client IPs.
- Request tracing may record the **route template** (`/v1/m/{mailbox_id}`), the status code and
  the latency. Write this as a custom layer; don't use the default `TraceLayer` URI formatter.
- Aggregate counters (messages/s, queue depth, active readers) are fine.
- The relay stores nothing on disk.
- **Only the relay's own log target is ever enabled.** `BLOX_LOG` sets a *level* for it, not a
  filter. Dependencies stay silent at every level, because `axum::serve` logs client addresses
  at trace (found by the log-leak test).

### 8.6 CORS
Not needed, because no v1 client runs in a browser. Send no CORS headers.

### 8.7 Deployment
- A single static binary. Configuration: `BLOX_LISTEN` (default `localhost:8080`),
  limits, and `--trust-proxy`.
- Put TLS in front with Caddy (automatic certificates). Caddy has no access log unless the
  `log` directive is used. Keep it that way.
  ```
  relay.example.com {
      reverse_proxy localhost:8080 {
          flush_interval -1
      }
  }
  ```
- Ship a Dockerfile (distroless or scratch image).

---

## 9. Adapter (Rust binary `blox` + library `blox-client`)

### 9.1 CLI
```
blox rpc [--relay <url>] --upstream <rpc-url> [--listen localhost:8545] [--label <name>]
         [--account 0x…]... [--token <secret>] [--allow-origin <origin>]...
         [--timeout 300] [--join-timeout 120] [--idle-timeout 120]
```
- `--relay` defaults to the public relay `https://relay.example.com`. It can be overridden on the
  command line or in `$XDG_CONFIG_HOME/blox/config.toml`.
- The only other file is `accounts.json`, a cache of addresses seen in **verified** signatures.
- **No secrets are stored on disk.**

### 9.2 JSON-RPC handling

| Method | Behaviour |
|---|---|
| `eth_accounts`, `eth_requestAccounts` | `--account` values plus cached verified addresses. No session is opened. |
| `eth_sendTransaction` | Fill → sign via session → verify → `eth_sendRawTransaction` upstream → return hash |
| `eth_signTransaction` | Same, without broadcasting. Returns the raw signed tx. |
| `eth_signTypedData_v4` | `evm.typed_data` → verify → return signature |
| `personal_sign` | `evm.personal_sign` → verify → return signature |
| `eth_sign`, `eth_signTypedData` (v1/v3) | Refuse: error 4200 |
| anything else | Forward unchanged to `--upstream` |

The adapter caches `eth_chainId` from upstream at startup.

### 9.3 Sessions and queuing
- A signing call that arrives with no active session opens one (§5.1) and waits for the join.
  Calls that arrive in the meantime queue behind it.
- **Only one request is outstanding** at the phone at a time. The others wait in a queue in
  the adapter. Each call's `--timeout` (default 300 s) runs from when the call arrived.
- **Queue order is `(from, nonce)` ascending, then arrival order.** `forge script` sends all of
  a script's transactions **at once**, each with its nonce already set (§9.8). Sending them to
  the phone in arrival order could show nonce 3 before nonce 2.
- The terminal shows each request's progress. Summaries contain only kind, `to` and nonce:
  `→ sent: tx to 0x…ab12 (nonce 42)` · `✓ signed` · `✗ rejected by user`.
- The session closes as described in §5.4. The next signing call prints a new QR code.

### 9.4 Transaction filling (`eth_sendTransaction`)
- **Callers usually fill everything themselves.** `cast send` and `forge script` (1.8.x) send
  `nonce`, `gas`, `maxFeePerGas`, `maxPriorityFeePerGas`, `chainId` and `type`, plus both
  `input` and `data`. The adapter uses every field the caller supplies unchanged, and fills
  only what is missing.
- `from` is required.
- `input` and `data` may both be present. They must be equal, otherwise the adapter returns -32602.
- `chainId` comes from upstream. If the caller supplies one that differs, the request is rejected.
- `nonce`, if missing, defaults to `max(eth_getTransactionCount(from, "pending"), last nonce signed in this session + 1)`.
  That keeps a batch of transactions from one script in the right order.
- `gas` defaults to `eth_estimateGas`, with an optional `--gas-multiplier` (default 1.0).
- If `gasPrice` is given, build a legacy EIP-155 tx. Otherwise build type 2:
  `maxPriorityFeePerGas` defaults to `eth_maxPriorityFeePerGas`, and
  `maxFeePerGas` defaults to `2 × latest.baseFeePerGas + maxPriorityFeePerGas`.
- `accessList` is passed through when given (type 1 or 2).
- Serialize the unsigned transaction *(hint: `alloy` consensus types)*.

### 9.5 Response verification (mandatory)
- `evm.tx`: decode `signed_tx`. Its unsigned fields, re-encoded, must be **byte-identical** to
  the request's `tx`. The recovered sender must equal `account`, and the chain ID must match.
- `evm.typed_data` / `evm.personal_sign`: the address recovered from `signature` over the
  locally computed hash must equal `account`.
- If verification fails, return error `-32603 "signer response failed verification"`, print a
  warning (no payload), **close the session**, and never broadcast.

### 9.6 Errors (EIP-1193 codes)
| Case | Code |
|---|---|
| User rejected | 4001 |
| `account_unknown` (the phone doesn't hold that address) | 4100 |
| Unsupported method or kind | 4200 |
| No signer joined, contested session, timeout, `decode_failed`, verification failure | -32603 with a message |

### 9.7 Local endpoint hardening
- Bind to loopback only. Refuse a non-loopback `--listen` unless `--i-know` is also passed.
- Reject any request whose `Host` header is not `localhost:<port>`, `localhost:<port>` or `[ipv6-host]:<port>`.
  This blocks DNS rebinding.
- Reject any request that carries an `Origin` header unless it is in `--allow-origin`. This blocks
  browser CSRF; CLI tools don't send `Origin`.
- If `--token` is set, require `Authorization: Bearer <token>`.

### 9.8 Tool compatibility (measured with Foundry 1.8.3 against anvil)
- **Foundry's default RPC timeout is 45 s**, which is too short for scan, join, review and
  biometric approval. Users must raise it with **one** of:
  - `--rpc-timeout 300` on `cast` / `forge`
  - `ETH_RPC_TIMEOUT=300`
  - `eth_rpc_timeout = 300` in `foundry.toml`

  `blox rpc` prints this hint at startup. The README puts it in the quick start.
- `forge script --broadcast` sends a script's `eth_sendTransaction` calls concurrently, with
  their nonces already set. `--slow` makes it send one at a time, each after the previous one
  confirms. Both work with the ordering in §9.3.
- Foundry also calls `anvil_nodeInfo`, `anvil_metadata` and `eth_getAccountInfo`. These are
  forwarded upstream unchanged, like any other non-signing method. Errors from real chains are
  expected and harmless.
- Foundry polls `eth_getTransactionReceipt` after sending. That's normal forwarding.

### 9.9 Library API *(hint)*
```rust
pub struct Signer { /* relay url, upstream-independent */ }
impl Signer {
    pub fn new(relay: Url, label: &str) -> Self;
    /// Opens a session. `show_qr` receives the `blox:s?p=…` string; the caller renders it.
    pub async fn connect(&self, show_qr: impl FnOnce(&str)) -> Result<Session, Error>;
}
impl Session {
    pub async fn sign(&self, req: SignRequest) -> Result<SignResponse, Error>; // verified (§9.5)
    pub async fn close(self);
}
```

---

## 10. Keystore App (Android)

### 10.1 Stack and distribution
- Kotlin and Jetpack Compose. `minSdk` 28 (Android 9, which has BiometricPrompt and StrongBox). `targetSdk` is the current SDK.
- **All protocol, decoding and signing logic is in the shared Rust crates** (`blox-proto`, `blox-evm`).
  Android reaches it through `blox-ffi` (UniFFI bindings), built with `cargo-ndk` for `arm64-v8a`,
  `armeabi-v7a` and `x86_64`. Kotlin handles the UI, the Android Keystore, storage and networking
  *(hint: OkHttp + okhttp-sse)*. The adapter and the app use the same decoder and envelope code,
  and so will the future iOS app.
- **Permissions: `INTERNET` and `CAMERA`**, plus two install-time "normal" permissions:
  `USE_BIOMETRIC` (added by androidx.biometric) and `HIDE_OVERLAY_WINDOWS` (§10.6). No
  background work, no foreground service, no notifications.
- Application id `wtf.oxff.blox`.
- The app has no Google Play Services dependency (no ML Kit, no FCM), so it can ship on
  F-Droid. QR scanning uses CameraX with ZXing core, with `ALSO_INVERTED` for the adapter's
  light-on-dark QR codes *(hint)*.
- Releases are reproducible builds signed with an offline release key. Each GitHub release
  publishes SHA-256 checksums and the signing certificate fingerprint. The README explains how
  to verify an APK (`apksigner verify --print-certs`). F-Droid and Play Store come later.

### 10.2 Key storage
- BIP39 mnemonic → BIP32 in Rust (`m/44'/60'/0'/0/i` for EVM). The user can generate a new
  mnemonic or import an existing one. The user can add accounts (the next index) and give them labels.
- **The Android Keystore and StrongBox don't support secp256k1.** The seed is therefore stored
  **encrypted** (AES-256-GCM) under a wrapping key held in the Android Keystore:
  - Use `setIsStrongBoxBacked(true)` where it's available, otherwise the TEE. Show the actual
    security level (`KeyInfo.securityLevel`), and warn if the key is software-only.
  - `setUserAuthenticationRequired(true)` with
    `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL)` means
    every decryption needs its own authentication. The `Cipher` is passed to `BiometricPrompt`
    as a `CryptoObject`. **Approving a request and unlocking the seed are one and the same step.**
  - `setInvalidatedByBiometricEnrollment(false)`. Enrolling a new biometric already requires
    the device PIN, so invalidating the key would add little and would lock users out. Handle
    `KeyPermanentlyInvalidatedException` (for example, the screen lock was removed) by guiding
    the user through a restore from the mnemonic.
  - A secure lock screen is required before a seed can be created or imported.
- The encrypted seed blob lives in app-private storage. Set `android:allowBackup="false"`, and
  exclude everything in the data-extraction rules. The wrapping key is never backed up, so a
  cloud copy would be useless and would only increase exposure.
- A mnemonic backup is required at creation: the user views it (under `FLAG_SECURE`) and
  confirms 3 of its words. Viewing it later requires authentication.
- The derived **addresses** and their labels are stored unencrypted, so the app can list accounts
  and check requests without unlocking anything.
- Session transport keys live **in memory only** (§4.2) and are never stored.
- The decrypted seed exists only during a signing call. Kotlin passes the plaintext `ByteArray`
  to Rust, which derives the key, signs and then zeroizes (`zeroize` crate). Kotlin clears its
  array right after the call.

### 10.3 Session screen
- Home screen: the account list and a large **Scan** button.
- After a scan: join (§5.2), then show "Connected to *label* · relay host" and a waiting state.
  Keep the screen on (`FLAG_KEEP_SCREEN_ON`).
- Requests are shown one at a time (§10.5). After a decision the screen goes back to waiting.
  A session counter shows how many were signed and rejected.
- Deduplicate by envelope `id`, and acknowledge (`DELETE`) after processing. If the stream
  drops, reconnect with backoff and show the connection state.
- The session ends as described in §5.4: the user taps **Done** (sends `close`), the idle
  timeout or hard cap fires, the app is in the background for more than 30 s, or the adapter
  sends `close`. The app then wipes all session state and returns to the home screen.

### 10.4 Checks before display (any failure → `rejected` with reason)
- `account` is one of the keystore's accounts (otherwise `account_unknown`), and `kind` is supported.
- The request is fresh (§4.6) and has not expired.
- The payload decodes completely. For `evm.tx`, the tx's `chainId` equals `chain`.

Decoding runs in Rust (`blox-evm`). It returns a display model (fields, decoded call, danger
flags) that Kotlin only renders. Kotlin never parses payloads itself.

### 10.5 Display
**`evm.tx`**:
```
Network:      Base (eip155:8453)       ← name from a built-in list; unknown ids flagged
From:         0xAbC…full 42-char checksummed…  (account label)
To:           0x…full 42-char checksummed…  (or "Contract creation")
Value:        1.2345 ETH
Max fee:      30 gwei   Max priority: 1.5 gwei   (or Gas price for legacy)
Gas limit:    21000     Max cost: 0.00063 ETH (gas × max fee + value)
Nonce:        42
Data:         0xa9059cbb… (tap for full hex)
Decoded:      transfer(to=0x…, amount=1000000)   ← when a known selector matches
```
Built-in selector table (minimum): ERC-20 `transfer`, `approve`, `transferFrom`, `increaseAllowance`;
ERC-721/1155 `safeTransferFrom`, `setApprovalForAll`; WETH `deposit`/`withdraw`; `multicall`, shown
as "batched calls" with no inner decoding in v1.

**Danger flags.** Show a red banner, and the user must type the last 4 hex characters of the
spender or operator address before the biometric prompt appears:
- `approve` or `increaseAllowance` with an amount ≥ 2^255
- `setApprovalForAll(_, true)`
- Contract creation

**`evm.typed_data`**:
- Show the domain (`name`, `version`, `chainId`, `verifyingContract`) and the full message as a tree.
- Refuse if `domain.chainId` is present and differs from `chain`.
- **Danger** (red banner and typed confirmation): EIP-2612 `Permit`; Permit2 (`verifyingContract` =
  `0x000000000022D473030F116dDEE9F6B43aC78BA3`: `PermitSingle`, `PermitBatch`,
  `PermitTransferFrom`, `PermitBatchTransferFrom`); Seaport `OrderComponents`.

**`evm.personal_sign`**:
- Show the message as UTF-8 if it is valid printable text, otherwise as hex.
- Detect SIWE (EIP-4361) and show its domain, URI and chain prominently.
- **Warn** if the message is exactly 32 bytes (it may be a hash), or if it decodes as an RLP transaction.

**General:**
- "Claims to be from: `<origin.client>` on *label*" in muted text.
- **Approve** opens the BiometricPrompt (§10.2). **Reject** is a single tap.

### 10.6 Screen and input protection
- `FLAG_SECURE` on every screen (every screen shows a recovery phrase, a QR secret or a
  request): no screenshots, no screen recording, no thumbnails in Recents.
- `setHideOverlayWindows(true)` (API 31+) and `filterTouchesWhenObscured` on approval controls,
  to stop overlay tapjacking.
- Session payloads come **only** from the in-app scanner. The app registers no intent filter
  or deep link for `blox:`, because another app could claim the same scheme and receive the PSK.
- No WebView anywhere in the app.
- HTTPS only (`cleartextTrafficPermitted="false"`). A debug build flag may allow a plain-HTTP
  relay on the local network.

### 10.7 Signing
Rust signs with the derived secp256k1 key (RFC 6979 deterministic, low-s). It returns
`signature`, plus `signed_tx` for transactions. The result is recorded in the audit log.

### 10.8 Audit log
Kept locally (Room/SQLite): time, adapter label, relay host, kind, chain, a decoded summary,
the outcome and the tx hash. It can be exported as JSON through the share sheet. It is never uploaded.
It is the only thing kept after a session.

### 10.9 Error states
- The scanned QR code is invalid, or the adapter stopped waiting: "Session expired — trigger the signing again to get a new QR".
- `close(contested)`: "Session aborted: another device joined. Someone may have seen the QR."
- The relay is unreachable: show the relay host, with a retry button.
- Decode failure: show "Cannot decode — refused", and send `decode_failed`.
- The wrapping key has been invalidated: "Your phone's security settings changed — restore from your recovery phrase".

---

## 11. Chain Extensibility (design constraint for v3)

- A new chain needs four things:
  1. a CAIP-2 namespace
  2. a key derivation (BIP32 / SLIP-10)
  3. a signing scheme
  4. **a decoder**, which is mandatory
- Signature schemes to plan for: secp256k1 ECDSA (EVM, Bitcoin legacy/SegWit), BIP340 Schnorr (Taproot),
  ed25519 (Solana, Aptos, Sui, Near, Cardano), sr25519 (Polkadot), Stark curve (Starknet), P-256 (passkey accounts).
- The keystore must **never** sign bytes that no decoder understands. There is no generic
  "sign this hash" kind.
- Each chain needs its own adapter, which speaks that chain's RPC. Examples: `blox rpc --chain solana`
  for Solana transactions, a Bitcoin adapter for PSBTs.

---

## 12. v2 and v3 (planned, do not implement in v1)

The aim of v2 is signing **without scanning a QR code each time**, and signing when the phone
isn't in hand. It reuses the relay API (§8), the signing messages (§6), the decoders and the app
unchanged. It adds a pairing layer and a way to receive requests.

### 12.1 Persistent pairing
- Scan a QR code **once**. The adapter and keystore exchange long-term X25519 identity keys and
  long-lived mailbox IDs (`MA`, `MK`). The keystore uses a new identity for each pairing, so
  adapters can't correlate it.
- **Authentication:**
  - The pairing QR carries a PSK, as in v1.
  - A 6-digit SAS confirmed on the adapter: `HKDF-SHA256(psk, salt="blox/v2/sas", info=a_pk‖k_pk‖MA‖MK)`, taken mod 10^6.
  - Afterwards, HPKE `mode_auth` with the stored static keys. Envelope types 0x03–0x0F are reserved for this.
- **Grants for each pairing:** accounts, chains and kinds. The keystore enforces them.
- `blox pair`, `blox pairings list|remove`, and `unpair` messages.
- The trade-offs to document:
  - no forward secrecy against later compromise of a static key
  - HPKE auth mode is vulnerable to key-compromise impersonation
  - long-lived mailboxes let the relay link activity over time

### 12.2 Receiving without the app open
- **Foreground listener ("Stay reachable"):** optional, holds SSE readers while the app is in the background.
- **Push:** FCM, plus UnifiedPush for builds without Google services. The push token links a
  mailbox to the push provider, and the README must say so.
- **Notifications** name the pairing ("Signing request from laptop") and **never** show
  transaction details, because they appear on the lock screen.

### 12.3 WalletConnect as an alternative transport
- **Primary:** the keystore also acts as a WalletConnect wallet, so any dapp's "Connect wallet"
  button reaches it. The same decoders, display and biometric approval apply.
- **Fallback (to be evaluated):** carrying Blox envelopes over the WalletConnect relay when no
  Blox relay is reachable. It needs a WalletConnect project ID and is non-standard. Decide after prototyping.

### 12.4 iOS app
- SwiftUI on the same Rust core (`blox-ffi` Swift bindings).
- The seed is encrypted under a key wrapped by a Secure Enclave P-256 key, with biometric access control (`.biometryCurrentSet` or `.userPresence`).
- The same session and pairing protocol as Android, and the same display model and danger flags.

### 12.5 v3: non-EVM chains
- Solana and Bitcoin (PSBT) first. Then other chains, following §11: a CAIP-2 namespace, a derivation, a signing scheme and a mandatory decoder for each.
- An adapter for each chain (for example `blox rpc --chain solana`). The app shows accounts grouped by chain.

### 12.6 Later (unscheduled)
- Policies: per-pairing allowlists, value caps, auto-approve tiers, and a server-side keystore (TEE/HSM) for bots.
- A browser extension exposing an EIP-6963 provider that uses the adapter.
- ERC-7730 clear-signing descriptors, and EIP-7702 support with a dedicated high-friction UI.

---

## 13. Quality Gates (v1)

### 13.1 Correctness
- [ ] `blox-proto` passes `test-vectors/` (mailbox ID derivation, padding, envelope seal/open for both types, session payload encoding), both natively and through the UniFFI bindings in an Android instrumented test.
- [ ] Full lifecycle with a **mock keystore** written in Rust (test seed, auto-approve; it gets the QR string from `show_qr`): open → hello → `eth_sendTransaction` → signed → broadcast to a local `anvil` → close.
- [ ] `cast send --unlocked --from <addr> --rpc-url http://localhost:8545` works against anvil, with the mock keystore and with the Android app on a real device.
- [ ] `forge script --unlocked --sender <addr> --broadcast --rpc-timeout 300` with 10 transactions completes in **one session**. The transactions arrive concurrently and reach the phone in nonce order.
- [ ] `cast send` with every field pre-filled is signed with exactly those values, and a mismatch between `input` and `data` is rejected.
- [ ] viem `createWalletClient({ transport: http('http://localhost:8545') })` `sendTransaction` and `signTypedData` work.
- [ ] Each of these works: legacy, type 1 and type 2 transactions; EIP-712 signing; `personal_sign`.
- [ ] After the idle timeout, the next signing call prints a new QR code, and nothing from the old session is accepted.

### 13.2 Security
- [ ] A tampered envelope (any flipped byte) is rejected.
- [ ] A `hello` sealed with the wrong PSK is rejected. A message sealed by a key from another session is rejected.
- [ ] A second valid `hello` aborts the session: both keystores get `close(contested)`, pending calls fail, and nothing more is sent.
- [ ] Replaying the same envelope is rejected (by `id`), and stale `ts` is rejected.
- [ ] A mock keystore that signs a **modified** tx, or signs with a different key, is caught by the adapter (§9.5). Nothing is broadcast, and the session closes.
- [ ] The adapter rejects a bad `Host` header, an unlisted `Origin`, and a missing token when `--token` is set.
- [ ] Reading or acknowledging with the wrong `read_secret` returns 401.
- [ ] Log capture during the full lifecycle contains no mailbox IDs, secrets, envelope bytes or IPs (automated grep test).
- [ ] 7702, blob and `eth_sign` requests are refused end to end.
- [ ] Nothing session-related is on disk on either side after close. Only the adapter's `accounts.json` and the app's audit log remain.

### 13.3 Relay robustness
- [ ] A reader that disconnects and reconnects gets unacknowledged messages again, and messages that were acknowledged do not come back.
- [ ] Queue, size and rate limits are enforced with the documented status codes.
- [ ] Memory returns to baseline after 10k mailboxes are drained or expire.
- [ ] 1,000 concurrent SSE readers; enqueue-to-delivery p99 < 50 ms on localhost.

### 13.4 Compatibility
- [ ] Runs on Android 9 (`minSdk` 28) through the current release, on at least one StrongBox device and one TEE-only device.
- [ ] BiometricPrompt approval works with fingerprint, with face (class 3), and with the device-PIN fallback.
- [ ] Removing the screen lock invalidates the key, and the restore flow recovers the same addresses.
- [ ] The terminal QR code scans reliably from the app in common terminals (light and dark themes, default font sizes).
- [ ] A reproducible build produces the same APK bytes as the published release (apart from the signature).

---

## 14. Deliverables (v1)

```
blox/
├── Cargo.toml                 (workspace)
├── crates/
│   ├── blox-proto/            envelope, HPKE wrapper, padding, messages, session payload, CAIP types
│   ├── blox-evm/              tx/EIP-712/personal_sign decoding, display model, danger flags, signing
│   ├── blox-ffi/              UniFFI bindings over proto + evm for mobile
│   ├── blox-relay/            axum relay (§8)          → binary `blox-relay`
│   ├── blox-client/           Signer/Session library (§9.9)
│   ├── blox-cli/              adapter binary `blox` (§9)
│   └── blox-mock-keystore/    Rust keystore for tests (§13.1)
├── android/                   Kotlin/Compose keystore app (§10), Gradle build that runs cargo-ndk
├── test-vectors/              JSON vectors pinning the wire format
├── deploy/
│   ├── Dockerfile
│   └── Caddyfile
└── README.md
```
Integration tests live in `crates/blox-cli/tests/`. They need `anvil` on `PATH`; skip them with a clear message if it is missing.

### 14.1 Milestones
1. **M1:** `blox-proto` + test vectors, `blox-relay`, `blox-mock-keystore`, and an integration test of a full session through the relay.
2. **M2:** the `blox rpc` adapter, passing the cast, forge and viem gates against anvil with the mock keystore.
3. **M3:** the Android keystore app (key storage, scan/join, display, biometric signing), passing the same gates from a real device.
4. **M4:** hardening and deployment: limits, the log-leak test, Docker/Caddy, README.

### 14.2 README must cover
- Running a relay locally and self-hosting it (Docker + Caddy)
- Using it with `cast`, `forge script` and viem: start `blox rpc`, trigger a signature, scan. Include the Foundry RPC timeout setting (§9.8).
- Installing the app and verifying the APK (checksums, certificate fingerprint, reproducible build)
- Security model: what the relay sees (§3.3), what is trusted (§3.4), the session properties (§4.7), and the QR-observer limitation (§3.2)
- Backing up and restoring the seed, and what invalidates the Keystore wrapping key

---

## 15. Relationship to FURY

[FURY](../FURY) is a messenger with no servers of its own. One BIP-39 mnemonic gives a Nostr
identity (NIP-06) plus EVM and BTC keys. Messages are NIP-44 encrypted, carried by Nostr
relays and routed over embedded Tor (Arti). FURY calls the seed the root of "identity and
wealth", and its business model includes in-wallet DEX swaps. But it has no transaction signer
and no phone-side key protection yet: `fury-sign` is a stub. **Blox is FURY's signing layer.**
It ships as a separate product that shares FURY's foundations.

### 15.1 What is shared
| Area | FURY | Blox |
|---|---|---|
| Seed | BIP-39, NIP-06 identity at `m/44'/1237'/0'/0/0` | Same mnemonic format |
| EVM keys | `m/44'/60'/0'/0/0` | `m/44'/60'/0'/0/i`. Index 0 is the same address. |
| Architecture | Rust core, UniFFI, thin Kotlin/Swift shells (M9) | The same (`blox-ffi`, §10.1) |
| In-memory key handling | `WalletKey`: heap, `mlock`, zeroize on drop, no silent downgrade | `blox-evm` adopts the same model (or depends on `fury-core::identity`) |
| Push (Blox v2) | Contentless pings, UnifiedPush first (M5.5) | Same design; one push proxy can serve both |

**To agree before Blox v3:** FURY derives BTC at `m/44'/0'/0'/0/0` (legacy P2PKH). Blox v3
should settle BIP-84 (native SegWit) or BIP-86 (Taproot) and bring FURY in line. Otherwise the
same seed shows different Bitcoin addresses in the two apps.

### 15.2 What stays separate, and why
- **The keystore is its own minimal app, not a module inside the messenger.** A messenger
  parses untrusted content from strangers all day. Keeping it apart from the seed is the
  separation principle (§1.3) applied to the app itself.
- **The messenger should not hold the whole seed either.** If it must hold a key, it should
  hold only the Nostr identity key, never the seed that also controls funds. Longer term, the
  keystore can serve as the messenger's Nostr signer (the NIP-55 Android signer pattern) with
  new kinds `nostr.event` and `nostr.nip44_decrypt`. That needs an **auto-approve policy class**
  for low-risk operations such as decrypting incoming messages from known contacts, which
  relaxes v1's "every request is approved by a human" rule. So it is v2 at the earliest, and
  it needs its own threat model.

### 15.3 Where the two conflict, and how to resolve it
- **IP addresses.** FURY's rule is that no IP reaches a relay; the Blox v1 relay sees IPs
  (§3.3). Options, in order of effort:
  1. **Tor option for Blox** (`--tor` on the adapter, a "Route via Tor" setting in the app).
     It uses Arti as FURY does. Cost: Tor bootstrap on "open app → scan", about 10 s the first
     time and a few seconds once the directory is cached.
  2. **A Nostr transport (v2 candidate), modelled on NIP-46 `nostrconnect://`.**
     - Throwaway Nostr keys per session, ephemeral event kinds (20000–29999, which relays
       don't store), Tor-routed through `fury-core`'s `RelayClient`.
     - The QR code carries the relays, the adapter's session pubkey and a secret.
     - No Blox relay to run, which matches FURY's "no servers you don't own".
     - Constraints: **NIP-44 plaintext is capped at 64 KiB** and relays limit event size, so
       large payloads (contract deployments) need chunking. Latency depends on the relays.
  The Blox relay stays the default. The Nostr transport is an alternative, which works because
  the signing messages (§6) don't depend on the transport.
- **Cryptography.** Blox uses X25519/HPKE on its relay. A Nostr transport would use NIP-44 with
  Schnorr-signed events instead. Only the envelope layer (§4.3) changes.
- **Lesson from FURY's graph leak (FURY `SECURITY.md`).** FURY's kind-4 DMs expose long-term
  pubkeys to relays, so anyone can rebuild who talks to whom. **Blox must never use a long-term
  identity key as a transport identifier.** v1 already complies: every session key and mailbox
  is new and unlinkable. v2 pairing (§12.1) uses a new identity for each pairing for the same
  reason. A Nostr transport must use per-session keys, never the user's npub.

### 15.4 Roadmap alignment
| Blox | FURY | Note |
|---|---|---|
| v1: Android signer, EVM | M4 (storage), M9 (mobile) | Blox v1 can ship on its own. Its Android key storage (§10.2) is a concrete design for FURY M9's "Android Keystore wraps the mnemonic key". |
| v2: pairing, push, WalletConnect, iOS | M5.5 (push), M9 (iOS) | Share the push proxy and UniFFI/iOS work. Evaluate the Nostr transport (§15.3). |
| v3: Bitcoin, Solana, other chains | FURY BTC keys (M1) | Settle the BTC derivation path (§15.1). |
| Later: keystore as the Nostr signer | M5+ | Needs the policy class (§15.2). |

---

## 16. Changes from the original draft (for reviewers)
- **The phone is the signer**, not a relay to `window.ethereum`. This removes the dependency on `eth_signTransaction`, which MetaMask doesn't support, and on the wallet's in-app browser.
- **Authenticated sessions:** HPKE auth_psk, with the PSK and adapter key carried in the QR code and first-join-only with contest detection. This closes the key-substitution attack on the draft's unauthenticated exchange.
- **Mailbox capabilities** (`read_secret`) replace the draft's endpoints, which anyone could call.
- **At-least-once delivery with acknowledgements** replaces `watch` channels and "delete on delivery".
- **Several requests per session**, so a script with a batch of transactions needs one scan.
- **A local JSON-RPC adapter** makes existing EVM tooling work unchanged.
- **A native Android keystore** holds the seed, encrypted under a hardware-backed Keystore key and unlocked by biometrics. It shares its Rust core with the adapter.
- **Defined limits, privacy-safe logging and deployment guidance** for running a public relay.

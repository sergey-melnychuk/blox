# Blox — Phone Keystore: Technical Specification

> **For the coding agent:** This spec is self-contained. The repo implements most of it
> (M1–M4, the web SDK, the Rust side of M5; the Android app is written but
> not yet built): PLAN.md has the status of every step and the implementation notes, NEXT.md the
> milestones. Read every section before writing a line. The security properties in §3 and §4 are
> non-negotiable; implementation notes marked *(hint)* are suggestions, not constraints.
>
> **Release scope:**
> - **MVP (v1)** is everything in §1–§11 and §13–§14: an Android keystore that holds several
>   signers and fills, signs and broadcasts EVM transactions (or returns them signed). A site or
>   app connects to one signer once, with a QR code. After that it sends requests through the
>   relay, which keeps them 5 minutes for the phone to pick up.
> - **v2** (§12) adds receiving with the app closed (push), per-connection policies, simulation
>   on the phone, importing existing mnemonics, and iOS.
> - **v3** (§12.7) adds Solana, Bitcoin and other non-EVM chains.
>
> v2 and v3 are planned only. Do not implement them, but do not make choices that block them.
> §15 (relationship to FURY) is informational: it constrains design choices but adds no MVP work.
>
> **Terms:** the **keystore** is the Android app. A **signer** is one seed held by the keystore,
> with its account. A **requester** is the site, app or backend asking for signatures. A
> **connection** links one requester to one signer (§2.1).

---

## 1. Overview

Blox makes the phone the authority over the user's keys. The keys, the chain endpoints and the
decision all live in the *keystore*, a native Android app (iOS later). Sites and apps hold no keys
and need no wallet. They say what they want done, for example "call this contract with this
calldata and 0.01 ETH on Base". The keystore fills in the rest from its own chain endpoint, shows
the result, signs if the user approves, and then either broadcasts it and reports the hash or
returns the signed transaction.

```
 site / app ──▶ Relay ──▶ Keystore (Android app) ──▶ chain endpoint chosen on the phone
 (requester    (checks    (fill · show · sign · broadcast)
  SDK)          tokens,
                blind)
      ◀──────── account + tx hash, or the signed transaction ─┘
```

| Component | Runs on | Role |
|---|---|---|
| **Keystore** | Android app (iOS later) | Holds the signers, their connections and the chain endpoints. Connects by QR. Fills, shows, signs, broadcasts. |
| **Relay** | Public VPS behind TLS (anyone can run one) | Keeps encrypted messages in inboxes for 5 minutes. Accepts a write only from a connected party (§2.2). Holds no keys and cannot read anything. |
| **Requester SDK** | In a site's page (TypeScript, with a wagmi connector and an EIP-1193 provider), or in an app or backend (Rust) | Connects (shows the QR code once), keeps the connection, sends requests, returns results. |

### 1.1 How it is used (MVP)
**Connecting, once per site:**
1. A site calls `blox.connect()` (or any request while it has no connection). The SDK shows a
   modal with a QR code.
2. The user opens the app, taps **Scan** and scans it. The app shows "*Example* (claimed) wants
   to connect", lets the user pick the signer and how long to remember the site (1 day, 30 days
   or 90 days), and the user approves with a biometric.
3. The signer's account signs a connection statement, which proves the account to the site the
   way SIWE does. Both sides end up holding the same **connection token**, signed by both. The
   SDK resolves `connect()` with the account and stores the connection.

**Requests, any time while connected:**
1. The site calls `blox.send({ chain: 8453, to, value, data })`. The SDK posts the request to the
   signer's inbox on the relay, presenting the token. A small toast says "Approve in the Blox app".
2. The user opens the app. It reads its inboxes and shows the request.
3. The keystore fills nonce, gas and fees from its own endpoint for that chain and shows the
   complete transaction. The user approves with a biometric.
4. The keystore signs and broadcasts through its endpoint, and answers with the account and the
   hash. For `signTransaction`, it returns the signed transaction instead and does not broadcast.
5. The relay keeps a request for 5 minutes. If the app isn't opened in that time, the call fails
   with `timeout`.

There is no background service and no notification in the MVP: the user opens the app to see
requests, and the phone is in their hand whenever it signs.

### 1.2 Goals
- Keys never leave the keystore. Requesters learn the account, transaction hashes, signed
  transactions they asked for, and message signatures only.
- **The requester states intent; the keystore decides everything else.** A request carries the
  chain, `to`, value and calldata (or a message). Nonce, gas, fees and the endpoint the
  transaction is sent to are chosen on the phone; the signer was chosen when connecting.
- **Every host the phone contacts is chosen on the phone.** Chain endpoints are configured in the
  app and never come from requests. A relay named in a QR code needs the user's consent the first
  time (§10.3).
- **Only connected requesters can reach the phone.** The relay accepts a write to an inbox only
  with a token its owner signed (§2.2), and the keystore drops anything not from a live connection.
- **Integration is one dependency and one import.** A site on wagmi adds the Blox connector to
  its config and changes nothing else; other stacks wrap the SDK's EIP-1193 provider or call the
  SDK directly (§9). Both translate wallet calls into intent. No WalletConnect, no injected
  `window.ethereum`, no network-side JSON-RPC signer.
- The relay is **blind**, self-hostable and open source. A compromised relay can deny service and
  see traffic metadata (§3.3). It cannot read or forge messages.
- The protocol does not depend on the transport, and is not tied to one chain: chains and
  accounts use CAIP identifiers, and payload kinds are namespaced (§6).

### 1.3 Principle: the keystore is the authority
**The requester is untrusted and holds nothing but its connection. The keystore holds the keys
and its own view of the chain, has its own screen, and decides.**

| | Requester (site, app, SDK) | Keystore (phone) |
|---|---|---|
| Knows | What it wants done; its connection token; the account and results it gets back | Seeds and keys; its connections; the chain endpoints the user configured |
| Does | States the intent (chain, to, value, data, or a message) | Fills, decodes, shows, gets consent, signs, broadcasts |
| Trusts | Only what it can check: message signatures and signed transactions are verified, hashes are looked up on chain (§9.5) | Nothing the requester *says*: it builds the transaction itself and shows what it built (§10.4) |

- The **only** interface between the two is the request and response (§6). Keys never cross it,
  and neither does a "sign this hash" shortcut.
- The keystore learns chain state only from endpoints the user configured on the phone.
- A connection exists only once the user approves it on the phone. The user can end any
  connection from the phone; a requester can end only its own.
- Transports (this relay, later Nostr) are interchangeable because the interface is this narrow.
- The same rule applies to identity keys, not just funds. See §15 for FURY.

### 1.4 Not in the MVP
- Receiving requests while the app is closed: push, a background listener, notifications (v2, §12.1).
- Per-connection policies (allowed chains, kinds, value caps) and auto-approval (v2, §12.2).
  Every request needs a human approval.
- Simulation on the phone (v2, §12.3). The MVP only checks that `eth_estimateGas` succeeds (§10.4).
- Importing an existing mnemonic in release builds, and more than one account per signer (v2, §12.5).
- An iOS app (v2). The shared Rust core (§10.1) is designed so an iOS app can reuse it.
- Non-EVM chains (v3).
- **Not planned at all:** a network-side JSON-RPC signer for tools such as `cast` and `forge`
  (an earlier draft had one; see §16), injecting `window.ethereum`, and WalletConnect. The SDK's
  in-page EIP-1193 provider and wagmi connector (§9.3) are part of the SDK, not an adapter in
  that sense: they run in the site's page, need no server, and pass on intent only.

---

## 2. Architecture

### 2.1 Connections
A **connection** links one requester to one signer. It is created once with a QR code (§5),
lives until it expires (the user picks 1 day, 30 days or 90 days) or either side ends it, and
carries any number of requests.

| Key | Held by | Scope | Use |
|---|---|---|---|
| `S` (Ed25519) and `s` (X25519) | Requester | One connection | `S` names the requester's inbox and signs its relay requests and the token; `s` is its HPKE key |
| `K` (Ed25519) and `k` (X25519) | Keystore | One signer, shared by all of that signer's connections | The same roles on the keystore side |
| The signer's account key (secp256k1) | Keystore | The signer | Signs the connection statement once at connect (§5.2), and the user's transactions and messages |

- `S`, `s`, `K` and `k` are **transport keys**. They are generated at random and have nothing to
  do with the signer's seed.
- The **connection token** (§4.3) names `S`, `s`, `K`, `k`, the relay and the expiry, and is
  signed with both `S` and `K`. Both sides keep it. It is what the relay checks.
- The **connection statement** (§5.2) is signed by the account and names the token. Only the
  requester receives it, end to end encrypted. It proves the account, as SIWE does. The relay
  never sees the account.

### 2.2 Inboxes
The relay has no sessions and no user accounts. It has **inboxes**, each named by an Ed25519
public key: the inbox ID is the key itself, as unpadded base64url (43 characters).
- **Reading** inbox `P` and acknowledging its messages needs a request signed by `P` (§4.4).
- **Writing** to inbox `P` needs one of:
  - a connection token that `P` has signed and has not revoked, with the request signed by the
    token's other party. This is every write after connecting.
  - a **ticket** that `P` registered: a one-time permission for the first message of a new
    connection (§5).
- There are **no anonymous writes**.
- **Connections are isolated.** Each connection has its own requester inbox `S`, so a response
  lands only with the site that asked. Each signer has one keystore inbox `K` per relay, which all
  its connections write to; the relay keeps at most 4 messages from any one writer in it, so one
  connection can't crowd out the others (§8.4), and the phone groups requests by connection (§10.6).
- An inbox can have several readers at once, for example one per browser tab (§8.2).
- Messages stay until they are acknowledged or are 5 minutes old.
- **One request in flight per connection** is the normal case: the SDK queues further calls
  (§9.2). Users will still manage to have several (a closed tab, a reload, a retry), so the
  phone handles that too (§6.5, §10.6).

### 2.3 Lifecycle
1. **Connect** (once, with a QR code, §5): the requester registers a ticket and shows the QR code;
   the keystore sends `bind` with the ticket; the requester answers `bound` with the countersigned
   token.
2. **Request** (any time while connected): the requester sends `sign_request`s to `K`; the
   keystore picks them up when the app is open and answers each with a `sign_response` to `S`
   (§6, §7).
3. **End:** either side sends `unbind` and revokes the token at the relay, or the token expires
   (§5.5).

---

## 3. Threat Model

### 3.1 Assets
- Seeds and private keys. They must never leave the keystore.
- The decision: only transactions the user saw, exactly as the phone built them, get signed and sent.
- The right to send requests to a signer. Only requesters the user connected may.
- Requests and responses. They must not be readable by the relay or the network.
- The link between a user and their activity. The relay should learn as little as possible (§3.3).

### 3.2 Adversaries and mitigations

| Adversary | Capability | Mitigation |
|---|---|---|
| **Relay operator / compromised relay** | Full access to relay memory and traffic | End-to-end HPKE (§4.5): `auth_psk` for `bind`, with the PSK only in the QR code; `auth` with the token's keys afterwards. The relay cannot read, forge or put itself in the middle. It never sees the account. |
| **Network attacker** | Watches or modifies traffic on any leg | TLS, plus end-to-end encryption and authentication |
| **Anyone who knows an inbox ID** | Tries to send requests to a signer, or spam a requester | No anonymous writes: the relay needs a token the inbox owner signed (§2.2). The keystore also drops every message not from a live connection, so a relay that skips the check gains nothing. |
| **A connected requester flooding the signer** | Fills the signer's inbox to push out other sites' requests | The relay keeps at most 4 messages per writer in an inbox (§8.4). The phone groups requests by connection (§10.6), and the user can disconnect the site. |
| **QR observer** | Sees or photographs the connect QR | The ticket works once (§5.1). An attacker who wins the race connects their own phone: the user's phone is told the code was already used, and the site shows the attacker's account, not the user's. Nothing of the user's is signed. |
| **Malicious requester** (a site, an app, or script injected into one) | Sends any request it wants over a connection, under any name | The keystore builds the transaction itself from the intent and its own chain data, and shows every field (§10.4, §10.5). The requester cannot set nonce, gas, fees or the endpoint. Dangerous kinds are refused, and risky calls get danger flags (§10.5). The name is shown as a claim. |
| **Stolen connection** (the site's stored keys and token, via XSS or a leaked backend) | Sends requests as that connection until it ends | Every request still needs approval on the phone. In browsers the keys are non-extractable (§9.6), so injected script can use the connection only while it runs in the page and cannot carry it away. The app lists connections with their last request, and disconnecting revokes the token (§10.6). Connections expire after at most 90 days. |
| **Site impersonating another site** | Shows a QR code with someone else's name | The name cannot be verified (§3.3). The phone shows it as "claims to be", next to the decoded call and the destination address. |
| **Requester steering the phone's network access** | Names a relay in the QR code | An unknown relay needs the user's consent before the phone connects (§10.3). Chain endpoints never come from requests. |
| **Chain endpoint the user configured** | Lies about nonce, fees, gas estimate or balance; delays or drops broadcasts; sees the phone's IP and transactions | It cannot change what is signed: the phone shows the full transaction. The endpoint's host is on the review screen, and the user chose it (§10.3). |
| **Other apps on the phone** | Overlays, screen capture, claiming URL schemes, reading backups | `FLAG_SECURE`, hidden overlays, in-app scanner only, backups disabled (§10.2, §10.7) |

### 3.3 What others necessarily learn (documented limitations)
- **The relay:** client IP addresses, timing, and message sizes (sizes are bucketed by padding,
  §4.7). It sees the inbox keys, which are stable for a signer, and which connection keys write
  to them; for browser requesters it also sees the `Origin` header. Over time it can therefore
  tell that one (unnamed) signer uses certain sites. It never learns the account. It can deny
  service: drop, delay or reorder messages. Replay is detected end to end (§4.8).
- **Connected sites** learn the signer's account and its keystore inbox key `K`. Two sites
  connected to the same signer can link the user, as they could by the address alone. Sites
  connected to *different* signers see different keys, so separate signers stay unlinkable.
- **The chain endpoint:** the phone's IP address, the account and every transaction it broadcasts
  or queries, as with any wallet's RPC provider. Users who care run their own node or choose a
  privacy-preserving endpoint.
- **The requester's name is unverified.** A phishing page can show a QR code with any name. It
  can also show a genuine site's QR code that it obtained by loading that site itself (QR
  proxying), and so hold a connection the user believes belongs to the real site. The user's
  protection is the decoded request on the phone, the connection list, and short expiries for
  sites they don't know.

### 3.4 Trusted components (explicitly)
- **Whoever controls the app's release signing key and build pipeline controls the keystore.**
  A malicious build can steal the seeds. Releases are therefore reproducible, signed with an
  offline key, and published with checksums and the certificate fingerprint (§10.1).
- The Android OS and the hardware-backed Keystore (TEE or StrongBox).
- The chain endpoints the user configures, for chain state and delivery only (§3.2).

### 3.5 Out of scope
- A compromised or rooted phone OS.
- A request that does what it says but is economically harmful, which the user approves
  after seeing it decoded correctly.

---

## 4. Cryptography

### 4.1 Primitives
- **HPKE (RFC 9180)** with suite:
  - KEM: `DHKEM(X25519, HKDF-SHA256)` (0x0020)
  - KDF: `HKDF-SHA256` (0x0001)
  - AEAD: `AES-256-GCM` (0x0002)
  - Mode: **`mode_auth_psk` (0x03) for `bind`**, **`mode_auth` (0x02) for every later message**
- **Ed25519 (RFC 8032)** for connection tokens, tickets' owners and relay request signatures.
- There are two implementations:
  - `blox-proto` in Rust (`hpke`, `ed25519-dalek` crates *(hint)*), used by the relay, the Rust
    requester and, through UniFFI, the mobile apps (§10.1).
  - The TypeScript SDK (§9.1): WebCrypto in browsers, so that keys can be non-extractable and
    the SDK needs no wasm; `@noble/curves` with raw keys outside browsers (§9.6).

  `test-vectors/` pins the wire format; both must pass it, and CI runs the TypeScript SDK
  against the Rust relay and mock keystore.
- Hashing: SHA-256. Randomness comes from the OS CSPRNG (in browsers, `crypto.getRandomValues`).

### 4.2 Keys
- Requester, per connection: `S`/`s` (§2.1), created when connecting and stored with the
  connection (§9.6). Deleted when the connection ends.
- Requester, per connect attempt: a 16-byte `ticket` and a 32-byte `psk`, wiped once `bound` is
  sent or the attempt times out.
- Keystore, per signer: `K`/`k`, created with the signer (§10.2) and deleted with it.
- These are transport keys only; none is derived from a seed.

### 4.3 Connection token
```
body     = version(1) = 0x01
         ‖ S(32) ‖ s(32)                    requester: Ed25519, X25519
         ‖ K(32) ‖ k(32)                    keystore:  Ed25519, X25519
         ‖ issued_at(8, BE unix s) ‖ expires_at(8, BE unix s)
         ‖ relay_len(1) ‖ relay             the relay's normalized URL (below)
token    = body ‖ sig_K(64) ‖ sig_S(64)    sig_S absent until the requester countersigns (§5.3)
signed   = "blox/v1/token" ‖ body           both parties sign the same bytes
token_id = SHA-256("blox/v1/token" ‖ body)
```
- Sent to the relay as the header `Blox-Token: <unpadded base64url>`.
- `expires_at − issued_at` is at most 90 days.
- **Normalized relay URL:** the QR code's relay field resolved as in §5.1, then lowercase
  scheme and host, no default port (443 for `https`, 80 for `http`), no trailing slash, no query
  or fragment. For the default relay: `https://relay.example.com`. The two parties check it; the
  relay does not.
- The token is not secret: possessing it lets no one write, because the relay also needs a
  request signature from a party (§4.4).

### 4.4 Relay request signatures
```
Authorization: Blox <ts>.<sig, unpadded base64url>
sig = Ed25519( "blox/v1/req" ‖ 0x00 ‖ method ‖ 0x00 ‖ path ‖ 0x00 ‖ ts(8, BE) ‖ SHA-256(body) )
```
- `method` is the uppercase ASCII method. `path` is the API path starting at `/v1/`, for
  example `/v1/inbox/<id>`, without any base path in the relay URL (a proxy serving the relay
  under a path strips it); the API uses no query strings. `ts` is decimal in the header and
  8 bytes big-endian in the signed bytes.
- The relay rejects `|now − ts| > 60 s` with `401 clock` (§8.2). Clients sign with relay time (§4.8).
- A request replayed within the window has no effect beyond a duplicate message, which the
  receiver drops by `id` (§4.8); acknowledgements and revocations are idempotent.
- The signing key is implied by the route: the inbox owner for reads, acknowledgements and
  ticket registration; the token's other party for writes; either party for revocation (§8.2).

### 4.5 Envelope (the bytes the relay stores and forwards)

```
offset  size  field
0       1     version = 0x01
1       1     type    = 0x01 bind | 0x02 message
2       32    spk     sender's X25519 key (k for bind and keystore messages, s for requester messages)
34      32    enc     HPKE encapsulated key
66      ..    ct      HPKE ciphertext (includes 16-byte tag)
```

- `bind` (keystore → requester, §5.2): HPKE `mode_auth_psk` with the `psk` from the QR code,
  `psk_id = "blox/v1/bind"`, `info = "blox/v1/bind"`, sender key `k`, recipient key `s` from the QR code.
- `message`: HPKE `mode_auth`, `info = "blox/v1/msg"`, sender and recipient keys from the token.
- `aad` = `"blox/v1" ‖ the recipient's 32-byte inbox key`. This ties each envelope to its inbox.
- The receiver finds the connection by `spk` and opens with that connection's key. An unknown
  `spk` is dropped (and acknowledged).
- Each envelope is sealed once (single-shot HPKE). No nonces are managed by hand.

### 4.6 Plaintext message

UTF-8 JSON object, then padding (§4.7):

```json
{
  "id":   "<16 random bytes, base64url>",
  "ts":   1760000000,
  "type": "bind | bound | sign_request | sign_response | cancel | unbind",
  "re":   "<id of the message being answered, or omitted>",
  "body": { }
}
```

### 4.7 Padding
Append `0x80` to the plaintext, then zero bytes up to the next bucket size:
**1 KiB, 4 KiB, 16 KiB, 64 KiB, 256 KiB**. A plaintext larger than 256 KiB − 1 byte is an error.
The receiver strips trailing zeros and the `0x80` marker.

### 4.8 Replay and freshness
- The receiver rejects a message if `|now − ts| > 300 s`, or if its `id` was seen on this
  connection in the last 10 minutes.
- The requester accepts **at most one** `sign_response` per request `id`. It matches responses by `re`.
- **Relay time.** Users' computers often have clocks that are minutes off. Clients therefore use
  the relay's clock for every time they send (message `ts`, request signatures, token times):
  they read `now` from `GET /v1/info` once, keep the offset, and read it again after a `401 clock`
  before retrying once. The keystore does the same, so both ends of a connection agree.

### 4.9 Properties
- **The relay cannot read or forge.** It never holds `psk`, `s`'s or `k`'s secret, or the account key.
- **`bind` cannot be forged without the QR code:** it needs the PSK. The account signature in it
  covers `K` and the ticket, so it can't be moved to another connection.
- **Static keys, no forward secrecy against their later theft.** Messages use static–static HPKE
  auth mode. Whoever later obtains `k`'s secret (stored on the phone without user
  authentication, §10.2) can decrypt recorded requests to that signer and impersonate the
  keystore's *transport*: it can read requests and send fake responses, but cannot sign
  anything, and the SDK verifies every signature and signed transaction (§9.5). The same holds
  for a requester's `s`.
- **Key-compromise impersonation:** HPKE auth mode lets the holder of a recipient's secret key
  forge messages *to* that recipient. Accepted for the reason above.

---

## 5. Connect Protocol

### 5.1 Requester prepares
Triggered by `connect()`, or by a request made while the requester has no connection (§9.2).
1. Generate `S`/`s`, a 16-byte `ticket` (or use the server's nonce, §9.2) and a 32-byte `psk`.
2. Register the ticket: `POST /v1/inbox/{S}/tickets` with `SHA-256(ticket)` and an expiry
   120 s ahead, signed by `S` (§8.2).
3. Open the reader stream on inbox `S`.
4. Build the QR content:
   ```text
   uri     = "BLOX:" base45(payload)                       (Base45: RFC 9285)
   payload = version(1) ‖ S(32) ‖ s(32) ‖ ticket(16) ‖ psk(32)
           ‖ relay_len(1) ‖ relay ‖ label_len(1) ‖ label
   relay   = ""                → the default relay https://relay.example.com
             "host[:port][/p]" → https://host[:port][/p]
             "http://…"        → as written (debug / LAN only; release apps refuse it)
   label   = UTF-8, at most 32 bytes (truncated on a character boundary)
   ```
   `label` is the requester's `name` from the SDK configuration. It is a claim (§3.3). Base45
   uses only QR's alphanumeric characters, so the whole URI is encoded in alphanumeric mode:
   about 190 characters and a version-8 QR code (49×49 modules) for a typical label, at most version 10.
5. Show the QR code: the SDK's modal in a browser (§9.4), or the integrator's own UI through
   `onQr`, with the name and `Waiting for phone… (120 s)`. The QR code is meant **only for the
   app's own scanner** (§10.7). If no valid `bind` arrives within 120 s, fail with `no_signer`.

### 5.2 Keystore accepts
1. The user taps **Scan** and scans the QR code with the in-app scanner. The app accepts only `BLOX:` payloads.
2. Check the relay against the keystore's relay list, and ask the user about an unknown one (§10.3).
3. The connect screen: "*label* (claimed) wants to connect", the relay host, the signer (a
   picker, last used preselected), and **Remember for** 1 day / 30 days (default) / 90 days.
   **Approve** opens the biometric prompt for the chosen signer; **Reject** ends here, and
   nothing is sent.
4. On approval:
   - build the token body (§4.3) with the signer's `K`/`k`, `issued_at = now` and the chosen
     expiry, and sign it with `K`
   - have the account sign this **connection statement** (EIP-191 `personal_sign`), one field
     per line, times in UTC:
     ```
     Blox connection
     Site: Example (claimed)
     Site key: <S>
     Keystore key: <K>
     Account: 0xAbC…(checksummed)
     Nonce: <ticket>
     Relay: relay.example.com
     Issued: 2026-11-10T12:00:00Z
     Expires: 2026-12-10T12:00:00Z
     ```
     Exact format: lines joined with `\n` and no trailing newline; keys and the ticket in
     unpadded base64url; times as `YYYY-MM-DDTHH:MM:SSZ`, equal to the token's `issued_at` and
     `expires_at`; `Relay:` is the token's normalized relay URL; `Site:` is the QR label followed
     by ` (claimed)`. It deliberately is not an EIP-4361 message, so it can't be replayed to a
     SIWE login elsewhere.
5. Send `bind` (envelope type 0x01, §4.5) to inbox `S` with `Blox-Ticket: <ticket>` and body:
   ```json
   { "token": "<token signed by K>", "account": "0xAbC…", "statement": "<text>", "signature": "0x<65 bytes>" }
   ```
   A `409` from the relay means the ticket was used: show "This QR code was already used.
   Someone may have seen it." and keep nothing. A `401` means it expired: "This QR code has
   expired — start again on the site".
6. Read inbox `K` and wait up to 120 s for `bound` from this connection's `s`.

### 5.3 Requester confirms
On the **first** valid `bind`:
1. Check that the token names its own `S` and `s` and the relay it used; that the envelope's
   `spk` is the token's `k`; that `sig_K` verifies; that `issued_at` is within 300 s of now and
   the lifetime at most 90 days; that the statement is exactly the text §5.2 gives for these
   values, the ticket and the account; and that the signature recovers to `account`.
2. Countersign the token with `S` and send `bound` (`{ "token": "<token signed by both>" }`) to
   inbox `K`.
3. Store `{ S, s, token, account }` (§9.6) and resolve `connect()` with the account.

If a **second** valid `bind` arrives for the same ticket (an honest relay never delivers one),
revoke both tokens, fail with `contested`, and show `A second device answered this QR code.
Someone may have seen it. Connection cancelled.`

### 5.4 Keystore stores
On `bound`, the keystore checks that the token is the one it sent with a valid `sig_S`, and
stores the connection: the token, the label, the relay, the signer, and the time. The app shows
"Connected to *label*".
- Without `bound` within 120 s, the keystore revokes the token at the relay (§8.2) and discards
  the connection. Otherwise the requester would keep a half-signed token that the relay accepts
  for writes to `K` until it expires.
- A new connection whose `S` or `s` equals an existing connection's replaces it, so `spk`
  always identifies exactly one connection (§4.5).

### 5.5 Ending a connection
- **Disconnect from either side:** send `unbind` (empty body) to the other party, and
  `POST /v1/revoke` the token (§8.2). Both forget the connection. The keystore disconnects from
  the connection list (§10.6), and when a signer or a relay is removed (§10.2, §10.3); the
  requester through `disconnect()`.
- **Expiry:** at `expires_at`, both sides forget it, and the relay stops accepting the token.
- A requester that loses its stored connection (cleared storage) simply connects again. The old
  connection stays in the app's list until it expires or the user removes it.
- Revocation on the relay is in memory only and saves bandwidth. Enforcement is end to end: a
  side that ended a connection drops every message from it.

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
  "kind":    "evm.send",
  "payload": { },
  "origin":  { "name": "Example", "url": "https://example.com" },
  "expires_at": 1760000300
}
```
- The signer is the connection's. A request cannot name another account.
- `origin` is **informational and untrusted**. The keystore shows it with the label "claims to
  be from". The browser SDK fills `url` from `location.origin`.
- `expires_at` defaults to `ts + 300`, the relay's TTL; a later value is treated as `ts + 300`.
  The keystore refuses requests that have expired.
- `chain` is `eip155:<decimal chain ID>`. The SDKs take the chain ID as a number.

### 6.3 Payload kinds (MVP)

| kind | payload | what the keystore does |
|---|---|---|
| `evm.send` | `{ "to": "0x…" or null, "value": "0x…", "data": "0x…" }` | Fills, shows, signs and **broadcasts** a transaction (§10.4). `to: null` deploys a contract. `value` and `data` default to zero and empty. |
| `evm.sign_tx` | the same as `evm.send` | Fills, shows and signs, then **returns** the signed transaction without broadcasting it. |
| `evm.personal_sign` | `{ "message": "0x<bytes>" }` | Signs the EIP-191 (0x45) hash and returns the signature |
| `evm.typed_data` | `{ "data": <EIP-712 JSON object> }` | Signs the EIP-712 hash and returns the signature |

- An `evm.send` or `evm.sign_tx` payload with **any other field** (`nonce`, `gas`, `gasPrice`,
  `maxFeePerGas`, `type`, …) is refused with `decode_failed`, so no requester can believe it set them.
- Refused with `unsupported`: `evm.eip7702_auth`, `evm.eth_sign` (signing a raw hash), and all
  non-EVM kinds. The keystore only builds type 2 and legacy EIP-155 transactions (§10.4); it never
  builds blob or EIP-7702 transactions.

### 6.4 `sign_response` body
```json
{ "status": "sent",      "account": "eip155:8453:0x…", "tx_hash": "0x…" }
{ "status": "signed_tx", "account": "eip155:8453:0x…", "tx_hash": "0x…", "raw": "0x<signed transaction>" }
{ "status": "signed",    "account": "eip155:8453:0x…", "signature": "0x<r‖s‖v 65 bytes>" }
{ "status": "failed",    "account": "eip155:8453:0x…", "tx_hash": "0x…", "error": "<endpoint's message>" }
{ "status": "rejected",  "reason": "user | expired | unsupported | decode_failed | no_endpoint | would_fail" }
```
- `sent`: the endpoint accepted the transaction (`eth_sendRawTransaction` returned its hash). It
  is not yet mined.
- `signed_tx`: the answer to `evm.sign_tx`. `raw` is the EIP-2718 encoding. The keystore has not
  broadcast it and does not reserve its nonce: a later request may be filled with the same nonce
  if this one hasn't reached the endpoint, and then only one of the two can be mined.
- `signed`: the answer to `evm.personal_sign` and `evm.typed_data`. `v` is 27 or 28.
- `failed`: the transaction was signed but the endpoint refused it or did not answer. `tx_hash`
  lets the requester check whether it went through anyway. The keystore does not retry in the MVP.
- `no_endpoint`: the keystore has no endpoint for that chain (§10.3).
- `would_fail`: `eth_estimateGas` failed, so the transaction would fail on chain (§10.4).

### 6.5 `cancel`
The requester withdraws a request it no longer waits for: `type: "cancel"`, `re` = the request's
`id`, empty body. It travels like a request (§4.5) and counts toward the per-writer limit.
- Pending on the phone, not yet approved: removed without an answer (§10.6).
- On the review screen: "The site withdrew this request", and **Approve** is disabled.
- Already approved, signed or sent: no effect. Cancelling can't recall a transaction.

---

## 7. End-to-End Flow (EVM transaction)

```
site ──blox.send({chain, to, value, data})──▶ SDK
SDK: no connection → connect first (§5), showing the QR modal once
SDK ──sign_request evm.send (seal→k) POST /v1/inbox/K + token + sig_S──▶ relay (kept ≤ 5 min)
SDK: toast "Approve in the Blox app"
user: opens the app → keystore reads inbox K (signed by K) → open, check the connection and freshness
keystore: fill nonce/fees/gas from its own endpoint (§10.4),
          show the complete transaction, Approve → BiometricPrompt → sign
keystore ──eth_sendRawTransaction──▶ its endpoint for that chain
keystore ──sign_response sent + tx_hash (seal→s) POST /v1/inbox/S + token + sig_K──▶ relay ──SSE──▶ SDK
SDK: resolve the call with { account, txHash }
```
For `evm.sign_tx` the keystore skips the broadcast and answers `signed_tx` with `raw`.

---

## 8. Relay (Rust)

### 8.1 Crates *(hint)*
`axum` (current stable), `tokio`, `tower-http` (limit, CORS), `tower_governor` or a small token
bucket written in-house, `serde`, `serde_json`, `tracing`, `tracing-subscriber`, and `blox-proto`
for token parsing and signature checks (Ed25519, SHA-256). The relay never opens envelopes.

### 8.2 HTTP API

The base path is `/v1`. Binary fields in JSON are unpadded base64url. `{id}` is an inbox key (§2.2).

```
POST /v1/inbox/{id}
  Content-Type: application/octet-stream
  Body: envelope bytes (§4.5)
  Either  Blox-Token: <token>  +  Authorization signed by the token's other party
  or      Blox-Ticket: <ticket>   (envelope type must be bind)
  202 { "seq": <u64> }
  400 malformed id, token or envelope header · 401 not authorized · 403 token revoked
  409 ticket already used · 413 too large · 429 rate limit or queue full

GET /v1/inbox/{id}
  Authorization signed by {id}
  Accept: text/event-stream
  → SSE stream:
      event: msg
      data: {"seq":17,"body":"<envelope b64url>","age_ms":1234}
    First sends every queued message in seq order, then new messages as they arrive.
    Sends a `: ping` comment every 15 s.
    Up to 8 readers per inbox at once, each getting every message (a 9th gets 429).
    Acknowledging removes a message for all readers, so a reader acknowledges only the
    messages it handled (§9.7).
  401

DELETE /v1/inbox/{id}/{seq}
  Authorization signed by {id}
  204 (idempotent; also 204 if already gone) · 401

POST /v1/inbox/{id}/tickets
  Authorization signed by {id}
  Body: { "ticket_hash": "<SHA-256(ticket)>", "expires_at": <unix s> }
  204 · 400 expiry more than 180 s ahead · 401 · 429 too many live tickets

POST /v1/revoke
  Blox-Token: <token>  +  Authorization signed by either party named in the token
  (the token's own signatures aren't required: a requester revokes half-signed tokens in §5.3,
  and anyone can make both keys of a fake token anyway, so they would add nothing)
  204 (idempotent) · 401 · 503 revocation table full
  Counts as a write for the per-IP and per-writer-key rate limits.

GET /v1/info    → { "version": "…", "now": <unix s>, "limits": { …§8.4 values… } }
GET /health     → { "ok": true }
```

- `Blox-Ticket` is the 16-byte ticket as unpadded base64url.
- Every error response has the body `{ "error": "<code>" }`, so clients can act on it:
  `malformed` (400), `unauthorized`, `clock`, `expired` (401), `revoked` (403), `ticket_used`
  (409), `too_large` (413), `rate_limited`, `queue_full`, `writer_full`, `readers_full`,
  `tickets_full` (429), `busy` (503).

A token write is accepted only if all of these hold:
- the token parses, `{id}` is one of its two parties, and it carries a valid signature by `{id}`
  (the requester's half-signed token is enough for `bound`, §5.3)
- the `Authorization` signature verifies under the token's other party
- `issued_at ≤ now + 60 s`, `expires_at > now`, and the lifetime is at most 90 days
- `token_id` is not revoked

A ticket write is accepted only if `SHA-256(ticket)` is registered for `{id}`, has not expired,
and has not been used; it is then marked used.

- Messages stay queued until they are acknowledged (`DELETE`) or reach their TTL. Delivery is
  **at least once**, and the receiver deduplicates by message `id` (§4.8). A reader that
  reconnects loses nothing that hasn't been acknowledged.
- The relay checks tokens, tickets and the envelope header (`version`, `type`, minimum length).
  It never opens an envelope.

### 8.3 State *(hint)*
```rust
struct Relay {
    inboxes: Mutex<HashMap<InboxKey, Inbox>>,
    tickets: Mutex<HashMap<[u8; 32], Ticket>>,     // ticket hash → { inbox, expires, used }
    revoked: Mutex<HashMap<TokenId, u64>>,         // token_id → expires_at
    limits:  Limits,
}
struct Inbox {
    next_seq: u64,
    queue: VecDeque<Queued>,        // bounded
    notify: Arc<tokio::sync::Notify>,
    readers: usize,                 // for the limit; each reader loop keeps its own cursor
}
struct Queued { seq: u64, body: Bytes, enqueued: Instant, writer: Writer }  // token party or ticket, for the per-writer limit
```
The reader loop keeps a cursor (`last_seq_sent`) and wakes on `notify`. Events are never carried
in a `watch` channel. An `Inbox` is removed when its queue is empty and it has no reader.
A background task runs every 10 s and removes expired messages, tickets and revocations.

### 8.4 Limits (defaults, configurable by env/flags, published in `/v1/info`)

| Limit | Default |
|---|---|
| Max envelope size | 272 KiB |
| Message TTL | **5 min** |
| Per-inbox queue | 32 messages / 2 MiB, at most 4 messages from one writer |
| Readers per inbox | 8 |
| Clock skew for request signatures and `issued_at` | 60 s |
| Max token lifetime | 90 days |
| Ticket lifetime / live tickets per inbox | 180 s / 4 |
| Revocation entries | 100,000 (then 503 on revoke) |
| Per-writer-key writes | 60 / min |
| Per-IP writes | 60 / min |
| Per-IP concurrent readers | 16 |
| Global queued bytes | 512 MiB (then 503 on writes) |

Per-IP counters are kept in memory only and expire within their window. They are never logged.
Behind a reverse proxy, the client IP comes from `X-Forwarded-For` **only if** `--trust-proxy` is set.

### 8.5 Logging and privacy
- Never log bodies, inbox keys, tokens, tickets, `Authorization` or `Blox-*` headers, full
  request paths or client IPs.
- Request tracing may record the **route template** (`/v1/inbox/{id}`), the status code and
  the latency. Write this as a custom layer; don't use the default `TraceLayer` URI formatter.
- Aggregate counters (messages/s, queue depth, active readers, live connections seen) are fine.
- The relay stores nothing on disk. A restart loses queued messages, tickets and revocations
  (§5.5 explains why that is safe).
- **Only the relay's own log target is ever enabled.** `BLOX_LOG` sets a *level* for it, not a
  filter. Dependencies stay silent at every level, because `axum::serve` logs client addresses
  at trace (found by the log-leak test).

### 8.6 CORS
Required, because the browser SDK talks to the relay directly.
- `Access-Control-Allow-Origin: *`, `Access-Control-Allow-Methods: GET, POST, DELETE`,
  `Access-Control-Allow-Headers: Authorization, Content-Type, Blox-Token, Blox-Ticket`,
  `Access-Control-Max-Age: 86400`.
- No credentials. A wildcard origin is safe because every call is authorized by a signature or
  a ticket, never by a cookie.

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

## 9. Requester SDK

### 9.1 Packages
- **`@blox/sdk`** (TypeScript, browsers and Node 22+): the requester, the modal, an EIP-1193
  provider (§9.3) and, as the subpath export `@blox/sdk/wagmi`, a wagmi connector.
  - **The integration budget is one dependency and one import.** No wasm, no CSS import, no
    bundler plugin, no build step on the site's side.
  - Crypto: in browsers, Ed25519 and X25519 through WebCrypto (non-extractable keys); outside
    browsers, `@noble/curves` with raw keys (Deno 1.46's WebCrypto X25519 is broken, and a
    backend keeps its keys as bytes anyway, §9.6). HKDF on `@noble/hashes` HMAC-SHA256;
    AES-256-GCM and SHA-256 from WebCrypto, which every runtime has. Keccak and secp256k1
    recovery come from
    `@noble/hashes` and `@noble/curves`, which sites using viem already ship *(hint)*.
  - wagmi is an optional peer dependency, needed only for `@blox/sdk/wagmi`.
  - Size target: 25 KB min+gzip on top of `@noble`.
- **`blox-client`** (Rust): the requester for apps, backends, CLIs and tests.

### 9.2 Integration and API
**A site on wagmi** (Uniswap, and anything built on a wagmi wallet picker) adds the connector to
its config:
```ts
import { blox } from "@blox/sdk/wagmi";

export const config = createConfig({
  chains: [mainnet, base],
  connectors: [injected(), blox({ name: "Uniswap" })],
  transports: { [mainnet.id]: http(), [base.id]: http() },
});
```
Nothing else changes. `sendTransaction`, `signMessage`, `signTypedData`, `switchChain` and
reconnecting on page load all go through the connector (§9.3).

**Other stacks** (ethers, web3-react, plain viem) wrap the provider:
```ts
import { createProvider } from "@blox/sdk";
const provider = new BrowserProvider(createProvider({ name: "Example", transports: { 1: "https://…" } }));
```

**Sites that want the intent API directly:**
```ts
import { Blox } from "@blox/sdk";
const blox = new Blox({ name: "Example" });       // relay defaults to https://relay.example.com; loads a stored connection
const { account } = await blox.connect();          // QR once; returns at once if already connected
const { txHash }        = await blox.send({ chain: 8453, to: "0x…", value: 10n ** 16n, data: "0x…" });
const { raw, txHash }   = await blox.signTransaction({ chain: 8453, to: "0x…", data: "0x…" });
const { signature }     = await blox.personalSign({ chain: 8453, message: "hello" });
const { signature }     = await blox.signTypedData({ chain: 8453, data: typedData });
await blox.disconnect();                           // unbind + revoke, forget the connection
```
- Every result also carries `account` (checksummed).
- A request made while not connected connects first. `connect()` returns the stored connection
  if there is one; to use another signer, `disconnect()` and connect again.
- `message` is a string (sent as its UTF-8 bytes) or bytes. `chain` is the chain ID (§6.2).
- `connect({ nonce })` takes a 16-byte nonce from the site's server and uses it as the ticket, so
  the server can check the connection statement: when `connect()` makes a new connection it
  also returns `statement` and `signature`, and `verifyConnection({ account, statement,
  signature }, { nonce })` (TypeScript and Rust) checks the format, the nonce, the times and the
  signature. This is the login. See §3.3 on what it does not prove.
- **One request in flight per connection.** Further calls wait in the SDK, across tabs too (a
  Web Lock per connection, §9.6), and the request toast says "Waiting for the previous request".
  Each call's timeout is its request's expiry (default 300 s), counted from when it is sent.
- **Abandoned requests are cancelled** (§6.5): when the user cancels, when the call times out,
  on `disconnect()`, and on `pagehide` (best effort, `fetch` with `keepalive`). The IDs of
  requests in flight are kept in `sessionStorage`, so after a reload the SDK cancels the ones the
  previous page left behind.
- Errors are `BloxError` with a `code`: `rejected` (with `reason`), `failed` (with `error` and
  `txHash`), `no_signer` (nobody answered the QR code within 120 s), `contested`, `timeout`
  (the app wasn't opened in time), `disconnected` (the phone sent `unbind`, the connection
  expired, or the relay answered `401 expired` or `403 revoked`; the stored connection is
  cleared and the next call connects again), `cancelled` (the user closed the modal or toast),
  `bad_response` (a response failed the checks of §9.5), `relay_error` (the relay couldn't be
  reached after retries or refused the request, with its error code), `unsupported_browser` (§9.6).
- The Rust `blox_client::Requester` has the same calls and errors. It takes a store for the
  connection (a file by default).

### 9.3 The EIP-1193 provider and the wagmi connector
The provider turns wallet calls into intent and passes on nothing else, so the phone still fills
everything (§1.3). The connector is a thin wrapper around the provider.

**Provider methods:**

| Method | Behavior |
|---|---|
| `eth_requestAccounts` | `connect()` (the QR modal if not connected); returns `[account]` |
| `eth_accounts` | `[account]`, or `[]` if not connected |
| `eth_chainId` | the provider's current chain |
| `wallet_switchEthereumChain` | Sets the current chain at once, with no round trip to the phone (every request carries its chain), and emits `chainChanged`. A chain the site didn't configure (the wagmi config's chains, or the keys of `transports` for `createProvider`; any chain if none are given) → 4902. |
| `wallet_addEthereumChain` | Accepted with no effect: the phone's endpoints are configured on the phone (§10.3). |
| `eth_sendTransaction` | `send` with `to`, `value`, `data` (or `input`) and the chain (`chainId` if given, else the current chain). `from` must be the account (else 4100). `nonce`, `gas`, `gasPrice`, `maxFeePerGas`, `maxPriorityFeePerGas`, `type` and `accessList` are dropped. `authorizationList`, blob fields and any other field → 4200. Returns the hash. |
| `eth_signTransaction` | `signTransaction`, with the same mapping; returns `raw` |
| `personal_sign` | `personalSign`; the address parameter must be the account |
| `eth_signTypedData_v4` | `signTypedData`; the address parameter must be the account |
| Read-only `eth_*` (`eth_call`, `eth_estimateGas`, `eth_getBalance`, `eth_blockNumber`, `eth_getTransactionReceipt`, `eth_getLogs`, …) | Forwarded to the site's own RPC for that chain: the wagmi config's transport, or `transports` given to `createProvider` (else 4200). The phone is never asked. |
| Everything else (`eth_sign`, `wallet_sendCalls`, `wallet_getCapabilities`, …) | 4200 |

Events: `connect` and `accountsChanged` on connecting, `chainChanged` on a switch, and
`accountsChanged([])` and `disconnect` when the connection ends or expires.

**Errors:**

| Blox | EIP-1193 |
|---|---|
| `rejected` (`user`), `cancelled` | 4001 (user rejected) |
| `rejected` (`no_endpoint`) | 4901, "No endpoint for *chain* in the Blox app" |
| `rejected` (`unsupported`, `decode_failed`) | 4200 |
| `disconnected` | 4100, then `accountsChanged([])` and `disconnect` |
| Everything else (`rejected` with `would_fail` or `expired`, `failed`, `timeout`, `no_signer`, `contested`, `bad_response`, `relay_error`, `unsupported_browser`) | -32603 with the code and reason in `message` and `data`; `failed` carries `data.txHash` |

**The wagmi connector** (`id: "blox"`, `name: "Blox"`, an inline icon):
- `connect` → `eth_requestAccounts`. The current chain starts as the chain wagmi asks for, or the config's first chain.
- `getProvider` → the provider above, with reads routed to the config's transports (falling back to each chain's default RPC URL).
- `isAuthorized` → true while a stored, unexpired connection exists, so wagmi reconnects on page load without the phone.
- `switchChain` → `wallet_switchEthereumChain`.
- `disconnect` → `blox.disconnect()`.
- The current chain is kept with the connection (§9.6), so it survives a reload.

Limits of the translation, which the README states:
- A site's own `gas` is replaced by the phone's estimate × 1.2 (§10.4). A site that set a higher
  limit on purpose gets the phone's value.
- EIP-5792 batching (`wallet_sendCalls`) is unsupported; wagmi and most dapps fall back to single
  transactions.

### 9.4 The modal
- Rendered in a closed shadow root with inline styles: no CSS import, and the site's styles
  don't reach it.
- Connecting: the QR code, the name, "Scan with the Blox app", a countdown and a Cancel button.
  After `bind`: "Connected as 0xAbC…".
- Requests: a small toast that doesn't block the page, "Approve in the Blox app · 4:59", then
  "Sent · 0x…", "Signed" or "Rejected". Sites with their own "confirm in wallet" UI can turn it
  off (`requestUi: "none"`).
- `onQr(uri)` and `onStatus(status)` replace the modal for integrators with their own UI.
- The QR string holds the ticket and the PSK. The SDK never logs it and never sends it anywhere
  except into the QR code.

### 9.5 What the SDK checks
- `bind`: everything in §5.3.
- `signed`: the address recovered from `signature` over the locally computed hash must equal the
  connection's account. The SDK computes EIP-191 and EIP-712 hashes itself.
- `signed_tx`: `raw` decodes to a transaction whose recovered sender is the account, whose chain
  ID, `to`, `value` and `data` match the request, and whose hash is `tx_hash`.
- Every response must report the connection's account.
- `sent`: the SDK returns `tx_hash` as is. A requester that needs more looks the transaction up
  on its own endpoint; its `from`, `to`, `value` and `input` match the request.
- A response that fails a check fails the call with `bad_response`. It means a keystore bug or a
  forged response from someone holding the keystore's transport key (§4.9).

### 9.6 Storage: non-extractable keys in IndexedDB
**Why not `localStorage`:** it holds strings only, so a key would have to be exported as bytes
to be stored there, and any script on the page could read those bytes and send them away. With
the connection's keys and its token, an attacker could then send requests from anywhere for up
to 90 days.

**How it works:**
1. **Generate, non-extractable.** When connecting, the SDK creates both connection keys with
   `extractable = false`:
   ```ts
   const S = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
   const s = await crypto.subtle.generateKey({ name: "X25519" },  false, ["deriveBits"]);
   ```
   For a key pair, the flag applies to the private key; the public key is always exportable. The
   SDK exports the two public keys (`exportKey("raw", …)`) for the QR code and the token.
2. **Store the `CryptoKey` objects themselves.** IndexedDB stores values by structured clone,
   and `CryptoKey` is serializable: the browser writes the key material into the origin's
   IndexedDB files itself, and keeps the `extractable` flag and the allowed usages with it. The
   SDK's record, in database `blox`, store `connections`, keyed by relay URL:
   ```ts
   { S: CryptoKey /* Ed25519 private, ["sign"] */, s: CryptoKey /* X25519 private, ["deriveBits"] */,
     S_pub: Uint8Array, s_pub: Uint8Array, token: Uint8Array, account: "0x…",
     chain: 8453 /* current chain, §9.3 */, expires_at: 1762790400 }
   ```
3. **Load and use.** A later page load reads the record back and gets working `CryptoKey`s
   again, still non-extractable and limited to their usages:
   - relay request signatures (§4.4): `crypto.subtle.sign("Ed25519", S, bytes)`
   - the HPKE DH steps for `s` (§4.5): `crypto.subtle.deriveBits({ name: "X25519", public: peer }, s, 256)`
4. **What the browser refuses.** `exportKey` on these keys throws `InvalidAccessError`, and so
   does `wrapKey` (it needs an extractable key). Script on the page can *use* the keys through
   the calls above but can never obtain their bytes. Other origins can't open the database at all.

**What it protects, and what it doesn't:**
- **Protected:** script injected into the site (XSS, a compromised third-party script) can't
  copy the connection out. It can only use the connection while it runs in the page, and every
  request it sends still needs approval on the phone (§3.2).
- **Not protected:**
  - **Script running in the page** can make requests as the site, and sees the values each call
    derives, such as DH outputs and HPKE secrets. One of them is the connection's static DH
    value `DH(s, k)`. Alone, that value lets it neither post to the relay (which needs `S`) nor
    open responses (each also needs a fresh DH with `s`).
  - **Malware with access to the browser profile.** "Non-extractable" is a boundary of the
    JavaScript API, not hardware protection: the key material is in the profile's IndexedDB
    files.
  - **Browser extensions** that can inject script into the site's pages can use the connection
    as page script can.

**Lifetime:**
- Clearing the site's data deletes the connection, and the user connects again. The SDK calls
  `navigator.storage.persist()` (best effort) so storage pressure doesn't evict it.
- **Safari** deletes script-written storage, IndexedDB included, for sites the user hasn't
  interacted with in 7 days of browser use. Such a user scans again.
- In private windows, the connection lasts until the window closes.

**Tabs:** all tabs of the site share the connection, and each reads inbox `S` itself (§9.7).
Two Web Locks keep them out of each other's way:
- `blox:<relay>:connect` while connecting, so only one QR code is shown; a second tab waits and
  then uses the stored connection.
- `blox:<relay>:<S>` around each request, so the connection has one request in flight (§9.2).

What locks can't prevent (a tab closed mid-request, a reload, a second browser, which is a
second connection) is handled by cancellation (§6.5) and on the phone (§10.6).

**No fallback:** if the browser lacks WebCrypto Ed25519 or X25519, the SDK fails with
`unsupported_browser`. It never falls back to raw key bytes.

**Outside browsers (Node, Deno, servers) and Rust:** keys are raw bytes (`@noble/curves` in
TypeScript), kept in a store the caller provides (`ConnectionStore`; a `MemoryStore` is built
in) or, in Rust, in a file with owner-only permissions (`FileStore`). A backend's connection is
as safe as the backend. Without Web Locks, one process serializes its requests in memory; two
processes sharing one stored connection are not supported.

### 9.7 Transport
- Reading uses `fetch` with a streaming response body and parses SSE frames itself.
  `EventSource` cannot send an `Authorization` header.
- Each tab reads inbox `S` while it has a request in flight or is connecting, and reconnects
  with backoff if the stream drops. It handles and acknowledges only the responses to its own
  requests (by `re`) and ignores the rest: the tab that asked handles them, or they expire after
  5 minutes. Whichever tab reads an `unbind` clears the stored connection and acknowledges it.
- Times come from the relay's clock (§4.8).

---

## 10. Keystore App (Android)

### 10.1 Stack and distribution
- Kotlin and Jetpack Compose. `minSdk` 28 (Android 9, which has BiometricPrompt and StrongBox). `targetSdk` is the current SDK.
- **All protocol, decoding, filling and signing logic is in the shared Rust crates** (`blox-proto`,
  `blox-evm`). Android reaches it through `blox-ffi` (UniFFI bindings), built with `cargo-ndk` for
  `arm64-v8a`, `armeabi-v7a` and `x86_64`. Kotlin handles the UI, the Android Keystore, storage and
  HTTP *(hint: OkHttp)*. Chain endpoint calls go through a `ChainRpc` interface that Rust defines
  and Kotlin implements *(hint: a UniFFI foreign trait)*, so the fill and broadcast logic stays in
  Rust, where the iOS app can reuse it.
- **Permissions: `INTERNET` and `CAMERA`**, plus two install-time "normal" permissions:
  `USE_BIOMETRIC` (added by androidx.biometric) and `HIDE_OVERLAY_WINDOWS` (§10.7). No
  background work, no foreground service, no notifications.
- Application id `wtf.oxff.blox`.
- The app has no Google Play Services dependency (no ML Kit, no FCM), so it can ship on
  F-Droid. QR scanning uses CameraX with ZXing core, with `ALSO_INVERTED` for light-on-dark
  QR codes *(hint)*.
- Releases are reproducible builds signed with an offline release key. Each GitHub release
  publishes SHA-256 checksums and the signing certificate fingerprint. The README explains how
  to verify an APK (`apksigner verify --print-certs`). F-Droid and Play Store come later.

### 10.2 Signers and key storage
- A **signer** is one BIP-39 seed and the EVM account derived from it at `m/44'/60'/0'/0/0`,
  with a label the user chooses, plus its transport keys `K`/`k` (§2.1). The keystore holds any
  number of signers.
- **Adding** a signer generates a new mnemonic in Rust. The user must back it up: view it (under
  `FLAG_SECURE`) and confirm 3 of its words. Only then is it stored.
- **Importing** an existing mnemonic (an "external signer") is v2 for release builds (§12.5).
  Debug builds keep import, for test phrases such as anvil's.
- **Removing** a signer shows a warning that its funds are lost without the recovery phrase, then
  requires authentication and typing the last 4 hex characters of its address. Removal first
  ends the signer's connections (§5.5, best effort if offline), then deletes the signer's
  wrapping key, which makes the encrypted seed unreadable even if the file survives on flash
  storage, and then the seed file, the transport keys, the address and the label.
- **Viewing** a signer's recovery phrase later requires authentication.
- **The Android Keystore and StrongBox don't support secp256k1.** Each seed is therefore stored
  **encrypted** (AES-256-GCM) under **its own** wrapping key held in the Android Keystore:
  - Use `setIsStrongBoxBacked(true)` where it's available, otherwise the TEE. Show the actual
    security level of each signer (`KeyInfo.securityLevel`), and warn if a key is software-only.
  - `setUserAuthenticationRequired(true)` with
    `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL)` means
    every decryption needs its own authentication. The `Cipher` is passed to `BiometricPrompt`
    as a `CryptoObject`. **Approving a request (or a connection) and unlocking the seed are one
    and the same step.**
  - `setInvalidatedByBiometricEnrollment(false)`. Enrolling a new biometric already requires
    the device PIN, so invalidating the key would add little and would lock users out. Handle
    `KeyPermanentlyInvalidatedException` (for example, the screen lock was removed, which
    invalidates every signer at once) by guiding the user through restoring each affected
    signer from its mnemonic. Restoring is allowed in release builds: it is import limited to
    signers the keystore already lists, and the restored address must match.
  - A secure lock screen is required before a signer can be added.
- **Transport keys** (`K`/`k`) are generated in Rust and stored encrypted under one Android
  Keystore key, `blox.transport.wrap.v1`, that does **not** require user authentication, so the
  app can read its inboxes when opened without a prompt. They can't sign anything (§4.9).
- The encrypted blobs live in app-private storage. Set `android:allowBackup="false"`, and
  exclude everything in the data-extraction rules. The wrapping keys are never backed up, so a
  cloud copy would be useless and would only increase exposure.
- The signers' **addresses** and labels, and the connections (tokens, labels, relays, times),
  are stored unencrypted, so the app can list them and check incoming messages without unlocking
  anything.
- The decrypted seed exists only during a signing call. Kotlin passes the plaintext `ByteArray`
  to Rust, which derives the key, signs and then zeroizes (`zeroize` crate). Kotlin clears its
  array right after the call.

### 10.3 Endpoints and relays
- **Chain endpoints:** a settings screen lists `(chain id, name, URL)`. Adding one calls
  `eth_chainId` on it and refuses a mismatch. The MVP ships with none; the user adds the chains
  they use.
- **Relays:** the default relay is on the list. When a QR code names a relay that is not on the
  list, the app shows its host and asks "Use this relay?". Allowing adds it to the list; declining
  ends the connect before any connection to the relay is made. Removing a relay ends the
  connections that use it.
- Release builds accept HTTPS only. Debug builds also accept plain HTTP, for a relay or an anvil
  node on the local network.
- Endpoints and relays are never taken from a request. They are not secret, and are stored
  unencrypted in app-private storage.

### 10.4 Checks and filling (before display)
Any failed check sends `rejected` with the reason, without asking the user, unless noted.
1. The message comes from a live connection (by `spk`, §4.5), or is a `bound` for a pending one
   (§5.4); anything else is dropped without an answer. The request is fresh (§4.8), has not expired and has not been cancelled (§6.5),
   its `kind` is supported, and the payload decodes completely with no extra fields.
2. The signer is the connection's.
3. `evm.typed_data`: refuse if `domain.chainId` is present and differs from `chain`.
4. `evm.send` and `evm.sign_tx`: the chain needs an endpoint (`no_endpoint`). The keystore then
   fills the transaction, using that endpoint only:
   - `nonce` = max(`eth_getTransactionCount(account, "pending")`, one more than the last nonce the
     app **sent** for that chain and account since it started). Transactions returned by
     `evm.sign_tx` don't count (§6.4).
   - fees: if the latest block has `baseFeePerGas`, a type 2 transaction with
     `maxPriorityFeePerGas` = `eth_maxPriorityFeePerGas` (or `eth_gasPrice − baseFee`, at least 0,
     if the endpoint lacks that method) and `maxFeePerGas` = `2 × baseFee + maxPriorityFeePerGas`.
     Otherwise a legacy EIP-155 transaction with `gasPrice` = `eth_gasPrice`.
   - `gas` = `eth_estimateGas({from, to, value, data})` × 1.2, rounded up. If estimation fails,
     the review screen shows "This transaction would fail" with the endpoint's error and offers
     only **Reject**, which sends `would_fail`.
   - a balance check: if `eth_getBalance(account, "pending")` is below `gas × fee + value`, show a warning.
   - If the endpoint can't be reached, show the error with **Retry** and **Reject**.
5. The filled transaction is fixed from this point. What is shown is exactly what gets signed (and sent).

Decoding and filling run in Rust (`blox-evm`). They return a display model (fields, decoded
call, danger flags, warnings) that Kotlin only renders. Kotlin never parses payloads itself.

### 10.5 Display
**`evm.send`** and **`evm.sign_tx`**:
```
From:         Example (claimed) · example.com (claimed)
Network:      Base (eip155:8453)       ← name from a built-in list; unknown ids flagged
Signer:       Savings · 0xAbC…full 42-char checksummed…
To:           0x…full 42-char checksummed…  (or "Contract creation")
Value:        0.01 ETH
Data:         0xa9059cbb… (tap for full hex)
Decoded:      transfer(to=0x…, amount=1000000)   ← when a known selector matches
Max fee:      30 gwei   Max priority: 1.5 gwei   (or Gas price for legacy)
Gas limit:    51000     Max cost: 0.00153 ETH (gas × max fee + value)
Nonce:        42
Sent via:     base.example.com          ← the endpoint's host
              (evm.sign_tx: "Returned to the site, not sent. Filled from base.example.com")
```
Built-in selector table (minimum): ERC-20 `transfer`, `approve`, `transferFrom`, `increaseAllowance`;
ERC-721/1155 `safeTransferFrom`, `setApprovalForAll`; WETH `deposit`/`withdraw`; `multicall`, shown
as "batched calls" with no inner decoding in the MVP.

**Danger flags.** Show a red banner, and the user must type the last 4 hex characters of the
spender or operator address before the biometric prompt appears:
- `approve` or `increaseAllowance` with an amount ≥ 2^255
- `setApprovalForAll(_, true)`
- Contract creation (a plain extra confirmation; there is no address to type)

**`evm.typed_data`**:
- Show the domain (`name`, `version`, `chainId`, `verifyingContract`) and the full message as a tree.
- **Danger** (red banner and typed confirmation): EIP-2612 `Permit`; Permit2 (`verifyingContract` =
  `0x000000000022D473030F116dDEE9F6B43aC78BA3`: `PermitSingle`, `PermitBatch`,
  `PermitTransferFrom`, `PermitBatchTransferFrom`); Seaport `OrderComponents`.

**`evm.personal_sign`**:
- Show the message as UTF-8 if it is valid printable text, otherwise as hex.
- Detect SIWE (EIP-4361) and show its domain, URI and chain prominently.
- **Warn** if the message is exactly 32 bytes (it may be a hash), or if it decodes as an RLP transaction.

**General:**
- The connection's label and the request's `origin`, as claims, in muted text.
- **Approve** opens the BiometricPrompt for the signer's key (§10.2). **Reject** is a single tap.
- After a transaction is sent: "Sent · 0x…" with a copy action. On `failed`, the endpoint's error.

### 10.6 Screens
- **Home:** pending requests **grouped by connection** ("Uniswap · Savings · 2 requests"), the
  signer list (label, address, security level, number of connections), **Add signer**, settings,
  and a large **Scan** button. A status line shows the relays being read ("Checking 2 relays…",
  "Up to date", or the error).
- **Reading inboxes:** while the app is in the foreground, it holds one reader stream per
  (relay, signer) that has connections there, reconnecting with backoff. After 30 s in the
  background it closes them.
- **Delivery on the keystore side:**
  - It deduplicates by message `id`.
  - A request is acknowledged (`DELETE`) only once it is answered, cancelled or expired. Until
    then, a restart of the app gets it again from the relay.
  - Each answer is stored with its request `id` for 10 minutes, before it is sent. A request
    delivered again (after a crash or a lost acknowledgement) gets the stored answer again and is
    not shown again, so the same request is never signed twice.
  - Every other message is acknowledged once processed.
- **Requests** are reviewed one connection at a time, oldest first, one request at a time
  (§10.5). Responses go back to that connection only.
  - A request that expires while waiting is removed and answered `expired`.
  - A cancelled request is removed. If it is on screen, the screen says "The site withdrew this
    request" and **Approve** is disabled.
  - When a connection has more than one pending request, its review screen says "*label* sent
    *n* requests. If you retried on the site, the older one may be a duplicate." The phone
    never drops or merges them on its own: two identical requests can both be intended.
- **Connect** (after a scan): §5.2.
- **Signer:** its address, its connections (label as claimed, relay host, connected on, expires
  on, last request), **Disconnect** on each (§5.5), view phrase, remove signer.
- `unbind` from a requester removes the connection and shows "*label* disconnected".

### 10.7 Screen and input protection
- `FLAG_SECURE` on every screen (screens show recovery phrases, QR secrets or requests): no
  screenshots, no screen recording, no thumbnails in Recents.
- `setHideOverlayWindows(true)` (API 31+) and `filterTouchesWhenObscured` on approval controls,
  to stop overlay tapjacking.
- QR payloads come **only** from the in-app scanner. The app registers no intent filter
  or deep link for `blox:`, because another app could claim the same scheme and receive the ticket and PSK.
- No WebView anywhere in the app.
- HTTPS only (`cleartextTrafficPermitted="false"`), except in debug builds (§10.3).

### 10.8 Signing and sending
Rust signs with the signer's derived secp256k1 key (RFC 6979 deterministic, low-s). For `evm.send`
it records the signed transaction and its hash with the request `id` (§10.6), then calls
`eth_sendRawTransaction` once on the chain's endpoint and answers `sent` or `failed` (§6.4). If
the app dies in between, the redelivered request is answered `failed` with that hash, and the
requester can look it up. For `evm.sign_tx` it answers `signed_tx` without contacting the endpoint again.
Message signatures are returned as `signed`. The result is recorded in the audit log.

### 10.9 Audit log
Kept locally *(hint: Room/SQLite; the app currently writes JSON lines)*: time, the connection's label (as claimed) and relay host, the
request's claimed origin, signer, kind, chain, a decoded summary, the endpoint host, the outcome
and the tx hash. Connects and disconnects are logged too. It can be exported as JSON through
the share sheet. It is never uploaded. Removing a signer keeps its audit entries.

### 10.10 Error states
- The scanned QR code is invalid, its ticket expired (`401`), or the requester stopped waiting: "This QR code has expired — start again on the site".
- The ticket was already used (`409`): "This QR code was already used. Someone may have seen it."
- No `bound` within 120 s: "The site didn't confirm the connection".
- A relay is unreachable: its host on the status line, with a retry button.
- No endpoint for the chain: "No endpoint for Base (eip155:8453). Add one in Settings." The request is answered `no_endpoint`.
- The endpoint is unreachable during filling: its host and error, with **Retry** and **Reject**.
- Decode failure: show "Cannot decode — refused", and send `decode_failed`.
- A wrapping key has been invalidated: "Your phone's security settings changed — restore this signer from its recovery phrase".

---

## 11. Chain Extensibility (design constraint for v3)

- A new chain needs five things:
  1. a CAIP-2 namespace
  2. a key derivation (BIP32 / SLIP-10), applied to each signer's seed
  3. a signing scheme
  4. **a decoder**, which is mandatory
  5. **fill and broadcast logic** for that chain's RPC, in the keystore
- Signature schemes to plan for: secp256k1 ECDSA (EVM, Bitcoin legacy/SegWit), BIP340 Schnorr (Taproot),
  ed25519 (Solana, Aptos, Sui, Near, Cardano), sr25519 (Polkadot), Stark curve (Starknet), P-256 (passkey accounts).
- The keystore must **never** sign bytes that no decoder understands. There is no generic
  "sign this hash" kind.
- Requests carry intent wherever the chain allows it. The keystore supplies chain-state fields
  (nonces, recent blockhashes, fees, UTXO selection) from its own endpoint.
- The connection statement (§5.2) gains one `Account:` line per namespace the signer has.

---

## 12. v2 and v3 (planned, do not implement in the MVP)

### 12.1 Receiving with the app closed
- **Foreground listener ("Stay reachable"):** optional, holds the reader streams while the app is in the background.
- **Push:** FCM, plus UnifiedPush for builds without Google services. The relay sends a
  contentless ping for an inbox. The push token links an inbox to the push provider, and the
  README must say so.
- **Notifications** name the connection ("Signing request from Example") and **never** show
  transaction details, because they appear on the lock screen.

### 12.2 Per-connection policies
- Limits chosen on the phone per connection: allowed chains and kinds, value caps.
- Auto-approval tiers for low-risk requests (see §15.2), with their own threat model.

### 12.3 Simulation on the phone
- Run the filled transaction through an EVM (yevm) against the chain endpoint before display:
  balance changes, token transfers and approvals, reverts.
- Results appear next to the decoded fields, after them. Approval never waits for simulation,
  and "not simulated" is shown if it doesn't finish.
- Licensing must be settled first: yevm is PolyForm Noncommercial, which conflicts with the
  app's MIT license and with F-Droid (§10.1).
- Simulation covers transactions only. Typed data still relies on danger flags.

### 12.4 iOS app
- SwiftUI on the same Rust core (`blox-ffi` Swift bindings).
- Each seed is encrypted under a key wrapped by a Secure Enclave P-256 key, with biometric access control (`.biometryCurrentSet` or `.userPresence`).
- The same connect protocol and messages as Android, and the same display model and danger flags.

### 12.5 Signers
- **Import an existing mnemonic** ("external signer") in release builds, with a warning that a
  phrase that was ever typed or stored elsewhere is only as safe as wherever it was.
- **More accounts per signer** (derive index 1, 2, …), each with its own label and connections.

### 12.6 Later (unscheduled)
- A server-side keystore (TEE/HSM) for bots.
- A "Route via Tor" setting in the app (§15.3).
- ERC-7730 clear-signing descriptors, and EIP-7702 support with a dedicated high-friction UI.

### 12.7 v3: non-EVM chains
- Solana and Bitcoin (PSBT) first. Then other chains, following §11: a CAIP-2 namespace, a
  derivation, a signing scheme, a mandatory decoder, and fill and broadcast logic for each.
- The app shows each signer's accounts grouped by chain.

---

## 13. Quality Gates (MVP)

Ticked gates are verified by tests (PLAN.md says how); a note marks
gates that are only partly covered. The unticked ones are mostly device and browser checks.

### 13.1 Correctness
- [ ] `blox-proto` passes `test-vectors/` (token encoding, `token_id` and signatures, relay URL normalization, request signatures, padding, envelope seal/open for `bind` and `message` with fixed ephemeral keys, QR payload encoding, the connection statement text) natively and through the UniFFI bindings in an Android instrumented test. The TypeScript SDK passes the same vectors, plus EIP-191 and EIP-712 hashes and transaction decoding. *(done: native and TypeScript; the Android instrumented test covers what the bindings expose: relay URLs, request signatures, the offer, the account, `acceptOffer`, and opening and answering the vectors' `sign_request`)*
- [x] Connect with a **mock keystore** written in Rust (test seed, auto-approve, its endpoint a local `anvil`): both sides end up with the same token signed by both, and `verifyConnection` accepts the statement. A requester restarted from its stored connection sends requests without a new QR code.
- [x] `send`: the mock fills from anvil, signs and broadcasts; the requester gets the hash; the receipt on anvil has the requested `to`, `value` and `data`.
- [x] Several `send`s get consecutive nonces and are all mined.
- [x] `signTransaction` returns `raw` that the SDK's checks accept; the mock broadcasts nothing; the requester broadcasts `raw` and it is mined.
- [x] Type 2 on a chain with a base fee, legacy on a chain without one (`anvil --hardfork berlin`).
- [x] A call that reverts is answered `would_fail`, and nothing is signed or sent.
- [x] A chain without an endpoint is answered `no_endpoint`. A payload with a `nonce` or `gas` field is answered `decode_failed`.
- [x] With two signers, a connection to the second one gets its requests signed by the second one.
- [x] `personal_sign` and `typed_data` return signatures that the SDK verifies.
- [x] A request sent while the keystore is offline is answered when it comes online within 5 minutes. After 5 minutes it is gone, and the call has failed with `timeout`.
- [ ] Two requesters on one connection's storage (two tabs): calls are serialized, and each gets only its own responses. A "reload" with a request in flight cancels it, and the mock keystore drops it unanswered. Two connections to one signer: each gets only its own responses. *(Rust: two requesters in flight on one connection, and a dropped call cancelled — done; serialization across tabs and the `sessionStorage` reload path need a browser)*
- [x] The wagmi connector, in a Node test with `@wagmi/core` against the Rust relay, the mock keystore and anvil: `connect`, `sendTransaction` (also with `nonce` and `gas` set by the caller, which the keystore's own values replace), `signMessage`, `signTypedData`, `switchChain`, and reconnecting from storage. Reads go to the configured transport, never to the keystore. *(done in a Deno test with `@wagmi/core` 3.6.9)*
- [ ] A wagmi demo page connects to the Android app on a real device and completes `sendTransaction`, over the public relay.

### 13.2 Security
- [x] A tampered envelope (any flipped byte) is rejected. A `bind` sealed with the wrong PSK is rejected. A message from an `spk` that isn't a live connection is dropped.
- [x] The relay answers 401 to: a write with no token or ticket; a token without the inbox owner's signature; a request signed by anyone but the token's other party; an expired token or one with too long a lifetime; a stale request `ts`; a read or acknowledgement not signed by the inbox key.
- [x] A used ticket is answered 409, and an expired one 401.
- [x] Disconnecting from either side: the other side's next write gets 403, and the side that disconnected drops messages from that connection even through a relay that ignores revocations.
- [ ] A second valid `bind` fails the connect with `contested` and revokes both tokens. *(implemented, not tested: needs a misbehaving relay)*
- [x] A `bind` whose `spk` isn't the token's `k`, or whose statement differs from the token by one character, is rejected.
- [x] When `bound` never arrives, the keystore revokes the half-signed token, and the requester's writes with it get 403.
- [x] A request redelivered after the keystore "crashed" mid-request (killed between answering and acknowledging, and between signing and broadcasting) is not shown again and gets the stored answer; nothing is signed twice.
- [x] A requester whose clock is 10 minutes off connects and sends requests (relay time, §4.8).
- [x] Replaying the same message is rejected (by `id`), and stale `ts` is rejected.
- [x] Log capture during connect and requests contains no inbox keys, tokens, tickets, envelope bytes or IPs (automated grep test).
- [ ] `evm.eip7702_auth` and `evm.eth_sign` requests are refused end to end. *(unit tests in `blox-evm`; the mock keystore and the app use the same code)*
- [ ] The keystore contacts no host except its configured endpoints and allowed relays. A QR code naming an unknown relay prompts before any connection.
- [ ] Removing a signer ends its connections, deletes its Android Keystore wrapping key and its transport keys; its old connections' writes are then refused.
- [ ] The SDK never logs the QR string or its secret keys. In browsers, `crypto.subtle.exportKey` on the stored connection keys fails. *(nothing is logged; the `exportKey` check needs a browser)*

### 13.3 Relay robustness
- [x] A reader that disconnects and reconnects gets unacknowledged messages again, and messages that were acknowledged do not come back.
- [x] Two readers on one inbox both get every message; a message one of them acknowledges is not delivered to readers that connect later; a 9th reader gets 429.
- [x] A writer with 4 messages queued in an inbox gets 429, while another connection's writes to the same inbox still succeed.
- [x] Queue, size, rate, ticket and revocation limits are enforced with the documented status codes.
- [ ] CORS preflights are answered, and a browser page can register a ticket, write, read and acknowledge. *(preflight: done; from a browser page: pending)*
- [ ] Memory returns to baseline after 10k inboxes are drained or expire, and expired tickets and revocations are dropped. *(tested with 200 inboxes)*
- [x] 1,000 concurrent SSE readers; enqueue-to-delivery p99 < 50 ms on localhost, including token checks.

### 13.4 Compatibility
- [ ] Runs on Android 9 (`minSdk` 28) through the current release, on at least one StrongBox device and one TEE-only device.
- [ ] BiometricPrompt approval works with fingerprint, with face (class 3), and with the device-PIN fallback.
- [ ] Removing the screen lock invalidates the seed wrapping keys, and the restore flow recovers the same addresses for every signer. Connections keep working (transport keys don't need user authentication).
- [ ] The SDK's QR code scans reliably from laptop screens, in light and dark page themes.
- [ ] The SDK works in current Chrome, Firefox and Safari, including IndexedDB storage, and in Node 22+. The connector works with wagmi's current major version. *(Deno and wagmi 3: done; browsers and Node: pending)*
- [ ] Integration needs one dependency and one import: a fresh Vite and a fresh Next.js app with wagmi build with the connector added and no other change (no bundler plugin, no CSS import). `@blox/sdk` stays within its size target (§9.1).
- [ ] A reproducible build produces the same APK bytes as the published release (apart from the signature).

---

## 14. Deliverables (MVP)

```
blox/
├── Cargo.toml                 (workspace)
├── crates/
│   ├── blox-proto/            envelope, HPKE, tokens, request signatures, padding, messages, QR payload, CAIP types
│   ├── blox-evm/              request decoding, filling, display model, danger flags, signing
│   ├── blox-ffi/              UniFFI bindings for the keystore (including the ChainRpc interface)
│   ├── blox-relay/            axum relay (§8)          → binary `blox-relay`
│   ├── blox-client/           Rust requester (§9)
│   └── blox-mock-keystore/    Rust keystore for tests (§13.1)
├── sdk/js/                    @blox/sdk: TypeScript requester, the modal, the EIP-1193 provider, the
│                              wagmi connector (`@blox/sdk/wagmi`), and `demo/` (Vite + wagmi)
├── android/                   Kotlin/Compose keystore app (§10), Gradle build that runs cargo-ndk
├── test-vectors/              JSON vectors pinning the wire format
├── deploy/
│   ├── Dockerfile
│   └── Caddyfile
└── README.md
```
The JSON-RPC adapter crates from M2 (`blox-adapter`, `blox-cli`) are removed. Integration tests
that need `anvil` skip with a clear message if it is missing.

### 14.1 Milestones
1. **M1 (done):** `blox-proto` + test vectors, `blox-relay`, `blox-mock-keystore`, and an integration test of a full session through the relay. M3 replaces the session parts.
2. **M2 (done, retired):** the `blox rpc` JSON-RPC adapter. Its fill logic moves to the keystore in M4, and its crates are removed.
3. **M3 — connections (Rust):** tokens, request signatures, the new envelope and QR payload in `blox-proto`; relay inboxes with signature checks, tickets, revocation, TTL 5 min, CORS; `Requester::connect` with a stored connection; the mock keystore's connect; the connection and relay gates of §13.2–§13.3.
4. **M4 — requests (Rust):** the messages of §6; filling, sending and `sign_tx` in `blox-evm`; the requester's calls and checks; the mock keystore with an anvil endpoint and two signers. The §13.1 gates that don't need a phone or a browser pass against anvil.
5. **M5 — Android:** signer management (add, remove, view phrase), transport keys, connect screen, connection list, reading inboxes, endpoint and relay settings, filling and sending through `ChainRpc`, the review screen. The same gates from a real device.
6. **M6 — web SDK:** `@blox/sdk` on WebCrypto with non-extractable keys in IndexedDB, the modal, the EIP-1193 provider and the wagmi connector, a wagmi demo page.
7. **M7 — release:** deploy the relay at `relay.example.com`, Docker/Caddy, README, reproducible signed release builds.

### 14.2 README must cover
- Integrating a site or app: adding the connector to a wagmi config (the one-line case), wrapping the provider for other stacks, or calling the SDK directly; what the user sees; server-side `verifyConnection` for login.
- Running a relay locally and self-hosting it (Docker + Caddy).
- Installing the app and verifying the APK (checksums, certificate fingerprint, reproducible build); adding signers and chain endpoints; reviewing and ending connections.
- Security model: what the relay, connected sites and the endpoint see (§3.3), what is trusted (§3.4), the properties of §4.9, the unverified requester name, QR proxying and the QR-observer limitation (§3.2, §3.3).
- Backing up and restoring signers, and what invalidates the Keystore wrapping keys.

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
| Seed | BIP-39, NIP-06 identity at `m/44'/1237'/0'/0/0` | Same mnemonic format, one per signer |
| EVM keys | `m/44'/60'/0'/0/0` | The same path. A FURY seed imported as a Blox signer (v2) shows the same address. |
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
  new kinds `nostr.event` and `nostr.nip44_decrypt`, over a connection. That needs an
  **auto-approve policy class** (§12.2) for low-risk operations such as decrypting incoming
  messages from known contacts, which relaxes the MVP's "every request is approved by a human"
  rule. So it is v2 at the earliest, and it needs its own threat model.

### 15.3 Where the two conflict, and how to resolve it
- **IP addresses.** FURY's rule is that no IP reaches a relay; the Blox relay and the chain
  endpoints see the phone's IP (§3.3). Options, in order of effort:
  1. **A Tor option for the keystore** (a "Route via Tor" setting in the app), using Arti as FURY
     does, for the relay and the endpoints. Cost: Tor bootstrap when the app opens, about 10 s
     the first time and a few seconds once the directory is cached. Browser requesters cannot use Tor.
  2. **A Nostr transport (v2 candidate), modelled on NIP-46 `nostrconnect://`.**
     - Connection keys as Nostr keys, ephemeral event kinds (20000–29999, which relays don't
       store) for requests and replaceable events for the 5-minute window, Tor-routed through
       `fury-core`'s `RelayClient`.
     - The QR code carries the relays, the requester's connection pubkey and a secret.
     - No Blox relay to run, which matches FURY's "no servers you don't own".
     - Constraints: **NIP-44 plaintext is capped at 64 KiB** and relays limit event size, so
       large payloads (contract deployments) need chunking. Latency depends on the relays.
  The Blox relay stays the default. The Nostr transport is an alternative, which works because
  the signing messages (§6) don't depend on the transport.
- **Cryptography.** Blox uses X25519/HPKE and Ed25519 tokens on its relay. A Nostr transport
  would use NIP-44 with Schnorr-signed events instead. Only the envelope and token layers (§4.3–§4.5) change.
- **Lesson from FURY's graph leak (FURY `SECURITY.md`).** FURY's kind-4 DMs expose long-term
  pubkeys to relays, so anyone can rebuild who talks to whom. **Blox must never use an identity
  key (a seed-derived key or the account) as a transport identifier.** The MVP complies: inbox
  keys are random transport keys, a new one per connection on the requester side and one per
  signer on the keystore side, and the account appears only inside encryption. The relay can
  still link one signer's connections over time (§3.3); per-connection keystore keys would
  hide that from the relay but not from the phone's IP, so the MVP does not use them. A Nostr
  transport must likewise never use the user's npub.

### 15.4 Roadmap alignment
| Blox | FURY | Note |
|---|---|---|
| MVP: Android keystore, EVM, connections | M4 (storage), M9 (mobile) | Blox can ship on its own. Its Android key storage (§10.2) is a concrete design for FURY M9's "Android Keystore wraps the mnemonic key". |
| v2: push, policies, simulation, import, iOS | M5.5 (push), M9 (iOS) | Share the push proxy and UniFFI/iOS work. Evaluate the Nostr transport (§15.3). |
| v3: Bitcoin, Solana, other chains | FURY BTC keys (M1) | Settle the BTC derivation path (§15.1). |
| Later: keystore as the Nostr signer | M5+ | Needs the policy class (§15.2). |

---

## 16. Changes from earlier drafts (for reviewers)

**From the QR-session draft (2026-11-10, earlier the same day):**
- **Connections replace one-shot sessions.** A requester connects to one signer once with a QR
  code; both sides keep a token signed by both, and the account signs a statement that serves
  as the site's login. Requests then go through the relay at any time and wait 5 minutes for
  the phone. A short connection (1 day) covers the one-off case.
- **The relay authorizes writes.** No anonymous writes: a token the inbox owner signed and a
  request signature from the other party, or a one-time ticket from the QR code. Reads are
  signed by the inbox key instead of presenting a `read_secret`.
- **`evm.sign_tx`:** the keystore can return a filled, signed transaction instead of broadcasting it.
- **Isolation per connection instead of one reader per inbox:** an inbox can have several
  readers (tabs), each takes only its own responses, the relay limits each writer to 4 queued
  messages in an inbox, and the phone groups requests by connection. One request in flight per
  connection is the SDK's rule; `cancel` (§6.5) cleans up after closed tabs, reloads and retries.
- The previous v2 pairing (§12.1 of that draft) is this design, moved into the MVP.
- **Integration is one dependency and one import.** The SDK gains an in-page EIP-1193 provider
  and a wagmi connector that translate wallet calls into intent, so existing dapps adopt Blox
  without touching their transaction code.
- **The browser SDK is TypeScript on WebCrypto, not a wasm build of `blox-proto`:** no bundler
  setup for integrators, and the connection keys are non-extractable. The wire format is pinned
  by the test vectors for both implementations.

**From the JSON-RPC adapter draft (implemented as M2):**
- **The phone fills, signs and broadcasts.** Requesters send intent only. This removes untrusted
  filling (nonce, gas and fees came from the adapter's upstream).
- **Every host the phone contacts is chosen on the phone.** Chain endpoints are configured in
  the app, and an unknown relay needs consent.
- **Integration through an SDK**, instead of acting as a JSON-RPC signer for `cast`, `forge` and
  viem. WalletConnect is dropped from the plan.
- **Several signers** per keystore, each with its own seed and wrapping key; importing an
  existing mnemonic moves to v2.
- **Relay:** messages are kept 5 minutes (was 10), and CORS is on for browser requesters.

**From the original draft:**
- **The phone is the signer**, not a relay to `window.ethereum`. This removes the dependency on `eth_signTransaction`, which MetaMask doesn't support, and on the wallet's in-app browser.
- **Authenticated channel:** HPKE with keys from the QR code, single-use QR, and contest detection. This closes the key-substitution attack on the draft's unauthenticated exchange.
- **At-least-once delivery with acknowledgements** replaces `watch` channels and "delete on delivery".
- **A native Android keystore** holds the seeds, encrypted under hardware-backed Keystore keys and unlocked by biometrics. It shares its Rust core with the requester SDKs.
- **Defined limits, privacy-safe logging and deployment guidance** for running a public relay.

/**
 * The requester (BLOX.md §9.2): connect once with a QR code, then send intent and get
 * hashes, signed transactions or signatures back.
 */

import { sha256 } from "@noble/hashes/sha2";
import { b64, unb64 } from "./b64.ts";
import { equal, randomBytes, toHex } from "./bytes.ts";
import { checkResponse, checksum, type TypedData, verifyStatement } from "./evm.ts";
import { type Backend, chooseBackend, type KemKey, kemKeyFrom, type SigKey, sigKeyFrom, UnsupportedBrowser } from "./keys.ts";
import { type Delivery, RelayClient, RelayError } from "./relay.ts";
import { DEFAULT_RELAY, normalizeRelay } from "./relayUrl.ts";
import { type ConnectionStore, defaultStore, type StoredConnection } from "./store.ts";
import { createUi } from "./ui.ts";
import {
  decodeMessage,
  encodeMessage,
  MAX_LIFETIME_SECS,
  newMessage,
  offerUri,
  openBind,
  openMessage,
  parseIso8601,
  type RejectReason,
  renderStatement,
  sealMessage,
  signRequest,
  type SignRequest,
  type SignResponse,
  statementField,
  Token,
  truncateLabel,
} from "./wire.ts";

export type ErrorCode =
  | "rejected"
  | "failed"
  | "no_signer"
  | "contested"
  | "timeout"
  | "disconnected"
  | "cancelled"
  | "bad_response"
  | "relay_error"
  | "unsupported_browser";

export class BloxError extends Error {
  constructor(
    readonly code: ErrorCode,
    message: string,
    readonly extra: { reason?: RejectReason; txHash?: string; relayCode?: string | null } = {},
  ) {
    super(message);
    this.name = "BloxError";
  }
}

export type Status =
  | { type: "connecting"; uri: string; until: number }
  | { type: "connected"; account: string }
  | { type: "queued" }
  | { type: "waiting"; until: number }
  | { type: "done"; text: string }
  | { type: "idle" };

export interface BloxOptions {
  /** Shown on the phone as a claim (§3.3). */
  name: string;
  relay?: string;
  /** Sent with requests as `origin.url`; defaults to `location.origin` in browsers. */
  url?: string;
  storage?: ConnectionStore;
  /** Receives the QR string while connecting, and `null` when it's no longer needed. */
  onQr?: (uri: string | null) => void;
  onStatus?: (s: Status) => void;
  connectTimeoutMs?: number;
  /** Key backend; chosen automatically (WebCrypto in browsers). */
  backend?: Backend;
  /** `"toast"` (default in browsers) shows request progress; `"none"` leaves it to you (§9.4). */
  requestUi?: "toast" | "none";
  /** Test hook: pretend the local clock is off by this many seconds (§4.8). */
  localClockSkew?: number;
}

export interface TxIntent {
  chain: number;
  /** `null` deploys a contract. */
  to: string | null;
  value?: bigint;
  data?: string;
}

interface Live {
  token: Token;
  sig: SigKey;
  kem: KemKey;
  account: string;
  stored: StoredConnection;
  /** The account's signed statement, when this instance made the connection (§9.2 login). */
  proof?: { statement: string; signature: string };
}

const MAX_REQUEST_SECS = 300;
const TICKET_SECS = 120;
const BIND_SKEW = 300;

type Locks = { request<T>(name: string, f: () => Promise<T>): Promise<T> };

export class Blox {
  readonly relayUrl: string;
  private readonly relay: RelayClient;
  private readonly store: ConnectionStore;
  private backendP: Promise<Backend> | null = null;
  private live: Live | null = null;
  private seen = new Set<string>();
  private queue: Promise<unknown> = Promise.resolve();
  private connecting: Promise<Live> | null = null;
  private inflight = new Map<string, { cancel: Uint8Array; auth: string; inbox: string; token: string }>();
  private abort: AbortController | null = null;
  private onQr: (uri: string | null) => void;
  private onStatus: (s: Status) => void;

  constructor(private readonly opts: BloxOptions) {
    this.relayUrl = normalizeRelay(opts.relay ?? DEFAULT_RELAY);
    this.relay = new RelayClient(this.relayUrl, opts.localClockSkew ?? 0);
    this.store = opts.storage ?? defaultStore();
    const browser = typeof (globalThis as { document?: unknown }).document !== "undefined";
    const ui = browser && (!opts.onQr || (!opts.onStatus && opts.requestUi !== "none"))
      ? createUi(opts.name, () => this.cancel(), { toast: opts.requestUi !== "none" })
      : null;
    this.onQr = opts.onQr ?? ui?.onQr ?? (() => {});
    this.onStatus = (s) => {
      opts.onStatus?.(s);
      if (!opts.onStatus) ui?.onStatus(s);
    };
    const g = globalThis as { addEventListener?: (t: string, f: () => void) => void };
    g.addEventListener?.("pagehide", () => this.cancelOnPageHide());
  }

  /** Cancels the connect or request in progress (the modal's Cancel). */
  cancel(): void {
    this.abort?.abort();
  }

  /** The connected account (checksummed), once known. */
  get account(): string | null {
    return this.live?.account ?? null;
  }

  private backend(): Promise<Backend> {
    this.backendP ??= this.opts.backend ? Promise.resolve(this.opts.backend) : chooseBackend();
    return this.backendP.catch((e) => {
      if (e instanceof UnsupportedBrowser) throw new BloxError("unsupported_browser", e.message);
      throw e;
    });
  }

  private status(s: Status) {
    this.onStatus(s);
  }

  // ---- connecting ---------------------------------------------------------------------

  /**
   * Connects unless a stored connection is still valid (§5). `nonce` (16 bytes from the
   * site's server) becomes the ticket, so the server can check the statement (§9.2).
   */
  async connect(opts: { nonce?: Uint8Array } = {}): Promise<{ account: string; statement?: string; signature?: string }> {
    const live = await this.ensureLive(opts.nonce);
    return { account: live.account, ...(live.proof ?? {}) };
  }

  private async ensureLive(nonce?: Uint8Array): Promise<Live> {
    if (this.live && this.live.token.body.expiresAt > this.relay.now()) return this.live;
    this.connecting ??= this.withLock(`blox:${this.relayUrl}:connect`, async () => {
      const stored = await this.store.load(this.relayUrl);
      if (stored) {
        const token = Token.fromHeader(stored.token);
        if (token.body.expiresAt > Math.floor(Date.now() / 1000) && token.verifyKeystore() && token.verifyRequester()) {
          this.live = { token, sig: sigKeyFrom(stored.sig), kem: kemKeyFrom(stored.kem), account: stored.account, stored };
          await this.cancelLeftovers();
          return this.live;
        }
        await this.store.clear(this.relayUrl);
      }
      this.live = await this.connectNew(nonce);
      return this.live;
    }).finally(() => (this.connecting = null));
    return await this.connecting;
  }

  private async connectNew(nonce?: Uint8Array): Promise<Live> {
    const backend = await this.backend();
    await this.relay.syncTime();
    const sig = await backend.newSigKey();
    const kem = await backend.newKemKey();
    const requester = { sig: sig.key.publicKey, kem: kem.key.publicKey };
    const ticket = nonce ?? randomBytes(16);
    if (ticket.length !== 16) throw new Error("nonce must be 16 bytes");
    const psk = randomBytes(32);
    const label = truncateLabel(this.opts.name);
    await this.relay.registerTicket(sig.key, sha256(ticket), this.relay.now() + TICKET_SECS);

    const abort = (this.abort = new AbortController());
    const inbox = new Inbox(this.relay, sig.key, abort.signal);
    try {
      const uri = offerUri(this.relayUrl, requester, ticket, psk, label);
      const deadline = Date.now() + (this.opts.connectTimeoutMs ?? TICKET_SECS * 1000);
      this.onQr(uri);
      this.status({ type: "connecting", uri, until: deadline });
      while (true) {
        const d = await inbox.next(deadline - Date.now());
        if (!d) throw new BloxError("no_signer", "no phone answered the QR code in time");
        const first = await this.checkBind(d.body, kem.key, sig.key.publicKey, psk, ticket, label);
        await this.relay.ack(sig.key, d.seq).catch(() => {});
        if (!first) continue;
        // An honest relay delivers one bind per ticket; another valid one means someone
        // else answered the same QR code (§5.3).
        const others = [];
        for (const d2 of inbox.drain()) {
          const c = await this.checkBind(d2.body, kem.key, sig.key.publicKey, psk, ticket, label);
          if (c) others.push(c);
          await this.relay.ack(sig.key, d2.seq).catch(() => {});
        }
        if (others.length) {
          for (const c of [first, ...others]) await this.relay.revoke(c.token, sig.key).catch(() => {});
          throw new BloxError("contested", "a second device answered the QR code; someone may have seen it");
        }
        const full = await first.token.countersign(sig.key);
        const bound = newMessage({ type: "bound", body: { token: full.toHeader() } }, this.relay.now());
        const sealed = await sealMessage(backend, kem.key, full.body.keystore, encodeMessage(bound));
        await this.relay.post(full.body.keystore.sig, { token: full, key: sig.key }, sealed);
        const stored: StoredConnection = {
          relay: this.relayUrl,
          label,
          account: first.account,
          token: full.toHeader(),
          sig: sig.stored,
          kem: kem.stored,
        };
        await this.store.save(stored);
        this.status({ type: "connected", account: first.account });
        return {
          token: full,
          sig: sig.key,
          kem: kem.key,
          account: first.account,
          stored,
          proof: { statement: first.statement, signature: first.signature },
        };
      }
    } finally {
      inbox.close();
      this.onQr(null);
      this.abort = null;
    }
  }

  /** §5.3 step 1: everything about a `bind`, including the account signature. */
  private async checkBind(
    body: Uint8Array,
    kem: KemKey,
    inbox: Uint8Array,
    psk: Uint8Array,
    ticket: Uint8Array,
    label: string,
  ): Promise<{ token: Token; account: string; statement: string; signature: string } | null> {
    try {
      const { spk, plaintext } = await openBind(kem, inbox, psk, body);
      const msg = decodeMessage(plaintext);
      const now = this.relay.now();
      if (msg.type !== "bind" || Math.abs(msg.ts - now) > BIND_SKEW) return null;
      const token = Token.fromHeader(msg.body.token);
      const b = token.body;
      const ok = token.verifyKeystore() &&
        equal(b.requester.sig, inbox) && equal(b.requester.kem, kem.publicKey) &&
        b.relay === this.relayUrl && equal(spk, b.keystore.kem) &&
        Math.abs(b.issuedAt - now) <= BIND_SKEW && b.expiresAt > now && b.expiresAt >= b.issuedAt &&
        b.expiresAt - b.issuedAt <= MAX_LIFETIME_SECS;
      if (!ok) return null;
      const statement = renderStatement({
        label,
        requester: b.requester.sig,
        keystore: b.keystore.sig,
        account: msg.body.account,
        ticket,
        relay: b.relay,
        issuedAt: b.issuedAt,
        expiresAt: b.expiresAt,
      });
      if (msg.body.statement !== statement) return null;
      if (!verifyStatement(statement, msg.body.signature, msg.body.account)) return null;
      return { token, account: msg.body.account, statement, signature: msg.body.signature };
    } catch {
      return null;
    }
  }

  // ---- requests -----------------------------------------------------------------------

  /** Sends one request and waits for its answer (§6). One request is in flight at a time. */
  async request(req: SignRequest): Promise<SignResponse> {
    const live = await this.ensureLive();
    this.status({ type: "queued" });
    return await this.withLock(`blox:${this.relayUrl}:${b64(live.sig.publicKey)}`, () => this.requestNow(live, req));
  }

  private async requestNow(live: Live, req: SignRequest): Promise<SignResponse> {
    const backend = await this.backend();
    const now = this.relay.now();
    const expiresAt = !req.expires_at || req.expires_at > now + MAX_REQUEST_SECS ? now + MAX_REQUEST_SECS : req.expires_at;
    const msg = newMessage({ type: "sign_request", body: { ...req, expires_at: expiresAt } }, now);
    const ks = live.token.body.keystore;
    const sealed = await sealMessage(backend, live.kem, ks, encodeMessage(msg));
    // Sealed now, so a closed tab or a reload can still withdraw it (§6.5).
    const cancel = await sealMessage(backend, live.kem, ks, encodeMessage(newMessage({ type: "cancel", body: {} }, now, msg.id)));
    const path = `/v1/inbox/${b64(ks.sig)}`;
    this.track(msg.id, {
      cancel,
      auth: await signRequest(live.sig, "POST", path, now, cancel),
      inbox: b64(ks.sig),
      token: live.token.toHeader(),
    });

    const abort = (this.abort = new AbortController());
    const inbox = new Inbox(this.relay, live.sig, abort.signal);
    try {
      try {
        await this.relay.post(ks.sig, { token: live.token, key: live.sig }, sealed);
      } catch (e) {
        throw await this.writeError(e);
      }
      const deadline = Date.now() + (expiresAt - this.relay.now()) * 1000;
      this.status({ type: "waiting", until: deadline });
      while (true) {
        let d;
        try {
          d = await inbox.next(deadline - Date.now());
        } catch (e) {
          if (e instanceof BloxError && e.code === "cancelled") {
            await this.relay.post(ks.sig, { token: live.token, key: live.sig }, cancel).catch(() => {});
          }
          throw e;
        }
        if (!d) {
          await this.relay.post(ks.sig, { token: live.token, key: live.sig }, cancel).catch(() => {});
          this.status({ type: "done", text: "Expired" });
          throw new BloxError("timeout", "the request expired before the phone answered");
        }
        let m;
        try {
          m = decodeMessage(await openMessage(live.kem, live.sig.publicKey, ks.kem, d.body));
        } catch {
          await this.relay.ack(live.sig, d.seq).catch(() => {});
          continue;
        }
        if (this.seen.has(m.id)) continue;
        if (m.type === "sign_response" && m.re === msg.id) {
          this.seen.add(m.id);
          await this.relay.ack(live.sig, d.seq).catch(() => {});
          return m.body;
        }
        if (m.type === "unbind") {
          await this.relay.ack(live.sig, d.seq).catch(() => {});
          await this.forget();
          throw new BloxError("disconnected", "the phone ended the connection");
        }
        // Another tab's answer on the same connection: leave it for that tab.
      }
    } finally {
      inbox.close();
      this.untrack(msg.id);
      this.abort = null;
    }
  }

  private async writeError(e: unknown): Promise<Error> {
    if (e instanceof RelayError && (e.code === "revoked" || e.code === "expired")) {
      await this.forget();
      return new BloxError("disconnected", "the connection was ended or has expired");
    }
    if (e instanceof RelayError) return new BloxError("relay_error", e.message, { relayCode: e.code });
    return new BloxError("relay_error", String(e));
  }

  /** `evm.send`: the phone fills, signs and broadcasts. */
  async send(tx: TxIntent): Promise<{ account: string; txHash: string }> {
    const r = await this.checked(txRequest("evm.send", tx, this.origin()));
    if (r.resp.status !== "sent") throw unexpected(r.resp);
    return { account: r.account, txHash: r.resp.tx_hash };
  }

  /** `evm.sign_tx`: the phone fills and signs; you broadcast `raw`. */
  async signTransaction(tx: TxIntent): Promise<{ account: string; txHash: string; raw: string }> {
    const r = await this.checked(txRequest("evm.sign_tx", tx, this.origin()));
    if (r.resp.status !== "signed_tx") throw unexpected(r.resp);
    return { account: r.account, txHash: r.resp.tx_hash, raw: r.resp.raw };
  }

  /** EIP-191. A string message is sent as its UTF-8 bytes. */
  async personalSign(p: { chain: number; message: string | Uint8Array }): Promise<{ account: string; signature: string }> {
    const bytes = typeof p.message === "string" ? new TextEncoder().encode(p.message) : p.message;
    const r = await this.checked({
      chain: `eip155:${p.chain}`,
      kind: "evm.personal_sign",
      payload: { message: toHex(bytes) },
      origin: this.origin(),
      expires_at: 0,
    });
    if (r.resp.status !== "signed") throw unexpected(r.resp);
    return { account: r.account, signature: r.resp.signature };
  }

  /** EIP-712. */
  async signTypedData(p: { chain: number; data: TypedData }): Promise<{ account: string; signature: string }> {
    const data = JSON.parse(JSON.stringify(p.data, (_, v) => (typeof v === "bigint" ? v.toString() : v)));
    const r = await this.checked({
      chain: `eip155:${p.chain}`,
      kind: "evm.typed_data",
      payload: { data },
      origin: this.origin(),
      expires_at: 0,
    });
    if (r.resp.status !== "signed") throw unexpected(r.resp);
    return { account: r.account, signature: r.resp.signature };
  }

  private async checked(req: SignRequest): Promise<{ account: string; resp: SignResponse }> {
    const resp = await this.request(req);
    const account = this.live?.account;
    if (!account) throw new BloxError("disconnected", "not connected");
    try {
      checkResponse(req, resp, account);
    } catch (e) {
      throw new BloxError("bad_response", `the answer failed its checks: ${(e as Error).message}`);
    }
    if (resp.status === "rejected") {
      this.status({ type: "done", text: "Rejected" });
      throw new BloxError("rejected", `the phone refused: ${resp.reason}`, { reason: resp.reason });
    }
    if (resp.status === "failed") {
      throw new BloxError("failed", resp.error, { txHash: resp.tx_hash });
    }
    this.status({ type: "done", text: resp.status === "sent" ? `Sent · ${resp.tx_hash}` : "Signed" });
    return { account, resp };
  }

  private origin() {
    const loc = (globalThis as { location?: { origin?: string } }).location;
    return { name: this.opts.name, url: this.opts.url ?? loc?.origin };
  }

  // ---- ending -------------------------------------------------------------------------

  /** Ends the connection: `unbind`, revoke, forget (§5.5). */
  async disconnect(): Promise<void> {
    const live = this.live ?? (await this.loadQuietly());
    if (live) {
      const backend = await this.backend();
      const ks = live.token.body.keystore;
      const bye = newMessage({ type: "unbind", body: {} }, this.relay.now());
      await sealMessage(backend, live.kem, ks, encodeMessage(bye))
        .then((sealed) => this.relay.post(ks.sig, { token: live.token, key: live.sig }, sealed))
        .catch(() => {});
      await this.relay.revoke(live.token, live.sig).catch(() => {});
    }
    await this.forget();
  }

  /** Loads a stored, unexpired connection without showing a QR code; its account or null. */
  async restore(): Promise<string | null> {
    if (this.live && this.live.token.body.expiresAt > this.relay.now()) return this.live.account;
    const s = await this.store.load(this.relayUrl);
    if (!s) return null;
    const token = Token.fromHeader(s.token);
    if (token.body.expiresAt <= Math.floor(Date.now() / 1000)) return null;
    this.live = { token, sig: sigKeyFrom(s.sig), kem: kemKeyFrom(s.kem), account: s.account, stored: s };
    return s.account;
  }

  private async loadQuietly(): Promise<Live | null> {
    const s = await this.store.load(this.relayUrl);
    if (!s) return null;
    return { token: Token.fromHeader(s.token), sig: sigKeyFrom(s.sig), kem: kemKeyFrom(s.kem), account: s.account, stored: s };
  }

  private async forget() {
    this.live = null;
    await this.store.clear(this.relayUrl);
  }

  /** Persists the current chain with the connection (the provider's state, §9.3). */
  async rememberChain(chain: number) {
    if (!this.live) return;
    this.live.stored = { ...this.live.stored, chain };
    await this.store.save(this.live.stored);
  }

  async storedChain(): Promise<number | undefined> {
    return (this.live?.stored ?? (await this.store.load(this.relayUrl)))?.chain;
  }

  // ---- one at a time, and leftovers ---------------------------------------------------

  private withLock<T>(name: string, f: () => Promise<T>): Promise<T> {
    const locks = (globalThis as { navigator?: { locks?: Locks } }).navigator?.locks;
    if (locks) return locks.request(name, f);
    const run = this.queue.then(f, f);
    this.queue = run.catch(() => {});
    return run;
  }

  private sessionKey() {
    return `blox:inflight:${this.relayUrl}`;
  }

  private session(): Storage | null {
    try {
      return (globalThis as { sessionStorage?: Storage }).sessionStorage ?? null;
    } catch {
      return null;
    }
  }

  private track(id: string, c: { cancel: Uint8Array; auth: string; inbox: string; token: string }) {
    this.inflight.set(id, c);
    this.saveInflight();
  }

  private untrack(id: string) {
    this.inflight.delete(id);
    this.saveInflight();
  }

  private saveInflight() {
    const s = this.session();
    if (!s) return;
    const list = [...this.inflight.values()].map((c) => ({ inbox: c.inbox, token: c.token, cancel: b64(c.cancel) }));
    if (list.length) s.setItem(this.sessionKey(), JSON.stringify(list));
    else s.removeItem(this.sessionKey());
  }

  /** After a reload: withdraw the requests the previous page left in flight (§9.2). */
  private async cancelLeftovers() {
    const s = this.session();
    const raw = s?.getItem(this.sessionKey());
    if (!raw || !this.live) return;
    s!.removeItem(this.sessionKey());
    for (const c of JSON.parse(raw) as { inbox: string; token: string; cancel: string }[]) {
      await this.relay
        .post(unb64(c.inbox), { token: Token.fromHeader(c.token), key: this.live.sig }, unb64(c.cancel))
        .catch(() => {});
    }
  }

  /** Best effort when the page goes away: `fetch` with `keepalive` and the pre-signed request. */
  private cancelOnPageHide() {
    for (const c of this.inflight.values()) {
      fetch(`${this.relayUrl}/v1/inbox/${c.inbox}`, {
        method: "POST",
        keepalive: true,
        headers: { authorization: c.auth, "blox-token": c.token, "content-type": "application/octet-stream" },
        body: c.cancel,
      }).catch(() => {});
    }
  }
}

/** Reads one inbox while a connect or a request is in progress. */
class Inbox {
  private ctrl = new AbortController();
  private items: Delivery[] = [];
  private wake: (() => void) | null = null;
  private failed: unknown = null;

  constructor(relay: RelayClient, key: SigKey, private readonly cancel?: AbortSignal) {
    cancel?.addEventListener("abort", () => this.wake?.());
    relay.subscribe(key, (d) => {
      this.items.push(d);
      this.wake?.();
    }, this.ctrl.signal).catch((e) => {
      this.failed = e;
      this.wake?.();
    });
  }

  /** The next delivery, or null after `ms`. */
  async next(ms: number): Promise<Delivery | null> {
    const deadline = Date.now() + ms;
    while (!this.items.length) {
      if (this.cancel?.aborted) throw new BloxError("cancelled", "cancelled");
      if (this.failed) throw new BloxError("relay_error", String(this.failed));
      const left = deadline - Date.now();
      if (left <= 0) return null;
      await new Promise<void>((resolve) => {
        const t = setTimeout(resolve, left);
        this.wake = () => {
          clearTimeout(t);
          resolve();
        };
      });
      this.wake = null;
    }
    return this.items.shift()!;
  }

  drain(): Delivery[] {
    return this.items.splice(0);
  }

  close() {
    this.ctrl.abort();
  }
}

function txRequest(kind: string, tx: TxIntent, origin: { name: string; url?: string }): SignRequest {
  return {
    chain: `eip155:${tx.chain}`,
    kind,
    payload: {
      to: tx.to === null ? null : checksum(tx.to),
      value: "0x" + (tx.value ?? 0n).toString(16),
      data: tx.data ?? "0x",
    },
    origin,
    expires_at: 0,
  };
}

function unexpected(r: SignResponse) {
  return new BloxError("bad_response", `unexpected answer ${r.status}`);
}

/**
 * For a site's server (§9.2): checks a connection statement against the nonce it issued.
 * `now` is the server's clock (seconds); the statement must be at most 300 s old.
 */
export function verifyConnection(
  c: { account: string; statement: string; signature: string },
  opts: { nonce: Uint8Array; now?: number },
): boolean {
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const t = c.statement;
  if (t.split("\n")[0] !== "Blox connection") return false;
  if (statementField(t, "Account") !== c.account) return false;
  if (statementField(t, "Nonce") !== b64(opts.nonce)) return false;
  const issued = parseIso8601(statementField(t, "Issued") ?? "");
  const expires = parseIso8601(statementField(t, "Expires") ?? "");
  if (issued === null || expires === null || Math.abs(issued - now) > 300 || expires <= now) return false;
  return verifyStatement(t, c.signature, c.account);
}


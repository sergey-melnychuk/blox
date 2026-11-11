/** The relay's HTTP API (BLOX.md §8.2) with signed requests (§4.4) and relay time (§4.8). */

import { b64, unb64 } from "./b64.ts";
import { own } from "./bytes.ts";
import type { SigKey } from "./keys.ts";
import { signRequest, type Token } from "./wire.ts";

export class RelayError extends Error {
  constructor(readonly status: number, readonly code: string | null) {
    super(`relay: ${status} ${code ?? ""}`);
  }
}

export type WriteAuth = { token: Token; key: SigKey } | { ticket: Uint8Array };

export interface Delivery {
  seq: number;
  body: Uint8Array;
}

export class RelayClient {
  /** Relay clock minus local clock (seconds). */
  private offset = 0;
  private synced = false;

  /** `base` is the normalized relay URL; `localSkew` is a test hook. */
  constructor(readonly base: string, private readonly localSkew = 0) {}

  private local(): number {
    return Math.floor(Date.now() / 1000) + this.localSkew;
  }

  /** Relay time. */
  now(): number {
    return this.local() + this.offset;
  }

  async syncTime(): Promise<void> {
    const res = await fetch(`${this.base}/v1/info`);
    if (!res.ok) throw new RelayError(res.status, null);
    const info = await res.json();
    this.offset = info.now - this.local();
    this.synced = true;
  }

  /** A signed request; resyncs the clock and retries once after `401 clock`. */
  async request(
    method: string,
    path: string,
    opts: { key?: SigKey; headers?: Record<string, string>; body?: Uint8Array; keepalive?: boolean; signal?: AbortSignal } = {},
  ): Promise<Response> {
    if (!this.synced) await this.syncTime();
    const body = opts.body ?? new Uint8Array(0);
    for (let attempt = 0; attempt < 2; attempt++) {
      const headers: Record<string, string> = { ...(opts.headers ?? {}) };
      if (opts.key) headers.authorization = await signRequest(opts.key, method, path, this.now(), body);
      const res = await fetch(`${this.base}${path}`, {
        method,
        headers,
        body: method === "GET" || method === "DELETE" ? undefined : own(body),
        keepalive: opts.keepalive,
        signal: opts.signal,
      });
      if (res.ok) return res;
      const code = await res.json().then((j) => j.error as string).catch(() => null);
      if (code === "clock" && attempt === 0) {
        await this.syncTime();
        continue;
      }
      throw new RelayError(res.status, code);
    }
    throw new Error("unreachable");
  }

  async post(inbox: Uint8Array, auth: WriteAuth, envelope: Uint8Array): Promise<void> {
    const headers: Record<string, string> = { "content-type": "application/octet-stream" };
    if ("ticket" in auth) {
      headers["blox-ticket"] = b64(auth.ticket);
      await this.request("POST", `/v1/inbox/${b64(inbox)}`, { headers, body: envelope });
    } else {
      headers["blox-token"] = auth.token.toHeader();
      await this.request("POST", `/v1/inbox/${b64(inbox)}`, { key: auth.key, headers, body: envelope });
    }
  }

  async registerTicket(owner: SigKey, ticketHash: Uint8Array, expiresAt: number): Promise<void> {
    const body = new TextEncoder().encode(JSON.stringify({ ticket_hash: b64(ticketHash), expires_at: expiresAt }));
    await this.request("POST", `/v1/inbox/${b64(owner.publicKey)}/tickets`, {
      key: owner,
      headers: { "content-type": "application/json" },
      body,
    });
  }

  async revoke(token: Token, key: SigKey): Promise<void> {
    await this.request("POST", "/v1/revoke", { key, headers: { "blox-token": token.toHeader() } });
  }

  async ack(owner: SigKey, seq: number): Promise<void> {
    await this.request("DELETE", `/v1/inbox/${b64(owner.publicKey)}/${seq}`, { key: owner });
  }

  /**
   * Reads `owner`'s inbox with `fetch` streaming (EventSource can't send Authorization),
   * reconnecting with backoff, until `signal` aborts.
   */
  async subscribe(owner: SigKey, onDelivery: (d: Delivery) => void, signal: AbortSignal): Promise<void> {
    let backoff = 250;
    while (!signal.aborted) {
      try {
        const res = await this.request("GET", `/v1/inbox/${b64(owner.publicKey)}`, {
          key: owner,
          headers: { accept: "text/event-stream" },
          signal,
        });
        backoff = 250;
        const reader = res.body!.getReader();
        const decoder = new TextDecoder();
        let buf = "";
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          let end;
          while ((end = buf.indexOf("\n\n")) >= 0) {
            const frame = buf.slice(0, end);
            buf = buf.slice(end + 2);
            const lines = frame.split("\n");
            if (!lines.some((l) => l.replace(/\s+$/, "") === "event: msg")) continue;
            const data = lines.find((l) => l.startsWith("data:"));
            if (!data) continue;
            const ev = JSON.parse(data.slice(5).trim());
            onDelivery({ seq: ev.seq, body: unb64(ev.body) });
          }
        }
      } catch (e) {
        if (signal.aborted) return;
        if (e instanceof RelayError && (e.code === "unauthorized" || e.code === "malformed")) throw e;
      }
      if (signal.aborted) return;
      await new Promise((r) => setTimeout(r, backoff));
      backoff = Math.min(backoff * 2, 5000);
    }
  }
}

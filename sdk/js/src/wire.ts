/**
 * The wire format (BLOX.md §4.3–§4.6, §5.1, §5.2): tokens, request signatures, envelopes,
 * the offer behind the QR code, the connection statement, and messages.
 */

import { sha256 } from "@noble/hashes/sha2";
import { b64, unb64 } from "./b64.ts";
import { base45 } from "./base45.ts";
import { concat, dec, enc, equal, randomBytes, readU64be, u64be } from "./bytes.ts";
import { openAuth, sealAuth } from "./hpke.ts";
import { type Backend, type KemKey, type SigKey, verifyEd25519 } from "./keys.ts";
import { pad, unpad } from "./pad.ts";
import { toQrField } from "./relayUrl.ts";

export const VERSION = 1;

// ---- token (§4.3) --------------------------------------------------------------------

export interface PartyKeys {
  sig: Uint8Array;
  kem: Uint8Array;
}

export interface TokenBody {
  requester: PartyKeys;
  keystore: PartyKeys;
  issuedAt: number;
  expiresAt: number;
  relay: string;
}

export const MAX_LIFETIME_SECS = 90 * 86400;
const TOKEN_DOMAIN = enc.encode("blox/v1/token");

export class Token {
  private constructor(
    readonly body: TokenBody,
    private readonly encoded: Uint8Array,
    readonly keystoreSig: Uint8Array,
    readonly requesterSig: Uint8Array | null,
  ) {}

  static encodeBody(b: TokenBody): Uint8Array {
    const relay = enc.encode(b.relay);
    return concat(
      new Uint8Array([VERSION]),
      b.requester.sig,
      b.requester.kem,
      b.keystore.sig,
      b.keystore.kem,
      u64be(b.issuedAt),
      u64be(b.expiresAt),
      new Uint8Array([relay.length]),
      relay,
    );
  }

  static fromBytes(bytes: Uint8Array): Token {
    if (bytes.length < 146 || bytes[0] !== VERSION) throw new Error("token");
    const relayLen = bytes[145];
    const n = 146 + relayLen;
    if (bytes.length !== n + 64 && bytes.length !== n + 128) throw new Error("token signatures");
    const body: TokenBody = {
      requester: { sig: bytes.slice(1, 33), kem: bytes.slice(33, 65) },
      keystore: { sig: bytes.slice(65, 97), kem: bytes.slice(97, 129) },
      issuedAt: readU64be(bytes, 129),
      expiresAt: readU64be(bytes, 137),
      relay: dec.decode(bytes.slice(146, n)),
    };
    const ks = bytes.slice(n, n + 64);
    const rs = bytes.length === n + 128 ? bytes.slice(n + 64) : null;
    return new Token(body, bytes.slice(0, n), ks, rs);
  }

  static fromHeader(s: string): Token {
    return Token.fromBytes(unb64(s));
  }

  /** Signs as the keystore (tests and tools). */
  static async issue(body: TokenBody, keystore: SigKey): Promise<Token> {
    const encoded = Token.encodeBody(body);
    const sig = await keystore.sign(concat(TOKEN_DOMAIN, encoded));
    return new Token(body, encoded, sig, null);
  }

  get signedBytes(): Uint8Array {
    return concat(TOKEN_DOMAIN, this.encoded);
  }

  id(): Uint8Array {
    return sha256(this.signedBytes);
  }

  verifyKeystore(): boolean {
    return verifyEd25519(this.keystoreSig, this.signedBytes, this.body.keystore.sig);
  }

  verifyRequester(): boolean {
    return !!this.requesterSig && verifyEd25519(this.requesterSig, this.signedBytes, this.body.requester.sig);
  }

  async countersign(requester: SigKey): Promise<Token> {
    if (!equal(requester.publicKey, this.body.requester.sig)) throw new Error("not the token's requester key");
    return new Token(this.body, this.encoded, this.keystoreSig, await requester.sign(this.signedBytes));
  }

  toBytes(): Uint8Array {
    return concat(this.encoded, this.keystoreSig, this.requesterSig ?? new Uint8Array(0));
  }

  toHeader(): string {
    return b64(this.toBytes());
  }
}

// ---- request signatures (§4.4) -------------------------------------------------------

/** `Authorization: Blox <ts>.<sig>`; `path` starts at `/v1/`. */
export async function signRequest(key: SigKey, method: string, path: string, ts: number, body: Uint8Array): Promise<string> {
  const z = new Uint8Array([0]);
  const msg = concat(enc.encode("blox/v1/req"), z, enc.encode(method.toUpperCase()), z, enc.encode(path), z, u64be(ts), sha256(body));
  return `Blox ${ts}.${b64(await key.sign(msg))}`;
}

// ---- envelopes (§4.5) ----------------------------------------------------------------

export const KIND_BIND = 1;
export const KIND_MESSAGE = 2;
const INFO = { [KIND_BIND]: enc.encode("blox/v1/bind"), [KIND_MESSAGE]: enc.encode("blox/v1/msg") } as Record<number, Uint8Array>;
const PSK_ID = enc.encode("blox/v1/bind");

function aad(recipientInbox: Uint8Array) {
  return concat(enc.encode("blox/v1"), recipientInbox);
}

export interface Envelope {
  kind: number;
  spk: Uint8Array;
  enc: Uint8Array;
  ct: Uint8Array;
}

export function parseEnvelope(bytes: Uint8Array): Envelope {
  if (bytes.length < 82 || bytes[0] !== VERSION || (bytes[1] !== 1 && bytes[1] !== 2)) throw new Error("envelope");
  return { kind: bytes[1], spk: bytes.slice(2, 34), enc: bytes.slice(34, 66), ct: bytes.slice(66) };
}

export async function sealMessage(
  backend: Backend,
  sender: KemKey,
  recipient: PartyKeys,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const { enc: e, ct } = await sealAuth(backend, sender, recipient.kem, INFO[KIND_MESSAGE], aad(recipient.sig), pad(plaintext));
  return concat(new Uint8Array([VERSION, KIND_MESSAGE]), sender.publicKey, e, ct);
}

export async function openMessage(recipient: KemKey, recipientInbox: Uint8Array, senderKem: Uint8Array, bytes: Uint8Array) {
  const env = parseEnvelope(bytes);
  if (env.kind !== KIND_MESSAGE || !equal(env.spk, senderKem)) throw new Error("not from the peer");
  return unpad(await openAuth(recipient, senderKem, env.enc, INFO[KIND_MESSAGE], aad(recipientInbox), env.ct));
}

/** Opens `bind` with the PSK; the sender key is the envelope's `spk` (checked by the caller). */
export async function openBind(recipient: KemKey, recipientInbox: Uint8Array, psk: Uint8Array, bytes: Uint8Array) {
  const env = parseEnvelope(bytes);
  if (env.kind !== KIND_BIND) throw new Error("expected bind");
  const pt = await openAuth(recipient, env.spk, env.enc, INFO[KIND_BIND], aad(recipientInbox), env.ct, { psk, pskId: PSK_ID });
  return { spk: env.spk, plaintext: unpad(pt) };
}

/** Seals `bind` as a keystore would (tests and tools). */
export async function sealBind(backend: Backend, sender: KemKey, recipient: PartyKeys, psk: Uint8Array, plaintext: Uint8Array) {
  const { enc: e, ct } = await sealAuth(backend, sender, recipient.kem, INFO[KIND_BIND], aad(recipient.sig), pad(plaintext), {
    psk,
    pskId: PSK_ID,
  });
  return concat(new Uint8Array([VERSION, KIND_BIND]), sender.publicKey, e, ct);
}

// ---- offer (§5.1) --------------------------------------------------------------------

export const MAX_LABEL = 32;

export function truncateLabel(label: string): string {
  const bytes = enc.encode(label);
  if (bytes.length <= MAX_LABEL) return label;
  let cut = MAX_LABEL;
  while (cut > 0 && (bytes[cut] & 0xc0) === 0x80) cut--;
  return dec.decode(bytes.slice(0, cut));
}

export function offerUri(relay: string, requester: PartyKeys, ticket: Uint8Array, psk: Uint8Array, label: string): string {
  const r = enc.encode(toQrField(relay));
  const l = enc.encode(truncateLabel(label));
  const payload = concat(
    new Uint8Array([VERSION]),
    requester.sig,
    requester.kem,
    ticket,
    psk,
    new Uint8Array([r.length]),
    r,
    new Uint8Array([l.length]),
    l,
  );
  const uri = "BLOX:" + base45(payload);
  payload.fill(0); // held the PSK
  return uri;
}

// ---- statement (§5.2) ----------------------------------------------------------------

export function iso8601(ts: number): string {
  return new Date(ts * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function parseIso8601(s: string): number | null {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(s)) return null;
  const ms = Date.parse(s);
  if (Number.isNaN(ms) || iso8601(ms / 1000) !== s) return null;
  return ms / 1000;
}

export interface StatementFields {
  label: string;
  requester: Uint8Array;
  keystore: Uint8Array;
  account: string;
  ticket: Uint8Array;
  relay: string;
  issuedAt: number;
  expiresAt: number;
}

export function renderStatement(f: StatementFields): string {
  return [
    "Blox connection",
    `Site: ${f.label} (claimed)`,
    `Site key: ${b64(f.requester)}`,
    `Keystore key: ${b64(f.keystore)}`,
    `Account: ${f.account}`,
    `Nonce: ${b64(f.ticket)}`,
    `Relay: ${f.relay}`,
    `Issued: ${iso8601(f.issuedAt)}`,
    `Expires: ${iso8601(f.expiresAt)}`,
  ].join("\n");
}

export function statementField(text: string, name: string): string | null {
  for (const line of text.split("\n")) if (line.startsWith(name + ": ")) return line.slice(name.length + 2);
  return null;
}

// ---- messages (§4.6, §6) -------------------------------------------------------------

export interface SignRequest {
  chain: string;
  kind: string;
  payload: unknown;
  origin?: { name?: string; url?: string };
  expires_at: number;
}

export type RejectReason = "user" | "expired" | "unsupported" | "decode_failed" | "no_endpoint" | "would_fail";

export type SignResponse =
  | { status: "sent"; account: string; tx_hash: string }
  | { status: "signed_tx"; account: string; tx_hash: string; raw: string }
  | { status: "signed"; account: string; signature: string }
  | { status: "failed"; account: string; tx_hash: string; error: string }
  | { status: "rejected"; reason: RejectReason };

export type Body =
  | { type: "bind"; body: { token: string; account: string; statement: string; signature: string } }
  | { type: "bound"; body: { token: string } }
  | { type: "sign_request"; body: SignRequest }
  | { type: "sign_response"; body: SignResponse }
  | { type: "cancel"; body: Record<string, never> }
  | { type: "unbind"; body: Record<string, never> };

export type Message = { id: string; ts: number; re?: string } & Body;

export function newMessage(body: Body, ts: number, re?: string): Message {
  return { id: b64(randomBytes(16)), ts, ...(re ? { re } : {}), ...body } as Message;
}

export function encodeMessage(m: Message): Uint8Array {
  return enc.encode(JSON.stringify(m));
}

export function decodeMessage(b: Uint8Array): Message {
  return JSON.parse(dec.decode(b)) as Message;
}

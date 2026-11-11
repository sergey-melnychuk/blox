/**
 * EVM checks for the requester (BLOX.md §9.5): EIP-191 and EIP-712 hashing, transaction
 * decoding, signer recovery, and the connection statement's signature (§5.3).
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { concat, enc, equal, fromHex, toHex } from "./bytes.ts";
import type { SignRequest, SignResponse } from "./wire.ts";

export const keccak = (b: Uint8Array) => keccak_256(b);

export function checksum(address: string): string {
  const a = address.toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{40}$/.test(a)) throw new Error("address");
  const h = toHex(keccak(enc.encode(a))).slice(2);
  return "0x" + Array.from(a, (c, i) => (parseInt(h[i], 16) >= 8 ? c.toUpperCase() : c)).join("");
}

export function eip191Hash(message: Uint8Array): Uint8Array {
  return keccak(concat(enc.encode(`\x19Ethereum Signed Message:\n${message.length}`), message));
}

/** Recovers the address from a 65-byte r‖s‖v signature over `hash` (v = 27/28 or 0/1). */
export function recoverAddress(hash: Uint8Array, sig: Uint8Array): string {
  if (sig.length !== 65) throw new Error("signature length");
  const v = sig[64] >= 27 ? sig[64] - 27 : sig[64];
  return recoverWithParity(hash, sig.slice(0, 32), sig.slice(32, 64), v);
}

function recoverWithParity(hash: Uint8Array, r: Uint8Array, s: Uint8Array, parity: number): string {
  if (parity !== 0 && parity !== 1) throw new Error("recovery id");
  const pub = secp256k1.Signature.fromCompact(concat(pad32(r), pad32(s))).addRecoveryBit(parity).recoverPublicKey(hash)
    .toRawBytes(false);
  return checksum(toHex(keccak(pub.slice(1)).slice(12)));
}

function pad32(b: Uint8Array): Uint8Array {
  if (b.length > 32) throw new Error("scalar");
  const out = new Uint8Array(32);
  out.set(b, 32 - b.length);
  return out;
}

// ---- EIP-712 -------------------------------------------------------------------------

type Field = { name: string; type: string };
type Types = Record<string, Field[]>;
export interface TypedData {
  types: Types;
  primaryType: string;
  domain: Record<string, unknown>;
  message: Record<string, unknown>;
}

const DOMAIN_FIELDS: Field[] = [
  { name: "name", type: "string" },
  { name: "version", type: "string" },
  { name: "chainId", type: "uint256" },
  { name: "verifyingContract", type: "address" },
  { name: "salt", type: "bytes32" },
];

function deps(types: Types, primary: string, found = new Set<string>()): Set<string> {
  const base = primary.replace(/\[.*$/, "");
  if (found.has(base) || !types[base]) return found;
  found.add(base);
  for (const f of types[base]) deps(types, f.type, found);
  return found;
}

function encodeType(types: Types, primary: string): string {
  const d = [...deps(types, primary)].filter((t) => t !== primary).sort();
  return [primary, ...d].map((t) => `${t}(${types[t].map((f) => `${f.type} ${f.name}`).join(",")})`).join("");
}

function toBigInt(v: unknown): bigint {
  if (typeof v === "bigint") return v;
  if (typeof v === "number") return BigInt(v);
  if (typeof v === "string") return BigInt(v);
  throw new Error("number");
}

function word(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let x = n < 0n ? (1n << 256n) + n : n;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function encodeValue(types: Types, type: string, value: unknown): Uint8Array {
  if (type.endsWith("]")) {
    const inner = type.slice(0, type.lastIndexOf("["));
    const items = value as unknown[];
    return keccak(concat(...items.map((v) => encodeValue(types, inner, v))));
  }
  if (types[type]) return hashStruct(types, type, value as Record<string, unknown>);
  if (type === "string") return keccak(enc.encode(value as string));
  if (type === "bytes") return keccak(typeof value === "string" ? fromHex(value) : (value as Uint8Array));
  if (type === "bool") return word(value === true || value === "true" ? 1n : 0n);
  if (type === "address") return word(BigInt(value as string));
  if (/^u?int\d*$/.test(type)) return word(toBigInt(value));
  if (/^bytes\d+$/.test(type)) {
    const b = typeof value === "string" ? fromHex(value) : (value as Uint8Array);
    const out = new Uint8Array(32);
    out.set(b);
    return out;
  }
  throw new Error(`EIP-712 type ${type}`);
}

function hashStruct(types: Types, primary: string, data: Record<string, unknown>): Uint8Array {
  const fields = types[primary];
  return keccak(concat(
    keccak(enc.encode(encodeType(types, primary))),
    ...fields.map((f) => encodeValue(types, f.type, data[f.name])),
  ));
}

export function eip712Hash(td: TypedData): Uint8Array {
  const types: Types = { ...td.types };
  if (!types.EIP712Domain) types.EIP712Domain = DOMAIN_FIELDS.filter((f) => td.domain[f.name] !== undefined);
  const domainHash = hashStruct(types, "EIP712Domain", td.domain);
  if (td.primaryType === "EIP712Domain") return keccak(concat(new Uint8Array([0x19, 0x01]), domainHash));
  return keccak(concat(new Uint8Array([0x19, 0x01]), domainHash, hashStruct(types, td.primaryType, td.message)));
}

// ---- RLP and transactions ------------------------------------------------------------

type Rlp = Uint8Array | Rlp[];

function rlpDecode(b: Uint8Array): Rlp {
  const [item, end] = rlpItem(b, 0);
  if (end !== b.length) throw new Error("rlp trailing bytes");
  return item;
}

function rlpItem(b: Uint8Array, at: number): [Rlp, number] {
  const p = b[at];
  if (p === undefined) throw new Error("rlp");
  const len = (n: number, off: number) => {
    let l = 0;
    for (let i = 0; i < n; i++) l = l * 256 + b[off + i];
    return l;
  };
  if (p < 0x80) return [b.slice(at, at + 1), at + 1];
  if (p < 0xb8) return [b.slice(at + 1, at + 1 + p - 0x80), at + 1 + p - 0x80];
  if (p < 0xc0) {
    const n = p - 0xb7, l = len(n, at + 1), start = at + 1 + n;
    return [b.slice(start, start + l), start + l];
  }
  const [start, end] = p < 0xf8
    ? [at + 1, at + 1 + p - 0xc0]
    : [at + 1 + (p - 0xf7), at + 1 + (p - 0xf7) + len(p - 0xf7, at + 1)];
  const items: Rlp[] = [];
  let i = start;
  while (i < end) {
    const [item, next] = rlpItem(b, i);
    items.push(item);
    i = next;
  }
  if (i !== end || end > b.length) throw new Error("rlp");
  return [items, end];
}

function rlpEncode(x: Rlp): Uint8Array {
  const header = (base: number, l: number) => {
    if (l < 56) return new Uint8Array([base + l]);
    const bytes: number[] = [];
    for (let n = l; n > 0; n = Math.floor(n / 256)) bytes.unshift(n % 256);
    return new Uint8Array([base + 55 + bytes.length, ...bytes]);
  };
  if (x instanceof Uint8Array) {
    if (x.length === 1 && x[0] < 0x80) return x;
    return concat(header(0x80, x.length), x);
  }
  const body = concat(...x.map(rlpEncode));
  return concat(header(0xc0, body.length), body);
}

function asBytes(x: Rlp): Uint8Array {
  if (!(x instanceof Uint8Array)) throw new Error("rlp field");
  return x;
}

function asBig(x: Rlp): bigint {
  const b = asBytes(x);
  return b.length ? BigInt(toHex(b)) : 0n;
}

function minimal(n: bigint): Uint8Array {
  return n === 0n ? new Uint8Array(0) : fromHex(n.toString(16).padStart(n.toString(16).length + (n.toString(16).length % 2), "0"));
}

export interface DecodedTx {
  type: 0 | 2;
  chainId: bigint;
  to: string | null;
  value: bigint;
  data: Uint8Array;
  from: string;
  hash: string;
}

/** Decodes a signed legacy (EIP-155) or type-2 transaction and recovers its sender. */
export function decodeSignedTx(raw: Uint8Array): DecodedTx {
  const hash = toHex(keccak(raw));
  if (raw[0] === 0x02) {
    const f = rlpDecode(raw.slice(1)) as Rlp[];
    if (!Array.isArray(f) || f.length !== 12) throw new Error("type 2 fields");
    const unsigned = concat(new Uint8Array([0x02]), rlpEncode(f.slice(0, 9)));
    const from = recoverWithParity(keccak(unsigned), asBytes(f[10]), asBytes(f[11]), Number(asBig(f[9])));
    const to = asBytes(f[5]);
    return { type: 2, chainId: asBig(f[0]), to: to.length ? checksum(toHex(to)) : null, value: asBig(f[6]), data: asBytes(f[7]), from, hash };
  }
  if (raw[0] >= 0xc0) {
    const f = rlpDecode(raw) as Rlp[];
    if (!Array.isArray(f) || f.length !== 9) throw new Error("legacy fields");
    const v = asBig(f[6]);
    if (v < 35n) throw new Error("legacy transaction without EIP-155");
    const chainId = (v - 35n) / 2n;
    const parity = Number((v - 35n) % 2n);
    const unsigned = rlpEncode([...f.slice(0, 6), minimal(chainId), new Uint8Array(0), new Uint8Array(0)]);
    const from = recoverWithParity(keccak(unsigned), asBytes(f[7]), asBytes(f[8]), parity);
    const to = asBytes(f[3]);
    return { type: 0, chainId, to: to.length ? checksum(toHex(to)) : null, value: asBig(f[4]), data: asBytes(f[5]), from, hash };
  }
  throw new Error("transaction type");
}

// ---- checks --------------------------------------------------------------------------

/** The account's EIP-191 signature on the connection statement (§5.3). */
export function verifyStatement(statement: string, signature: string, account: string): boolean {
  try {
    if (checksum(account) !== account) return false;
    return recoverAddress(eip191Hash(enc.encode(statement)), fromHex(signature)) === account;
  } catch {
    return false;
  }
}

/** §9.5: checks an answer against its request and the connection's account. Throws on failure. */
export function checkResponse(req: SignRequest, resp: SignResponse, account: string): void {
  if (resp.status === "rejected") return;
  const chainId = BigInt(req.chain.replace(/^eip155:/, ""));
  if (resp.account !== `${req.chain}:${account}`) throw new Error("response names another account");
  const p = req.payload as Record<string, unknown>;
  switch (resp.status) {
    case "sent":
    case "failed":
      if (req.kind !== "evm.send") throw new Error("response kind");
      if (!/^0x[0-9a-fA-F]{64}$/.test(resp.tx_hash)) throw new Error("tx_hash");
      return;
    case "signed_tx": {
      if (req.kind !== "evm.sign_tx") throw new Error("response kind");
      const tx = decodeSignedTx(fromHex(resp.raw));
      const wantTo = p.to === null || p.to === undefined ? null : checksum(p.to as string);
      if (tx.chainId !== chainId) throw new Error("chain id differs");
      if (tx.to !== wantTo || tx.value !== BigInt((p.value as string) ?? "0x0") || !equal(tx.data, fromHex((p.data as string) ?? "0x"))) {
        throw new Error("transaction differs from the request");
      }
      if (tx.from !== account) throw new Error("signed by another account");
      if (tx.hash.toLowerCase() !== resp.tx_hash.toLowerCase()) throw new Error("tx_hash differs");
      return;
    }
    case "signed": {
      let hash: Uint8Array;
      if (req.kind === "evm.personal_sign") hash = eip191Hash(fromHex(p.message as string));
      else if (req.kind === "evm.typed_data") hash = eip712Hash(p.data as TypedData);
      else throw new Error("response kind");
      if (recoverAddress(hash, fromHex(resp.signature)) !== account) throw new Error("signed by another account");
      return;
    }
  }
}

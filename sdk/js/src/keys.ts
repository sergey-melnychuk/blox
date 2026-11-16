/**
 * Connection keys (BLOX.md §2.1, §9.6): `S` (Ed25519) and `s` (X25519), behind two backends.
 *
 * - **webcrypto** (browsers): non-extractable `CryptoKey`s, stored as such in IndexedDB.
 *   Script on the page can use them but never read their bytes. Where the browser can't store
 *   an X25519 `CryptoKey` (WebKit: Safari and every iOS browser), `s` is kept sealed instead
 *   (BLOX.md §9.6).
 * - **raw** (Node, Deno, servers): `@noble/curves` with the secrets as bytes, stored in a
 *   file or a store the caller provides. A backend's connection is as safe as the backend.
 *
 * Browsers must have WebCrypto Ed25519 and X25519; there is no fallback to raw keys there.
 */

import { ed25519, x25519 } from "@noble/curves/ed25519";
import { own, randomBytes } from "./bytes.ts";

export interface SigKey {
  readonly publicKey: Uint8Array;
  sign(msg: Uint8Array): Promise<Uint8Array>;
}

export interface KemKey {
  readonly publicKey: Uint8Array;
  /** X25519(secret, peer). */
  dh(peer: Uint8Array): Promise<Uint8Array>;
}

/** What a store keeps for one key. */
export type StoredKey =
  | { kind: "webcrypto"; key: CryptoKey; pub: Uint8Array }
  /** X25519 as PKCS #8, wrapped with AES-GCM under `aes` (a non-extractable key). */
  | { kind: "sealed"; aes: CryptoKey; iv: Uint8Array; wrapped: Uint8Array; pub: Uint8Array }
  | { kind: "raw"; secret: Uint8Array; pub: Uint8Array };

export interface Backend {
  readonly name: "webcrypto" | "raw";
  newSigKey(): Promise<{ key: SigKey; stored: StoredKey }>;
  newKemKey(): Promise<{ key: KemKey; stored: StoredKey }>;
  /** An ephemeral X25519 key for one HPKE encapsulation. */
  ephemeral(): Promise<KemKey>;
}

export class UnsupportedBrowser extends Error {
  constructor() {
    super("this browser lacks WebCrypto Ed25519 or X25519");
  }
}

// ---- raw ----------------------------------------------------------------------------

export function rawSigKey(secret: Uint8Array): SigKey {
  const pub = ed25519.getPublicKey(secret);
  return { publicKey: pub, sign: (m) => Promise.resolve(ed25519.sign(m, secret)) };
}

export function rawKemKey(secret: Uint8Array): KemKey {
  const pub = x25519.getPublicKey(secret);
  return { publicKey: pub, dh: (peer) => Promise.resolve(x25519.getSharedSecret(secret, peer)) };
}

export const rawBackend: Backend = {
  name: "raw",
  newSigKey() {
    const secret = randomBytes(32);
    const key = rawSigKey(secret);
    return Promise.resolve({ key, stored: { kind: "raw", secret, pub: key.publicKey } });
  },
  newKemKey() {
    const secret = randomBytes(32);
    const key = rawKemKey(secret);
    return Promise.resolve({ key, stored: { kind: "raw", secret, pub: key.publicKey } });
  },
  ephemeral() {
    return Promise.resolve(rawKemKey(randomBytes(32)));
  },
};

// ---- webcrypto ----------------------------------------------------------------------

function webSigKey(key: CryptoKey, pub: Uint8Array): SigKey {
  return {
    publicKey: pub,
    sign: async (m) => new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, own(m))),
  };
}

function webKemKey(key: CryptoKey | Promise<CryptoKey>, pub: Uint8Array): KemKey {
  return {
    publicKey: pub,
    dh: async (peer) => {
      const p = await crypto.subtle.importKey("raw", own(peer), { name: "X25519" }, true, []);
      return new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: p }, await key, 256));
    },
  };
}

// WebKit can't structured-clone an X25519 `CryptoKey` (Safari 27: "Unable to deserialize
// data"), so IndexedDB can't store one: `put` fails with a DataError, or the key reads back
// missing. AES keys do store. There, `s` is generated extractable, wrapped under a fresh
// non-extractable AES-GCM key, and used through a non-extractable copy unwrapped from that.

let clones: Promise<boolean> | undefined;
/** True if this browser can store an X25519 `CryptoKey` (structured clone keeps it). */
function x25519Clones(): Promise<boolean> {
  return clones ??= (async () => {
    try {
      const { priv } = await generate("X25519", false);
      return (structuredClone(priv) as CryptoKey | undefined)?.algorithm?.name === "X25519";
    } catch {
      return false;
    }
  })();
}

const SEAL = "pkcs8";

function unseal(s: { aes: CryptoKey; iv: Uint8Array; wrapped: Uint8Array }): Promise<CryptoKey> {
  return crypto.subtle.unwrapKey(SEAL, own(s.wrapped), s.aes, { name: "AES-GCM", iv: own(s.iv) }, {
    name: "X25519",
  }, false, ["deriveBits"]);
}

/** A KEM key stored sealed: what browsers that can't store X25519 keys use (and tests). */
export async function newSealedKemKey(): Promise<{ key: KemKey; stored: StoredKey }> {
  const { priv, pub } = await generate("X25519", true);
  const aes = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["wrapKey", "unwrapKey"]);
  const iv = randomBytes(12);
  const wrapped = new Uint8Array(await crypto.subtle.wrapKey(SEAL, priv, aes, { name: "AES-GCM", iv: own(iv) }));
  const stored: StoredKey = { kind: "sealed", aes, iv, wrapped, pub };
  return { key: webKemKey(await unseal(stored), pub), stored };
}

async function generate(alg: "Ed25519" | "X25519", extractable: boolean): Promise<{ priv: CryptoKey; pub: Uint8Array }> {
  const usages: KeyUsage[] = alg === "Ed25519" ? ["sign", "verify"] : ["deriveBits"];
  const pair = (await crypto.subtle.generateKey({ name: alg }, extractable, usages)) as CryptoKeyPair;
  // For a key pair, `extractable` applies to the private key; the public key always exports.
  const pub = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return { priv: pair.privateKey, pub };
}

export const webcryptoBackend: Backend = {
  name: "webcrypto",
  async newSigKey() {
    const { priv, pub } = await generate("Ed25519", false);
    return { key: webSigKey(priv, pub), stored: { kind: "webcrypto", key: priv, pub } };
  },
  async newKemKey() {
    if (!(await x25519Clones())) return newSealedKemKey();
    const { priv, pub } = await generate("X25519", false);
    return { key: webKemKey(priv, pub), stored: { kind: "webcrypto", key: priv, pub } };
  },
  async ephemeral() {
    const { priv, pub } = await generate("X25519", false);
    return webKemKey(priv, pub);
  },
};

/** Rebuilds a usable key from what a store kept. */
export function sigKeyFrom(s: StoredKey): SigKey {
  if (s.kind === "sealed") throw new Error("a sealed key is X25519");
  return s.kind === "raw" ? rawSigKey(s.secret) : webSigKey(s.key, s.pub);
}

export function kemKeyFrom(s: StoredKey): KemKey {
  if (s.kind === "sealed") {
    const key = unseal(s);
    key.catch(() => {}); // a failure surfaces from dh()
    return webKemKey(key, s.pub);
  }
  return s.kind === "raw" ? rawKemKey(s.secret) : webKemKey(s.key, s.pub);
}

/** False for a key that didn't survive storage (a browser that read it back without one). */
export function storedKeyOk(s: StoredKey | undefined): boolean {
  if (!s?.pub) return false;
  if (s.kind === "raw") return !!s.secret;
  if (s.kind === "sealed") return !!s.aes && !!s.wrapped && !!s.iv;
  return !!s.key;
}

/** True if WebCrypto has working Ed25519 and X25519 here. */
export async function webcryptoWorks(): Promise<boolean> {
  try {
    const a = await webcryptoBackend.newKemKey();
    const b = await webcryptoBackend.newKemKey();
    const s = await webcryptoBackend.newSigKey();
    await s.key.sign(new Uint8Array([1]));
    const x = await a.key.dh(b.key.publicKey);
    return x.length === 32;
  } catch {
    return false;
  }
}

/** Browsers: WebCrypto or fail. Elsewhere: WebCrypto if it works, else raw keys. */
export async function chooseBackend(): Promise<Backend> {
  const browser = typeof (globalThis as { document?: unknown }).document !== "undefined";
  if (await webcryptoWorks()) return browser ? webcryptoBackend : rawBackend;
  if (browser) throw new UnsupportedBrowser();
  return rawBackend;
}

/** Strict Ed25519 verification (RFC 8032, no ZIP-215 leniency). */
export function verifyEd25519(sig: Uint8Array, msg: Uint8Array, pub: Uint8Array): boolean {
  try {
    return ed25519.verify(sig, msg, pub, { zip215: false });
  } catch {
    return false;
  }
}

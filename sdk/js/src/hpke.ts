/**
 * HPKE (RFC 9180), the one suite Blox uses (BLOX.md §4.1): DHKEM(X25519, HKDF-SHA256),
 * HKDF-SHA256, AES-256-GCM; modes `auth` (0x02) and `auth_psk` (0x03); single-shot.
 *
 * The X25519 operations go through `KemKey`, so the long-term secret can stay inside a
 * non-extractable WebCrypto key. Derived values (DH outputs, the key schedule) pass through
 * JS memory during a call (§9.6).
 */

import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { concat, enc, own, u16be } from "./bytes.ts";
import type { Backend, KemKey } from "./keys.ts";

const KEM_ID = 0x0020;
const KDF_ID = 0x0001;
const AEAD_ID = 0x0002;
const SUITE_KEM = concat(enc.encode("KEM"), u16be(KEM_ID));
const SUITE = concat(enc.encode("HPKE"), u16be(KEM_ID), u16be(KDF_ID), u16be(AEAD_ID));
const V1 = enc.encode("HPKE-v1");

function extract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  return hmac(sha256, salt.length ? salt : new Uint8Array(32), ikm);
}

function expand(prk: Uint8Array, info: Uint8Array, len: number): Uint8Array {
  const out = new Uint8Array(len);
  let t: Uint8Array = new Uint8Array(0);
  for (let i = 1, at = 0; at < len; i++) {
    t = hmac(sha256, prk, concat(t, info, new Uint8Array([i])));
    out.set(t.slice(0, Math.min(t.length, len - at)), at);
    at += t.length;
  }
  return out;
}

function labeledExtract(suite: Uint8Array, salt: Uint8Array, label: string, ikm: Uint8Array) {
  return extract(salt, concat(V1, suite, enc.encode(label), ikm));
}

function labeledExpand(suite: Uint8Array, prk: Uint8Array, label: string, info: Uint8Array, len: number) {
  return expand(prk, concat(u16be(len), V1, suite, enc.encode(label), info), len);
}

/** RFC 9180 DeriveKeyPair for X25519: the secret from `ikm` (test vectors). */
export function deriveSecret(ikm: Uint8Array): Uint8Array {
  const prk = labeledExtract(SUITE_KEM, new Uint8Array(0), "dkp_prk", ikm);
  return labeledExpand(SUITE_KEM, prk, "sk", new Uint8Array(0), 32);
}

function sharedSecret(dh: Uint8Array, kemContext: Uint8Array): Uint8Array {
  const prk = labeledExtract(SUITE_KEM, new Uint8Array(0), "eae_prk", dh);
  return labeledExpand(SUITE_KEM, prk, "shared_secret", kemContext, 32);
}

function keySchedule(mode: number, shared: Uint8Array, info: Uint8Array, psk: Uint8Array, pskId: Uint8Array) {
  const pskIdHash = labeledExtract(SUITE, new Uint8Array(0), "psk_id_hash", pskId);
  const infoHash = labeledExtract(SUITE, new Uint8Array(0), "info_hash", info);
  const ctx = concat(new Uint8Array([mode]), pskIdHash, infoHash);
  const secret = labeledExtract(SUITE, shared, "secret", psk);
  return {
    key: labeledExpand(SUITE, secret, "key", ctx, 32),
    nonce: labeledExpand(SUITE, secret, "base_nonce", ctx, 12),
  };
}

async function aes(op: "encrypt" | "decrypt", key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, data: Uint8Array) {
  const k = await crypto.subtle.importKey("raw", own(key), { name: "AES-GCM" }, false, [op]);
  const params = { name: "AES-GCM", iv: own(nonce), additionalData: own(aad), tagLength: 128 };
  return new Uint8Array(
    op === "encrypt" ? await crypto.subtle.encrypt(params, k, own(data)) : await crypto.subtle.decrypt(params, k, own(data)),
  );
}

export interface PskInput {
  psk: Uint8Array;
  pskId: Uint8Array;
}

/** Seals `pt` from `sender` to `recipientPub` (mode auth, or auth_psk when `psk` is given). */
export async function sealAuth(
  backend: Backend,
  sender: KemKey,
  recipientPub: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  pt: Uint8Array,
  psk?: PskInput,
): Promise<{ enc: Uint8Array; ct: Uint8Array }> {
  const eph = await backend.ephemeral();
  const dh = concat(await eph.dh(recipientPub), await sender.dh(recipientPub));
  const encapped = eph.publicKey;
  const shared = sharedSecret(dh, concat(encapped, recipientPub, sender.publicKey));
  const mode = psk ? 0x03 : 0x02;
  const { key, nonce } = keySchedule(mode, shared, info, psk?.psk ?? new Uint8Array(0), psk?.pskId ?? new Uint8Array(0));
  return { enc: encapped, ct: await aes("encrypt", key, nonce, aad, pt) };
}

/** Opens what [sealAuth] produced, authenticating `senderPub`. Throws on any mismatch. */
export async function openAuth(
  recipient: KemKey,
  senderPub: Uint8Array,
  encapped: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  ct: Uint8Array,
  psk?: PskInput,
): Promise<Uint8Array> {
  const dh = concat(await recipient.dh(encapped), await recipient.dh(senderPub));
  const shared = sharedSecret(dh, concat(encapped, recipient.publicKey, senderPub));
  const mode = psk ? 0x03 : 0x02;
  const { key, nonce } = keySchedule(mode, shared, info, psk?.psk ?? new Uint8Array(0), psk?.pskId ?? new Uint8Array(0));
  return await aes("decrypt", key, nonce, aad, ct);
}

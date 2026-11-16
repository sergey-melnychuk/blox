// Seal → open in TypeScript, for both envelope kinds and both key backends.
import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import { enc } from "../src/bytes.ts";
import {
  type Backend,
  kemKeyFrom,
  newSealedKemKey,
  rawBackend,
  type StoredKey,
  storedKeyOk,
  webcryptoBackend,
  webcryptoWorks,
} from "../src/keys.ts";
import { openBind, openMessage, sealBind, sealMessage } from "../src/wire.ts";

async function roundtrip(backend: Backend) {
  const a = await backend.newKemKey();
  const b = await backend.newKemKey();
  const aSig = await backend.newSigKey();
  const bSig = await backend.newSigKey();
  const bParty = { sig: bSig.key.publicKey, kem: b.key.publicKey };
  const msg = await sealMessage(backend, a.key, bParty, enc.encode("hello"));
  assertEquals(new TextDecoder().decode(await openMessage(b.key, bSig.key.publicKey, a.key.publicKey, msg)), "hello");
  // Bound to the recipient's inbox, and to the sender.
  await assertRejects(() => openMessage(b.key, aSig.key.publicKey, a.key.publicKey, msg));
  const flipped = msg.slice();
  flipped[100] ^= 1;
  await assertRejects(() => openMessage(b.key, bSig.key.publicKey, a.key.publicKey, flipped));
  const psk = crypto.getRandomValues(new Uint8Array(32));
  const bind = await sealBind(backend, a.key, bParty, psk, enc.encode("bind"));
  const opened = await openBind(b.key, bSig.key.publicKey, psk, bind);
  assertEquals(new TextDecoder().decode(opened.plaintext), "bind");
  await assertRejects(() => openBind(b.key, bSig.key.publicKey, new Uint8Array(32), bind));
}

Deno.test("raw backend", () => roundtrip(rawBackend));

Deno.test("webcrypto backend (when this runtime's X25519 works)", async () => {
  if (!(await webcryptoWorks())) {
    console.log("skipping: WebCrypto X25519 is broken in this runtime");
    return;
  }
  await roundtrip(webcryptoBackend);
  const k = await webcryptoBackend.newSigKey();
  assert(k.stored.kind === "webcrypto");
  await assertRejects(() => crypto.subtle.exportKey("pkcs8", (k.stored as { key: CryptoKey }).key));
});

Deno.test("sealed KEM key (WebKit, which can't store X25519 keys): stores, reloads, agrees", async () => {
  if (!(await webcryptoWorks())) {
    console.log("skipping: WebCrypto X25519 is broken in this runtime");
    return;
  }
  const k = await newSealedKemKey();
  assert(k.stored.kind === "sealed");
  // What IndexedDB does to the record: a structured clone.
  const stored = structuredClone(k.stored) as Extract<StoredKey, { kind: "sealed" }>;
  assert(storedKeyOk(stored));
  await assertRejects(() => crypto.subtle.exportKey("raw", stored.aes));
  const reloaded = kemKeyFrom(stored);
  const peer = await webcryptoBackend.ephemeral();
  assertEquals(await reloaded.dh(peer.publicKey), await peer.dh(k.key.publicKey));
  assertEquals(await k.key.dh(peer.publicKey), await peer.dh(k.key.publicKey));
  // Wrong AES key: dh fails, nothing throws earlier.
  const other = await newSealedKemKey();
  const bad = kemKeyFrom({ ...stored, aes: (other.stored as typeof stored).aes });
  await assertRejects(() => bad.dh(peer.publicKey));
});

Deno.test("a stored key that came back without its key material is not ok", () => {
  const pub = new Uint8Array(32);
  assert(!storedKeyOk(undefined));
  assert(!storedKeyOk({ kind: "webcrypto", pub } as unknown as StoredKey));
  assert(!storedKeyOk({ kind: "sealed", pub } as unknown as StoredKey));
  assert(storedKeyOk({ kind: "raw", pub, secret: new Uint8Array(32) }));
});

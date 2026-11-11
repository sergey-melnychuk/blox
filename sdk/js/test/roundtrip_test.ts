// Seal → open in TypeScript, for both envelope kinds and both key backends.
import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import { enc } from "../src/bytes.ts";
import { type Backend, rawBackend, webcryptoWorks, webcryptoBackend } from "../src/keys.ts";
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

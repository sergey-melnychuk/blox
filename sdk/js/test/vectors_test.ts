// The TypeScript SDK against test-vectors/proto-v1.json (BLOX.md §4.1, §13.1).
import { assert, assertEquals } from "jsr:@std/assert@1";
import { b64, unb64 } from "../src/b64.ts";
import { base45, unbase45 } from "../src/base45.ts";
import { dec, enc, fromHex } from "../src/bytes.ts";
import { deriveSecret } from "../src/hpke.ts";
import { rawKemKey, rawSigKey } from "../src/keys.ts";
import { pad, unpad } from "../src/pad.ts";
import { normalizeRelay, toQrField } from "../src/relayUrl.ts";
import { offerUri, openBind, openMessage, renderStatement, signRequest, Token } from "../src/wire.ts";

const V = JSON.parse(await Deno.readTextFile(new URL("../../../test-vectors/proto-v1.json", import.meta.url)));
const k = V.keys;

const S = rawSigKey(unb64(k.requester_sig_secret));
const K = rawSigKey(unb64(k.keystore_sig_secret));
const s = rawKemKey(deriveSecret(enc.encode(k.requester_kem_ikm_utf8)));
const kk = rawKemKey(deriveSecret(enc.encode(k.keystore_kem_ikm_utf8)));

Deno.test("keys", () => {
  assertEquals(b64(S.publicKey), k.requester_sig);
  assertEquals(b64(K.publicKey), k.keystore_sig);
  assertEquals(b64(s.publicKey), k.requester_kem);
  assertEquals(b64(kk.publicKey), k.keystore_kem);
});

Deno.test("tokens: encoding, signatures, id", async () => {
  const body = {
    requester: { sig: S.publicKey, kem: s.publicKey },
    keystore: { sig: K.publicKey, kem: kk.publicKey },
    issuedAt: V.token.issued_at,
    expiresAt: V.token.expires_at,
    relay: V.token.relay,
  };
  const half = await Token.issue(body, K);
  assertEquals(half.toHeader(), V.token.keystore_signed);
  const full = await half.countersign(S);
  assertEquals(full.toHeader(), V.token.countersigned);
  assertEquals(b64(full.id()), V.token.token_id);
  const parsed = Token.fromHeader(V.token.countersigned);
  assert(parsed.verifyKeystore() && parsed.verifyRequester());
  const bad = unb64(V.token.countersigned);
  bad[bad.length - 1] ^= 1;
  assert(!Token.fromBytes(bad).verifyRequester());
});

Deno.test("request signature", async () => {
  const r = V.request_signature;
  const auth = await signRequest(S, r.method, r.path, r.ts, fromHex(r.body_hex));
  assertEquals(auth, r.authorization);
});

Deno.test("relay urls", () => {
  for (const [input, normalized, qr] of V.relay_urls) {
    assertEquals(normalizeRelay(input), normalized);
    assertEquals(toQrField(normalized), qr);
  }
});

Deno.test("padding and base45", () => {
  for (const p of V.padding) {
    if (p.plaintext_hex === undefined) continue;
    const padded = pad(fromHex(p.plaintext_hex));
    assertEquals(padded.length, p.padded_len);
    assertEquals(unpad(padded), fromHex(p.plaintext_hex));
  }
  assertEquals(base45(enc.encode("Hello!!")), "%69 VD92EX0");
  assertEquals(dec.decode(unbase45("QED8WEX0")), "ietf!");
});

Deno.test("statement", () => {
  const text = renderStatement({
    label: V.statement.label,
    requester: S.publicKey,
    keystore: K.publicKey,
    account: V.statement.account,
    ticket: unb64(k.ticket),
    relay: V.token.relay,
    issuedAt: V.token.issued_at,
    expiresAt: V.token.expires_at,
  });
  assertEquals(text, V.statement.text);
});

Deno.test("envelopes open with the stored keys", async () => {
  for (const e of V.envelopes) {
    const bytes = unb64(e.envelope);
    const pt = e.recipient === "requester"
      ? (await openBind(s, S.publicKey, unb64(k.psk), bytes)).plaintext
      : await openMessage(kk, K.publicKey, s.publicKey, bytes);
    assertEquals(dec.decode(pt), e.plaintext_utf8);
  }
});

Deno.test("offer uri", () => {
  const uri = offerUri(V.token.relay, { sig: S.publicKey, kem: s.publicKey }, unb64(k.ticket), unb64(k.psk), V.offer.label);
  assertEquals(uri, V.offer.uri);
});

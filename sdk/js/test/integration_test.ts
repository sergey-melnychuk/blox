// The TypeScript requester against the Rust relay and mock keystore, with anvil
// (BLOX.md §13.1). Needs `cargo build -p blox-relay -p blox-mock-keystore` first; skips
// with a message when the binaries or anvil are missing.
import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import { Blox, BloxError, MemoryStore, verifyConnection } from "../src/index.ts";
import { rawBackend } from "../src/keys.ts";

import { BOB, rpc, waitFor, type World, world } from "./world.ts";

function blox(w: World, store = new MemoryStore(), extra: Partial<ConstructorParameters<typeof Blox>[0]> = {}) {
  return new Blox({
    name: "Deno test",
    relay: w.relay,
    storage: store,
    backend: rawBackend,
    onQr: (uri) => {
      if (uri) w.writer.write(new TextEncoder().encode(uri + "\n"));
    },
    ...extra,
  });
}

Deno.test({
  name: "connect, every call kind, restart from storage, disconnect",
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const w = await world();
    if (!w) return;
    try {
      const store = new MemoryStore();
      const b = blox(w, store);
      const { account } = await b.connect();
      assertEquals(account, "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

      const sig = await b.personalSign({ chain: 31337, message: "hello" });
      assertEquals(sig.account, account);
      await b.signTypedData({
        chain: 31337,
        data: {
          types: { EIP712Domain: [{ name: "name", type: "string" }, { name: "chainId", type: "uint256" }], Mail: [{ name: "contents", type: "string" }, { name: "n", type: "uint256" }] },
          primaryType: "Mail",
          domain: { name: "Blox", chainId: 31337 },
          message: { contents: "hello", n: 7 },
        },
      });

      const sent = await b.send({ chain: 31337, to: BOB, value: 1000n, data: "0xcafe" });
      await waitFor(async () => !!(await rpc(w.anvil, "eth_getTransactionReceipt", [sent.txHash])), "receipt");
      const tx = await rpc(w.anvil, "eth_getTransactionByHash", [sent.txHash]);
      assertEquals([tx.to, tx.value, tx.input], [BOB, "0x3e8", "0xcafe"]);

      const signed = await b.signTransaction({ chain: 31337, to: BOB, value: 5n });
      assertEquals(await rpc(w.anvil, "eth_sendRawTransaction", [signed.raw]), signed.txHash);

      await assertRejects(
        () => b.send({ chain: 999, to: BOB }),
        BloxError,
        "no_endpoint",
      );

      // A new instance over the same storage needs no QR code.
      const again = blox(w, store, { onQr: (uri) => assert(!uri, "no QR code expected") });
      await again.personalSign({ chain: 31337, message: "again" });

      await b.disconnect();
      // A leftover instance is told the connection has ended.
      const stale = new MemoryStore();
      await stale.save((await (async () => {
        const s2 = new MemoryStore();
        const c = blox(w, s2);
        await c.connect();
        const saved = await s2.load(c.relayUrl);
        await c.disconnect();
        return saved!;
      })()));
      const e = await assertRejects(() => blox(w, stale).personalSign({ chain: 31337, message: "x" }), BloxError);
      assertEquals(e.code, "disconnected");
    } finally {
      await w.stop();
    }
  },
});

Deno.test({
  name: "requesters with wrong clocks; an already expired request times out",
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const w = await world();
    if (!w) return;
    try {
      for (const skew of [600, -600]) {
        const b = blox(w, new MemoryStore(), { localClockSkew: skew });
        await b.connect();
        await b.personalSign({ chain: 31337, message: `skew ${skew}` });
      }
      const b = blox(w);
      await b.connect();
      const e = await assertRejects(
        () => b.request({ chain: "eip155:31337", kind: "evm.personal_sign", payload: { message: "0x01" }, expires_at: 1 }),
        BloxError,
      );
      assertEquals(e.code, "timeout");
    } finally {
      await w.stop();
    }
  },
});

Deno.test({
  name: "server login: connect with a server nonce, verifyConnection",
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const w = await world();
    if (!w) return;
    try {
      const nonce = crypto.getRandomValues(new Uint8Array(16));
      const c = await blox(w).connect({ nonce });
      assert(c.statement && c.signature);
      const proof = { account: c.account, statement: c.statement!, signature: c.signature! };
      assert(verifyConnection(proof, { nonce }));
      assert(!verifyConnection(proof, { nonce: new Uint8Array(16) }), "another nonce");
      assert(!verifyConnection({ ...proof, account: BOB }, { nonce }), "another account");
      assert(!verifyConnection(proof, { nonce, now: Math.floor(Date.now() / 1000) + 600 }), "stale");
    } finally {
      await w.stop();
    }
  },
});

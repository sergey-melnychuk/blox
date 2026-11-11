// The TypeScript requester against the Rust relay and mock keystore, with anvil
// (BLOX.md §13.1). Needs `cargo build -p blox-relay -p blox-mock-keystore` first; skips
// with a message when the binaries or anvil are missing.
import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import { Blox, BloxError, MemoryStore, verifyConnection } from "../src/index.ts";
import { rawBackend } from "../src/keys.ts";

const TARGET = new URL("../../../target/debug/", import.meta.url).pathname;
const HOME = Deno.env.get("HOME") ?? "";
const ANVIL = Deno.env.get("ANVIL") ?? `${HOME}/.foundry/bin/anvil`;
const BOB = "0x4242424242424242424242424242424242424242";

function exists(p: string) {
  try {
    Deno.statSync(p);
    return true;
  } catch {
    return false;
  }
}

function freePort(): number {
  const l = Deno.listen({ hostname: "localhost", port: 0 });
  const port = (l.addr as Deno.NetAddr).port;
  l.close();
  return port;
}

async function waitFor(f: () => Promise<boolean>, what: string) {
  for (let i = 0; i < 100; i++) {
    if (await f().catch(() => false)) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`timed out waiting for ${what}`);
}

async function rpc(url: string, method: string, params: unknown[]) {
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const j = await res.json();
  if (j.error) throw new Error(j.error.message);
  return j.result;
}

interface World {
  relay: string;
  anvil: string;
  keystore: Deno.ChildProcess;
  writer: WritableStreamDefaultWriter<Uint8Array>;
  lines: string[];
  stop(): Promise<void>;
}

async function world(): Promise<World | null> {
  if (!exists(TARGET + "blox-relay") || !exists(TARGET + "blox-mock-keystore") || !exists(ANVIL)) {
    console.log("skipping: build blox-relay and blox-mock-keystore, and install anvil");
    return null;
  }
  const rp = freePort(), ap = freePort();
  const relay = new Deno.Command(TARGET + "blox-relay", { env: { BLOX_LISTEN: `localhost:${rp}` }, stdout: "null", stderr: "null" }).spawn();
  const anvil = new Deno.Command(ANVIL, { args: ["--port", String(ap), "--silent"], stdout: "null", stderr: "null" }).spawn();
  const relayUrl = `http://localhost:${rp}`, anvilUrl = `http://localhost:${ap}`;
  await waitFor(async () => (await fetch(`${relayUrl}/health`)).ok, "relay");
  await waitFor(async () => !!(await rpc(anvilUrl, "eth_chainId", [])), "anvil");
  const keystore = new Deno.Command(TARGET + "blox-mock-keystore", {
    args: ["--endpoint", `31337=${anvilUrl}`],
    stdin: "piped",
    stdout: "piped",
    stderr: "null",
  }).spawn();
  const lines: string[] = [];
  (async () => {
    const dec = new TextDecoder();
    let buf = "";
    for await (const chunk of keystore.stdout) {
      buf += dec.decode(chunk);
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        lines.push(buf.slice(0, i));
        buf = buf.slice(i + 1);
      }
    }
  })();
  await waitFor(() => Promise.resolve(lines.some((l) => l.includes("ready"))), "mock keystore");
  const writer = keystore.stdin.getWriter();
  return {
    relay: relayUrl,
    anvil: anvilUrl,
    keystore,
    writer,
    lines,
    async stop() {
      await writer.close().catch(() => {});
      for (const p of [keystore, relay, anvil]) {
        try {
          p.kill("SIGTERM");
        } catch { /* gone */ }
        await p.status;
      }
    },
  };
}

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

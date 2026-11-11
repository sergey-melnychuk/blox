// The wagmi connector through @wagmi/core against the Rust relay, mock keystore and anvil
// (BLOX.md §9.3, §13.1). Skips when the binaries or anvil are missing.
import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import {
  connect,
  createConfig,
  createStorage,
  disconnect,
  getAccount,
  getChainId,
  http,
  noopStorage,
  reconnect,
  sendTransaction,
  signMessage,
  signTypedData,
  switchChain,
  waitForTransactionReceipt,
} from "@wagmi/core";
import { foundry, mainnet } from "viem/chains";
import { MemoryStore } from "../src/index.ts";
import { rawBackend } from "../src/keys.ts";
import { blox } from "../src/wagmi.ts";
import { BOB, rpc, type World, world } from "./world.ts";

function config(w: World, store: MemoryStore, onQr?: (uri: string | null) => void) {
  return createConfig({
    chains: [foundry, mainnet],
    connectors: [
      blox({
        name: "wagmi test",
        relay: w.relay,
        storage: store,
        backend: rawBackend,
        onQr: onQr ?? ((uri) => {
          if (uri) w.writer.write(new TextEncoder().encode(uri + "\n"));
        }),
      }),
    ],
    transports: { [foundry.id]: http(w.anvil), [mainnet.id]: http(w.anvil) },
    storage: createStorage({ storage: noopStorage }),
  });
}

Deno.test({
  name: "wagmi: connect, sendTransaction, signMessage, signTypedData, switchChain, reconnect",
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const w = await world();
    if (!w) return;
    try {
      const store = new MemoryStore();
      const cfg = config(w, store);
      const res = await connect(cfg, { connector: cfg.connectors[0] });
      assertEquals(res.accounts[0], "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
      assertEquals(res.chainId, foundry.id);

      // The caller's nonce and gas are dropped: the phone fills its own (§9.3).
      const hash = await sendTransaction(cfg, { to: BOB, value: 1234n, data: "0xcafe", nonce: 999, gas: 1_000_000n });
      const receipt = await waitForTransactionReceipt(cfg, { hash });
      assertEquals(receipt.status, "success");
      const tx = await rpc(w.anvil, "eth_getTransactionByHash", [hash]);
      assertEquals([tx.to, tx.value, tx.input, tx.nonce], [BOB, "0x4d2", "0xcafe", "0x0"]);
      assert(BigInt(tx.gas) < 1_000_000n, "the phone's estimate × 1.2, not the caller's gas");

      const sig = await signMessage(cfg, { message: "hello" });
      assertEquals(sig.length, 132);
      await signTypedData(cfg, {
        domain: { name: "Blox", chainId: foundry.id },
        types: { Mail: [{ name: "contents", type: "string" }] },
        primaryType: "Mail",
        message: { contents: "hello" },
      });

      // Switching chain is local; the phone has no endpoint for chain 1 → 4901.
      await switchChain(cfg, { chainId: mainnet.id });
      assertEquals(getChainId(cfg), mainnet.id);
      await assertRejects(() => sendTransaction(cfg, { to: BOB, value: 1n }));
      await switchChain(cfg, { chainId: foundry.id });

      // A new page (new config) over the same storage reconnects without the phone.
      const cfg2 = config(w, store, (uri) => assert(!uri, "no QR code expected on reconnect"));
      await reconnect(cfg2);
      assertEquals(getAccount(cfg2).address, "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
      assertEquals(await signMessage(cfg2, { message: "again" }).then((s) => s.length), 132);

      await disconnect(cfg);
      assertEquals(getAccount(cfg).status, "disconnected");
    } finally {
      await w.stop();
    }
  },
});

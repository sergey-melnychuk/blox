// Shared by the integration tests: the Rust relay, anvil and the mock keystore binary.
const TARGET = new URL("../../../target/debug/", import.meta.url).pathname;
const HOME = Deno.env.get("HOME") ?? "";
const ANVIL = Deno.env.get("ANVIL") ?? `${HOME}/.foundry/bin/anvil`;
export const BOB = "0x4242424242424242424242424242424242424242";

export function exists(p: string) {
  try {
    Deno.statSync(p);
    return true;
  } catch {
    return false;
  }
}

export function freePort(): number {
  const l = Deno.listen({ hostname: "localhost", port: 0 });
  const port = (l.addr as Deno.NetAddr).port;
  l.close();
  return port;
}

export async function waitFor(f: () => Promise<boolean>, what: string) {
  for (let i = 0; i < 100; i++) {
    if (await f().catch(() => false)) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`timed out waiting for ${what}`);
}

export async function rpc(url: string, method: string, params: unknown[]) {
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const j = await res.json();
  if (j.error) throw new Error(j.error.message);
  return j.result;
}

export interface World {
  relay: string;
  anvil: string;
  keystore: Deno.ChildProcess;
  writer: WritableStreamDefaultWriter<Uint8Array>;
  lines: string[];
  stop(): Promise<void>;
}

export async function world(): Promise<World | null> {
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


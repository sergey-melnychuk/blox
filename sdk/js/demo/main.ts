import {
  connect,
  createConfig,
  disconnect,
  getAccount,
  http,
  reconnect,
  sendTransaction,
  signMessage,
  signTypedData,
  switchChain,
  waitForTransactionReceipt,
  watchAccount,
} from "@wagmi/core";
import { foundry, mainnet } from "viem/chains";
import { blox } from "@blox/sdk/wagmi";

const $ = (id: string) => document.getElementById(id) as HTMLInputElement;
const log = (s: string) => ($("log").textContent = `${new Date().toLocaleTimeString()} ${s}\n` + $("log").textContent);

// `?mock`: print the QR string instead of drawing it, to paste into the mock keystore.
const mock = new URLSearchParams(location.search).has("mock");

function makeConfig() {
  return createConfig({
    chains: [foundry, mainnet],
    // The one line a wagmi site adds:
    connectors: [blox({ name: "Blox demo", relay: $("relay").value, ...(mock ? { onQr: (uri) => uri && log(uri) } : {}) })],
    transports: { [foundry.id]: http($("rpc").value), [mainnet.id]: http() },
  });
}

let config = makeConfig();
const run = (f: () => Promise<unknown>) => () => f().catch((e) => log(`error: ${e.shortMessage ?? e.message}`));

watchAccount(config, { onChange: (a) => ($("account").textContent = a.address ? `${a.address} on chain ${a.chainId}` : "Not connected") });
reconnect(config);

$("connect").onclick = run(async () => {
  config = makeConfig();
  watchAccount(config, { onChange: (a) => ($("account").textContent = a.address ? `${a.address} on chain ${a.chainId}` : "Not connected") });
  const r = await connect(config, { connector: config.connectors[0] });
  log(`connected ${r.accounts[0]}`);
});
$("disconnect").onclick = run(async () => {
  await disconnect(config);
  log("disconnected");
});
$("send").onclick = run(async () => {
  const hash = await sendTransaction(config, { to: $("to").value as `0x${string}`, value: BigInt($("value").value) });
  log(`sent ${hash}`);
  const r = await waitForTransactionReceipt(config, { hash });
  log(`mined in block ${r.blockNumber}: ${r.status}`);
});
$("sign").onclick = run(async () => log(`signature ${await signMessage(config, { message: "Hello from the Blox demo" })}`));
$("typed").onclick = run(async () => {
  const sig = await signTypedData(config, {
    domain: { name: "Blox demo", chainId: getAccount(config).chainId },
    types: { Mail: [{ name: "contents", type: "string" }] },
    primaryType: "Mail",
    message: { contents: "hello" },
  });
  log(`typed signature ${sig}`);
});
$("chain").onchange = run(async () => {
  await switchChain(config, { chainId: Number($("chain").value) as 1 | 31337 });
  log(`switched to chain ${$("chain").value}`);
});

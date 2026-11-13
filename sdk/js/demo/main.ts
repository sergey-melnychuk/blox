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
  waitForTransactionReceipt,
  watchAccount,
} from "@wagmi/core";
import { type Chain, foundry, sepolia } from "viem/chains";
import { parseEther } from "viem";
import { blox } from "@blox/sdk/wagmi";

// Query options, for local runs (README.md):
//   ?anvil[=http://localhost:8545]   anvil instead of Sepolia
//   ?relay=http://localhost:8080     another relay (default: https://relay.example.com)
//   ?mock                            print the QR string in the log, for the mock keystore
const q = new URLSearchParams(location.search);
const anvil = q.has("anvil");
const chain: Chain = anvil ? foundry : sepolia;
const rpc = anvil ? q.get("anvil") || "http://localhost:8545" : "https://ethereum-sepolia-rpc.publicnode.com";
const explorer = anvil ? undefined : "https://sepolia.etherscan.io";

const $ = <T extends HTMLElement = HTMLInputElement>(id: string) => document.getElementById(id) as T;

function log(text: string, link?: string) {
  const line = document.createElement("div");
  line.textContent = `${new Date().toLocaleTimeString()} ${text} `;
  if (link) {
    const a = document.createElement("a");
    a.href = link;
    a.target = "_blank";
    a.rel = "noopener";
    a.textContent = "↗";
    line.append(a);
  }
  $("log").prepend(line);
}

const config = createConfig({
  chains: [chain],
  // The one line a wagmi site adds:
  connectors: [
    blox({
      name: "Blox demo",
      ...(q.get("relay") ? { relay: q.get("relay")! } : {}),
      ...(q.has("mock") ? { onQr: (uri: string | null) => uri && log(uri) } : {}),
    }),
  ],
  transports: { [chain.id]: http(rpc) } as never,
});

const short = (a: string) => `${a.slice(0, 6)}…${a.slice(-4)}`;
watchAccount(config, {
  onChange: (a) => {
    $("account").textContent = a.address ? `${short(a.address)} · ${chain.name}` : "";
    document.body.classList.toggle("connected", !!a.address);
  },
});
reconnect(config);

const run = (f: () => Promise<unknown>) => () =>
  f().catch((e) => log(`${e.shortMessage ?? e.message}`));

$("connect").onclick = run(async () => {
  const r = await connect(config, { connector: config.connectors[0] });
  log(`connected ${r.accounts[0]}`);
});
$("disconnect").onclick = run(async () => {
  await disconnect(config);
  log("disconnected");
});
$("send").onclick = run(async () => {
  const to = ($("to").value.trim() || getAccount(config).address) as `0x${string}`;
  const hash = await sendTransaction(config, { to, value: parseEther($("amount").value || "0") });
  log(`sent ${short(hash)}`, explorer && `${explorer}/tx/${hash}`);
  const r = await waitForTransactionReceipt(config, { hash });
  log(`block ${r.blockNumber}: ${r.status}`, explorer && `${explorer}/tx/${hash}`);
});
$("sign").onclick = run(async () =>
  log(`signature ${await signMessage(config, { message: "Hello from the Blox demo" })}`)
);
$("typed").onclick = run(async () => {
  const sig = await signTypedData(config, {
    domain: { name: "Blox demo", chainId: chain.id },
    types: { Mail: [{ name: "contents", type: "string" }] },
    primaryType: "Mail",
    message: { contents: "hello" },
  });
  log(`typed signature ${sig}`);
});

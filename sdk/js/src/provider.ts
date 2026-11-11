/**
 * An in-page EIP-1193 provider over [Blox] (BLOX.md §9.3). It turns wallet calls into
 * intent and passes nothing else on, so the phone still fills everything. Reads go to the
 * site's own RPC; the phone is never asked.
 */

import { Blox, BloxError, type BloxOptions } from "./blox.ts";
import { checksum } from "./evm.ts";

export class ProviderRpcError extends Error {
  constructor(readonly code: number, message: string, readonly data?: unknown) {
    super(message);
    this.name = "ProviderRpcError";
  }
}

type ReadFn = (chainId: number, method: string, params: unknown) => Promise<unknown>;

export interface ProviderOptions extends BloxOptions {
  /** Chains the site is configured for; `wallet_switchEthereumChain` to others → 4902. */
  chains?: number[];
  /** The site's RPC per chain, for read-only methods: a URL or a request function. */
  transports?: Record<number, string | ((args: { method: string; params?: unknown }) => Promise<unknown>)>;
  /** The initial chain (default: the stored one, else the first configured chain, else 1). */
  chainId?: number;
}

const READ_ONLY = new Set([
  "eth_call",
  "eth_estimateGas",
  "eth_getBalance",
  "eth_blockNumber",
  "eth_getTransactionReceipt",
  "eth_getTransactionByHash",
  "eth_getTransactionCount",
  "eth_getBlockByNumber",
  "eth_getBlockByHash",
  "eth_getCode",
  "eth_getStorageAt",
  "eth_getLogs",
  "eth_gasPrice",
  "eth_maxPriorityFeePerGas",
  "eth_feeHistory",
  "eth_blobBaseFee",
  "net_version",
  "web3_clientVersion",
]);

const DROPPED = ["nonce", "gas", "gasPrice", "maxFeePerGas", "maxPriorityFeePerGas", "type", "accessList", "from", "chainId", "to", "value", "data", "input"];
const REFUSED = ["authorizationList", "blobVersionedHashes", "maxFeePerBlobGas", "blobs", "sidecars"];

type Listener = (...args: unknown[]) => void;

export class BloxProvider {
  readonly blox: Blox;
  private chainId: number;
  private chainKnown = false;
  private listeners = new Map<string, Set<Listener>>();
  private read: ReadFn;

  constructor(private readonly opts: ProviderOptions, read?: ReadFn) {
    this.blox = new Blox(opts);
    this.chainId = opts.chainId ?? opts.chains?.[0] ?? 1;
    this.read = read ?? ((chainId, method, params) => readVia(opts.transports?.[chainId], method, params));
  }

  on(event: string, f: Listener): this {
    (this.listeners.get(event) ?? this.listeners.set(event, new Set()).get(event)!).add(f);
    return this;
  }

  removeListener(event: string, f: Listener): this {
    this.listeners.get(event)?.delete(f);
    return this;
  }

  private emit(event: string, ...args: unknown[]) {
    this.listeners.get(event)?.forEach((f) => f(...args));
  }

  private async currentChain(): Promise<number> {
    if (!this.chainKnown) {
      this.chainKnown = true;
      const stored = await this.blox.storedChain();
      if (stored !== undefined && (!this.opts.chains || this.opts.chains.includes(stored))) this.chainId = stored;
    }
    return this.chainId;
  }

  async request({ method, params }: { method: string; params?: unknown }): Promise<unknown> {
    try {
      return await this.handle(method, (params ?? []) as unknown[]);
    } catch (e) {
      throw toRpcError(e, this, method);
    }
  }

  /** Called on errors that end the connection. */
  ended() {
    this.emit("accountsChanged", []);
    this.emit("disconnect", new ProviderRpcError(4100, "disconnected"));
  }

  private async handle(method: string, params: unknown[]): Promise<unknown> {
    switch (method) {
      case "eth_requestAccounts": {
        const { account } = await this.blox.connect();
        const chainId = await this.currentChain();
        this.emit("connect", { chainId: hex(chainId) });
        this.emit("accountsChanged", [account]);
        return [account];
      }
      case "eth_accounts": {
        const a = this.blox.account ?? (await this.blox.restore());
        return a ? [a] : [];
      }
      case "eth_chainId":
        return hex(await this.currentChain());
      case "wallet_switchEthereumChain": {
        const id = Number((params[0] as { chainId: string }).chainId);
        if (this.opts.chains && !this.opts.chains.includes(id)) throw new ProviderRpcError(4902, `chain ${id} is not configured`);
        this.chainId = id;
        this.chainKnown = true;
        await this.blox.rememberChain(id);
        this.emit("chainChanged", hex(id));
        return null;
      }
      case "wallet_addEthereumChain":
        // The phone's endpoints are configured on the phone (§10.3).
        return null;
      case "eth_sendTransaction":
      case "eth_signTransaction": {
        const tx = (params[0] ?? {}) as Record<string, unknown>;
        await this.requireAccount(tx.from as string | undefined);
        for (const k of REFUSED) if (tx[k] !== undefined) throw new ProviderRpcError(4200, `${k} is not supported`);
        for (const k of Object.keys(tx)) if (!DROPPED.includes(k) && tx[k] !== undefined) throw new ProviderRpcError(4200, `${k} is not supported`);
        const chain = tx.chainId !== undefined ? Number(tx.chainId) : await this.currentChain();
        const intent = {
          chain,
          to: (tx.to as string | null | undefined) ?? null,
          value: tx.value !== undefined ? BigInt(tx.value as string) : 0n,
          data: (tx.data ?? tx.input ?? "0x") as string,
        };
        if (method === "eth_sendTransaction") return (await this.blox.send(intent)).txHash;
        return (await this.blox.signTransaction(intent)).raw;
      }
      case "personal_sign": {
        const [message, address] = params as [string, string];
        await this.requireAccount(address);
        const bytes = /^0x[0-9a-fA-F]*$/.test(message) ? hexBytes(message) : new TextEncoder().encode(message);
        return (await this.blox.personalSign({ chain: await this.currentChain(), message: bytes })).signature;
      }
      case "eth_signTypedData_v4": {
        const [address, data] = params as [string, string | object];
        await this.requireAccount(address);
        const td = typeof data === "string" ? JSON.parse(data) : data;
        return (await this.blox.signTypedData({ chain: await this.currentChain(), data: td })).signature;
      }
      default:
        if (READ_ONLY.has(method)) return await this.read(await this.currentChain(), method, params);
        throw new ProviderRpcError(4200, `${method} is not supported`);
    }
  }

  private async requireAccount(address?: string) {
    const account = this.blox.account ?? (await this.blox.restore()) ?? (await this.blox.connect()).account;
    if (address && checksum(address) !== account) throw new ProviderRpcError(4100, "not the connected account");
  }
}

export function createProvider(opts: ProviderOptions): BloxProvider {
  return new BloxProvider(opts);
}

async function readVia(t: ProviderOptions["transports"] extends Record<number, infer T> | undefined ? T | undefined : never, method: string, params: unknown) {
  if (!t) throw new ProviderRpcError(4200, `no RPC configured for ${method}`);
  if (typeof t === "function") return await t({ method, params });
  const res = await fetch(t, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const j = await res.json();
  if (j.error) throw new ProviderRpcError(j.error.code ?? -32603, j.error.message ?? "rpc error", j.error.data);
  return j.result;
}

function hex(n: number) {
  return "0x" + n.toString(16);
}

function hexBytes(s: string): Uint8Array {
  const h = s.slice(2);
  return Uint8Array.from({ length: h.length / 2 }, (_, i) => parseInt(h.slice(2 * i, 2 * i + 2), 16));
}

/** §9.3's error table. */
function toRpcError(e: unknown, p: BloxProvider, method: string): unknown {
  if (e instanceof ProviderRpcError) return e;
  if (!(e instanceof BloxError)) return new ProviderRpcError(-32603, String(e));
  switch (e.code) {
    case "cancelled":
      return new ProviderRpcError(4001, "the user cancelled");
    case "rejected":
      if (e.extra.reason === "user") return new ProviderRpcError(4001, "the user rejected the request");
      if (e.extra.reason === "no_endpoint") return new ProviderRpcError(4901, "no endpoint for this chain in the Blox app");
      if (e.extra.reason === "unsupported" || e.extra.reason === "decode_failed") {
        return new ProviderRpcError(4200, `the Blox app refused ${method}: ${e.extra.reason}`);
      }
      return new ProviderRpcError(-32603, `rejected: ${e.extra.reason}`, { code: e.code, reason: e.extra.reason });
    case "disconnected":
      p.ended();
      return new ProviderRpcError(4100, "the connection was ended or has expired");
    default:
      return new ProviderRpcError(-32603, e.message, { code: e.code, ...e.extra });
  }
}

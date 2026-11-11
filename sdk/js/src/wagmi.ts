/**
 * The wagmi connector (BLOX.md §9.3): add `blox({ name })` to a wagmi config's connectors.
 *
 * ```ts
 * import { blox } from "@blox/sdk/wagmi";
 * createConfig({ chains: [mainnet, base], connectors: [injected(), blox({ name: "Uniswap" })], transports });
 * ```
 *
 * `@wagmi/core` is only a type dependency: `createConnector` is the identity, so this file
 * returns the connector function directly.
 */

import type { CreateConnectorFn } from "@wagmi/core";
import type { BloxOptions } from "./blox.ts";
import { BloxProvider, ProviderRpcError } from "./provider.ts";

const ICON = "data:image/svg+xml;base64," +
  btoa(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="#111"/><path d="M9 9h14v14H9z" fill="none" stroke="#fff" stroke-width="3"/></svg>`);

type Address = `0x${string}`;

export function blox(opts: Omit<BloxOptions, "relay"> & { relay?: string }): CreateConnectorFn {
  return ((config) => {
    let provider: BloxProvider | undefined;
    const chains = config.chains.map((c) => c.id);
    const get = () => {
      provider ??= new BloxProvider({ ...opts, chains }, async (chainId, method, params) => {
        const chain = config.chains.find((c) => c.id === chainId);
        const transport = config.transports?.[chainId];
        if (transport && chain) return await transport({ chain, retryCount: 0 }).request({ method, params } as never);
        const url = chain?.rpcUrls.default.http[0];
        if (!url) throw new ProviderRpcError(4200, `no RPC for chain ${chainId}`);
        const res = await fetch(url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
        });
        const j = await res.json();
        if (j.error) throw new ProviderRpcError(j.error.code ?? -32603, j.error.message);
        return j.result;
      });
      return provider;
    };

    return {
      id: "blox",
      name: "Blox",
      type: "blox",
      icon: ICON,
      async setup() {
        const p = get();
        p.on("accountsChanged", (a) => this.onAccountsChanged(a as string[]));
        p.on("chainChanged", (c) => this.onChainChanged(c as string));
        p.on("disconnect", () => this.onDisconnect());
      },
      async connect(params: { chainId?: number } = {}) {
        const p = get();
        const accounts = (await p.request({ method: "eth_requestAccounts" })) as Address[];
        let chainId = Number(await p.request({ method: "eth_chainId" }));
        if (params.chainId && params.chainId !== chainId) {
          await p.request({ method: "wallet_switchEthereumChain", params: [{ chainId: "0x" + params.chainId.toString(16) }] });
          chainId = params.chainId;
        }
        return { accounts, chainId } as never;
      },
      async disconnect() {
        await get().blox.disconnect();
      },
      async getAccounts() {
        return (await get().request({ method: "eth_accounts" })) as Address[];
      },
      async getChainId() {
        return Number(await get().request({ method: "eth_chainId" }));
      },
      async getProvider() {
        return get();
      },
      async isAuthorized() {
        return (await get().blox.restore()) !== null;
      },
      async switchChain({ chainId }: { chainId: number }) {
        const chain = config.chains.find((c) => c.id === chainId);
        if (!chain) throw new ProviderRpcError(4902, `chain ${chainId} is not configured`);
        await get().request({ method: "wallet_switchEthereumChain", params: [{ chainId: "0x" + chainId.toString(16) }] });
        return chain;
      },
      onAccountsChanged(accounts: string[]) {
        if (accounts.length === 0) this.onDisconnect();
        else config.emitter.emit("change", { accounts: accounts as Address[] });
      },
      onChainChanged(chain: string) {
        config.emitter.emit("change", { chainId: Number(chain) });
      },
      onDisconnect() {
        config.emitter.emit("disconnect");
      },
    };
  }) as CreateConnectorFn;
}

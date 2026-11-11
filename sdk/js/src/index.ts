/**
 * @blox/sdk — connect a site or app to a Blox phone keystore (BLOX.md §9).
 *
 * ```ts
 * import { Blox } from "@blox/sdk";
 * const blox = new Blox({ name: "Example" });
 * const { account } = await blox.connect();
 * const { txHash } = await blox.send({ chain: 8453, to: "0x…", value: 10n ** 16n });
 * ```
 */

export { Blox, BloxError, verifyConnection } from "./blox.ts";
export type { BloxOptions, ErrorCode, Status, TxIntent } from "./blox.ts";
export { IndexedDbStore, MemoryStore } from "./store.ts";
export type { ConnectionStore, StoredConnection } from "./store.ts";
export { rawBackend, webcryptoBackend } from "./keys.ts";
export type { Backend } from "./keys.ts";
export { DEFAULT_RELAY } from "./relayUrl.ts";
export type { RejectReason, SignRequest, SignResponse } from "./wire.ts";

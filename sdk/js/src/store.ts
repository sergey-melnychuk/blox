/**
 * Where the connection lives between page loads (BLOX.md §9.6).
 *
 * In browsers, [IndexedDbStore] keeps the keys as non-extractable `CryptoKey` objects
 * (structured clone keeps the flag and the usages), next to the token and the account.
 */

import type { StoredKey } from "./keys.ts";

export interface StoredConnection {
  relay: string;
  label: string;
  /** Checksummed address. */
  account: string;
  /** Countersigned token (`Blox-Token` encoding). */
  token: string;
  sig: StoredKey;
  kem: StoredKey;
  /** The provider's current chain (§9.3). */
  chain?: number;
}

export interface ConnectionStore {
  load(relay: string): Promise<StoredConnection | null>;
  save(c: StoredConnection): Promise<void>;
  clear(relay: string): Promise<void>;
}

/** In memory; instances can be shared (like tabs sharing a browser's storage). */
export class MemoryStore implements ConnectionStore {
  private map = new Map<string, StoredConnection>();
  load(relay: string) {
    return Promise.resolve(this.map.get(relay) ?? null);
  }
  save(c: StoredConnection) {
    this.map.set(c.relay, c);
    return Promise.resolve();
  }
  clear(relay: string) {
    this.map.delete(relay);
    return Promise.resolve();
  }
}

const DB = "blox";
const STORE = "connections";

/** IndexedDB, database `blox`, store `connections`, keyed by relay URL. */
export class IndexedDbStore implements ConnectionStore {
  private db: Promise<IDBDatabase> | null = null;

  private open(): Promise<IDBDatabase> {
    this.db ??= new Promise((resolve, reject) => {
      const req = indexedDB.open(DB, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE, { keyPath: "relay" });
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    // Best effort: ask the browser not to evict the connection under storage pressure.
    (navigator as { storage?: { persist?: () => Promise<boolean> } }).storage?.persist?.().catch(() => {});
    return this.db;
  }

  private async tx<T>(mode: IDBTransactionMode, f: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const req = f(db.transaction(STORE, mode).objectStore(STORE));
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async load(relay: string) {
    return (await this.tx("readonly", (s) => s.get(relay))) ?? null;
  }
  async save(c: StoredConnection) {
    await this.tx("readwrite", (s) => s.put(c));
  }
  async clear(relay: string) {
    await this.tx("readwrite", (s) => s.delete(relay));
  }
}

export function defaultStore(): ConnectionStore {
  return typeof indexedDB !== "undefined" ? new IndexedDbStore() : new MemoryStore();
}

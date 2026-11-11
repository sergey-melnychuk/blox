/** Relay URLs: normalization (BLOX.md §4.3) and the QR code's relay field (§5.1). */

export const DEFAULT_RELAY = "https://relay.example.com";

export function normalizeRelay(url: string): string {
  const m = /^([A-Za-z]+):\/\/(.*)$/.exec(url);
  if (!m) throw new Error("relay url");
  const scheme = m[1].toLowerCase();
  const defaultPort = scheme === "https" ? "443" : scheme === "http" ? "80" : null;
  if (!defaultPort) throw new Error("relay url");
  const rest = m[2];
  if (/[?#@\s]/.test(rest)) throw new Error("relay url");
  const slash = rest.indexOf("/");
  const authority = slash < 0 ? rest : rest.slice(0, slash);
  const path = slash < 0 ? "" : rest.slice(slash);
  let host: string;
  let port: string | null = null;
  if (authority.startsWith("[")) {
    const end = authority.indexOf("]");
    if (end < 0) throw new Error("relay url");
    host = authority.slice(0, end + 1);
    const after = authority.slice(end + 1);
    if (after) {
      if (!after.startsWith(":")) throw new Error("relay url");
      port = after.slice(1);
    }
  } else {
    const c = authority.lastIndexOf(":");
    host = c < 0 ? authority : authority.slice(0, c);
    port = c < 0 ? null : authority.slice(c + 1);
  }
  if (!host) throw new Error("relay url");
  if (port !== null && !/^[0-9]+$/.test(port)) throw new Error("relay url");
  if (port === defaultPort) port = null;
  const out = `${scheme}://${host.toLowerCase()}${port ? ":" + port : ""}${path.replace(/\/+$/, "")}`;
  if (new TextEncoder().encode(out).length > 255) throw new Error("relay url");
  return out;
}

export function toQrField(normalized: string): string {
  return normalized === DEFAULT_RELAY ? "" : normalized.startsWith("https://") ? normalized.slice(8) : normalized;
}

export function relayHost(normalized: string): string {
  return normalized.replace(/^[a-z]+:\/\//, "").split("/")[0];
}

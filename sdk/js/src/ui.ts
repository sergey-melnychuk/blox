/**
 * The default modal and toast (BLOX.md §9.4), in a closed shadow root with inline styles:
 * no CSS import, and the site's styles don't reach in. Browsers only.
 */

import type { Status } from "./blox.ts";
import { qrSvg } from "./qr.ts";

const STYLE = `
:host { all: initial; }
.overlay { position: fixed; inset: 0; background: rgba(0,0,0,.55); display: flex; align-items: center;
  justify-content: center; z-index: 2147483647; font: 15px/1.4 system-ui, -apple-system, sans-serif; }
.card { background: #fff; color: #111; border-radius: 16px; padding: 24px; width: min(360px, calc(100vw - 32px));
  box-shadow: 0 10px 40px rgba(0,0,0,.3); text-align: center; }
.card h2 { margin: 0 0 4px; font-size: 18px; }
.card p { margin: 6px 0; color: #444; }
.qr { background: #fff; padding: 8px; margin: 12px auto; width: min(280px, 100%); }
.qr svg { width: 100%; height: auto; display: block; }
button { font: inherit; border: 1px solid #ccc; background: #f6f6f6; color: #111; border-radius: 10px; padding: 8px 16px; cursor: pointer; }
.toast { position: fixed; right: 16px; bottom: 16px; max-width: min(380px, calc(100vw - 32px)); background: #111; color: #fff;
  border-radius: 12px; padding: 12px 16px; display: flex; gap: 12px; align-items: center; z-index: 2147483647;
  font: 14px/1.4 system-ui, -apple-system, sans-serif; box-shadow: 0 6px 24px rgba(0,0,0,.3); word-break: break-all; }
.toast button { background: transparent; color: #fff; border-color: #555; padding: 4px 10px; }
@media (prefers-color-scheme: dark) {
  .card { background: #1c1c1e; color: #f2f2f2; } .card p { color: #bbb; }
  button { background: #2c2c2e; color: #f2f2f2; border-color: #444; }
}`;

function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls?: string, text?: string): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function countdown(until: number): string {
  const s = Math.max(0, Math.round((until - Date.now()) / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

export function createUi(name: string, onCancel: () => void, opts: { toast: boolean }) {
  let host: HTMLElement | null = null;
  let root: ShadowRoot | null = null;
  let timer: number | undefined;

  const mount = () => {
    if (root) return root;
    host = document.createElement("blox-ui");
    root = host.attachShadow({ mode: "closed" });
    root.appendChild(el("style", undefined, STYLE));
    document.body.appendChild(host);
    return root;
  };

  const clear = () => {
    if (timer !== undefined) clearInterval(timer);
    timer = undefined;
    root?.querySelectorAll(".overlay, .toast").forEach((n) => n.remove());
  };

  const tick = (node: HTMLElement, prefix: string, until: number) => {
    const update = () => (node.textContent = `${prefix} · ${countdown(until)}`);
    update();
    timer = setInterval(update, 1000) as unknown as number;
  };

  const onQr = (uri: string | null) => {
    clear();
    if (!uri) return;
    const r = mount();
    const overlay = el("div", "overlay");
    const card = el("div", "card");
    card.appendChild(el("h2", undefined, "Connect with Blox"));
    card.appendChild(el("p", undefined, `${name} wants to connect`));
    const qr = el("div", "qr");
    qr.innerHTML = qrSvg(uri); // generated SVG, no user input
    card.appendChild(qr);
    card.appendChild(el("p", undefined, "Scan with the Blox app"));
    const left = el("p");
    card.appendChild(left);
    const cancel = el("button", undefined, "Cancel");
    cancel.onclick = () => {
      clear();
      onCancel();
    };
    card.appendChild(cancel);
    overlay.appendChild(card);
    r.appendChild(overlay);
    tick(left, "Waiting for your phone", Date.now() + 120_000);
  };

  const toast = (text: string, until?: number, cancellable = false) => {
    clear();
    const r = mount();
    const t = el("div", "toast");
    const label = el("span", undefined, text);
    t.appendChild(label);
    if (cancellable) {
      const b = el("button", undefined, "Cancel");
      b.onclick = () => {
        clear();
        onCancel();
      };
      t.appendChild(b);
    }
    r.appendChild(t);
    if (until) tick(label, text, until);
  };

  const onStatus = (s: Status) => {
    switch (s.type) {
      case "connected":
        if (opts.toast) {
          toast(`Connected as ${s.account}`);
          setTimeout(clear, 3000);
        }
        break;
      case "queued":
        if (opts.toast) toast("Waiting for the previous request");
        break;
      case "waiting":
        if (opts.toast) toast("Approve in the Blox app", s.until, true);
        break;
      case "done":
        if (opts.toast) {
          toast(s.text);
          setTimeout(clear, 3000);
        }
        break;
      case "idle":
        clear();
        break;
    }
  };

  return { onQr, onStatus };
}

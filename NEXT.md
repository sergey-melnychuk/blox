# Next steps

**Done so far:** protocol, relay, adapter (`blox rpc` and the embeddable `blox-adapter`), and
the Android keystore app. The full round trip (`cast` → phone approval → mined on anvil) works
on a real phone over the local network.

Suggested order: **1, then 2.** The relay deploy is small, makes Blox usable outside the
LAN, and lets the gate integration run against the real relay from the start.

## 1. M4: deploy the relay at `relay.example.com`

Everything currently works only while the phone is on the same Wi-Fi. A public relay makes it
work anywhere (including mobile data) and makes the default URL real. It's also the point
where release builds can be tested, since they refuse plain HTTP.

- [ ] Dockerfile (distroless or scratch) and Caddyfile (BLOX.md §8.7)
- [ ] Top-level README: running, self-hosting, security model (BLOX.md §14.2)
- [ ] Deploy to the VPS, with DNS for `relay.example.com` (needs VPS/DNS access)
- [ ] Round trip over the public relay from a phone on mobile data
- [ ] Release APK tested against the public relay

## 2. yevm-gate integration (in the yevm repo)

Gate accepts `eth_sendTransaction`, simulates it with yevm, shows the `BLOX:` QR code next to
WalletConnect, and sends the request to the phone: simulate, then sign, then broadcast. The
Blox side is ready (`blox-adapter`, BLOX.md §9.9).

- [ ] Depend on `blox-adapter`; call `Adapter::handle` for each JSON-RPC request, forward when it returns `None`
- [ ] `Upstream` backed by gate's `chains` table (per-chain routing)
- [ ] `Hooks::before_sign`: simulate the fully filled transaction, show side effects, veto on reject
- [ ] `Hooks::show_qr`: render the `BLOX:` code in the web UI
- [ ] Move gate from alloy 1.7 to 2.x (both versions can be built in together meanwhile)

The yevm repo has uncommitted work in progress: do this on a branch, only when ready.

## 3. Finish M3 (Android)

- [ ] On-device checks (BLOX.md §13.4): StrongBox/TEE shown, fingerprint and PIN fallback,
      screenshots blocked, session ends after 30 s in the background, multi-transaction
      `forge script` in one scan, QR code scans from light and dark terminal themes
- [ ] Audit log (Room), BLOX.md §10.8
- [ ] Add more accounts (derive index 1, 2, …) from the home screen
- [ ] Reproducible, signed release builds; publish checksums and certificate fingerprint (§10.1)
- [ ] App icon and visual polish

## 4. Security pass before real funds

- [ ] Onboarding keeps the recovery phrase in Compose UI state as a `String`, which can't be wiped. Minimise or replace it
- [ ] Review edge cases: requests that time out, retries after a reconnect, key invalidated mid-session
- [ ] Test `--timeout` and `--idle-timeout` paths in the adapter (only the join timeout is tested)
- [ ] Independent review of the protocol and key handling

## Also open

- [ ] A real viem test (needs Node) in place of the raw JSON-RPC stand-in
- [ ] Decide whether the phone should run yevm-core itself, so simulation happens on the trusted
      device (brings yevm's PolyForm Noncommercial license into the app)

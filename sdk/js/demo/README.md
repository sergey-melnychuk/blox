# Blox demo (wagmi)

A static wagmi site with the Blox connector, built from the SDK's source. It connects to a
phone through a relay and sends on Sepolia. DEPLOY.md ("The demo site") hosts it at `/demo/` on
the relay's own site.

```sh
cd sdk/js && deno task demo                  # demo/dist: index.html and demo.js
python3 -m http.server -d demo/dist 5173     # or any static server: http://localhost:5173
```

No npm: `deno bundle` builds it. The files use relative paths, so they work under any path.

The phone needs a Sepolia endpoint in Settings (chain `11155111`, e.g.
`https://ethereum-sepolia-rpc.publicnode.com`) and some Sepolia ETH on the signer.

Click **Connect**, scan the QR code with the Blox app, then **Send** (empty "To" sends to
yourself), **Sign message** or **Sign typed data**. Transaction lines link to Etherscan.

Query options for local runs:

| Option | Effect |
|---|---|
| `?anvil` or `?anvil=http://host:8545` | anvil (chain 31337) instead of Sepolia |
| `?relay=http://localhost:8080` | another relay (default: the site serving the page) |
| `?mock` | print the `BLOX:` string in the log instead of drawing it, for the mock keystore |

With everything local (RUN.md): `scripts/local-services.sh`, then open
`http://localhost:5173/?anvil&relay=http://localhost:8080&mock` and paste the printed
`BLOX:` line into `target/local/keystore.in`.

# Blox demo (wagmi)

A static wagmi app using the Blox connector from the SDK's source.

```sh
# Terminal 1–3: a local chain, a relay, and either the Android app or the mock keystore
anvil --host any-address
BLOX_LISTEN=:8080 cargo run -p blox-relay
cargo run -p blox-mock-keystore -- --endpoint 31337=http://localhost:8545   # paste the QR string

# Terminal 4
cd sdk/js/demo && npm install && npm run dev
```

Open the printed URL, click **Connect**, and scan the QR code with the Blox app. With the
mock keystore instead, open the page with `?mock`: the `BLOX:` string is printed in the log
instead of drawn; paste it into the mock keystore's terminal.

Not verified on the machine this was written on (no Node or browser there).

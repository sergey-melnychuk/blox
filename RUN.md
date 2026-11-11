# Running Blox locally

Two ways to see a full round trip: **without a phone** (the mock keystore stands in for the
app) and **with the Android app**. Both use a local anvil chain and a local relay. Commands
assume you're in the repo root (`blox/`).

## Without a phone

The mock keystore (`crates/blox-mock-keystore`) behaves like the app with automatic
approval: it connects to offers you give it, fills transactions from its endpoint, signs
with anvil's test keys and broadcasts.

Run each in its own terminal:

```sh
anvil
```
```sh
BLOX_LISTEN=localhost:8080 cargo run -p blox-relay
```
```sh
cargo run -p blox-mock-keystore -- --endpoint 31337=http://localhost:8545
```

Or start all three with one command (release builds; logs in `target/local`; Ctrl-C stops
them all):

```sh
scripts/local-services.sh
```

It reads the mock keystore's input from `target/local/keystore.in`: give it a QR string with
`echo 'BLOX:…' > target/local/keystore.in`, and read its answers in `target/local/keystore.log`.

The mock keystore prints its signers and then waits for `BLOX:` lines on its input. Now
connect and send with the example requester. `--print-uri` prints the QR string instead of
drawing it:

```sh
cargo run -p blox-client --example send -- --relay http://localhost:8080 --print-uri \
    --chain 31337 --to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 --value 1000000000000000
```

Copy the `BLOX:…` line it prints into the mock keystore's terminal. The keystore answers
`{"connected": …}`, the example prints `Connected as 0xf39F…` and then the transaction
hash. The connection is stored in `blox-example.json` (mode 0600), so later runs need no QR
code:

```sh
cargo run -p blox-client --example send -- --relay http://localhost:8080 --chain 31337 --message hello
cargo run -p blox-client --example send -- --relay http://localhost:8080 --disconnect
```

Useful mock keystore flags: `--signer 1` connects anvil's second account, `--days 1` sets
how long a connection lasts, `--mnemonic` uses another phrase.

## With the Android app

> The connections UI is PLAN.md step 5.2. Until it has been built and checked on a device,
> this section describes the intended flow.

### 1. Shell setup (macOS, every new terminal)

```sh
export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
export ANDROID_HOME=~/Library/Android/sdk
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"
```

### 2. Install the app

1. Enable USB debugging on the phone: Settings → About phone → tap *Build number* 7 times,
   then Developer options → *USB debugging*. Plug the phone in and accept the prompt.
2. Build, install and launch:
   ```sh
   adb devices                                   # the phone should be listed
   (cd android && ./gradlew :app:installDebug)
   adb shell am start -n wtf.oxff.blox/.MainActivity
   ```

The phone needs a screen lock (PIN, pattern or password) before you can add a signer.

### 3. Start a chain and a relay the phone can reach

The phone must be on the same Wi-Fi as the computer. Find the computer's LAN address
(`ipconfig getifaddr en0` on macOS) and use it in place of `my-computer.lan` below.

```sh
anvil --host any-address
```
```sh
BLOX_LISTEN=:8080 cargo run -p blox-relay
```

Or both at once, without the mock keystore (the app is the keystore):

```sh
BLOX_HOST=any-address scripts/local-services.sh --no-keystore
```

Debug builds of the app accept plain-HTTP relays and endpoints; release builds refuse them.

### 4. Set up the app

1. **Add a signer.** Choose "Import an existing one" and enter anvil's test phrase
   (`test test test test test test test test test test test junk`), whose first account
   `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` anvil funds. **Never use this phrase for
   anything real.**
2. **Add an endpoint** in Settings: chain `31337`, URL `http://my-computer.lan:8545`. The app
   checks it with `eth_chainId`.

### 5. Connect and send

```sh
cargo run -p blox-client --example send -- --relay http://my-computer.lan:8080 \
    --chain 31337 --to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 --value 1000000000000000
```

A QR code appears in the terminal. In the app, tap **Scan** and scan it. The first time,
the app asks whether to use the relay `my-computer.lan:8080`. Choose the signer and how long to
remember the site, and approve with your fingerprint or PIN. The example prints
`Connected as …` and sends the request: it waits in the app's request list (the relay keeps
it for 5 minutes). Review it, tap **Approve**, and the example prints the transaction hash.

### Logs

```sh
adb logcat --pid=$(adb shell pidof wtf.oxff.blox)
```

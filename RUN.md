# Running Blox on a phone

A full signing round trip: `cast` on your computer → `blox rpc` → relay → the Android app →
approve on the phone → transaction mined on a local anvil chain. Commands assume you're in
the repo root (`blox/`).

## 1. Shell setup (every new terminal)

```sh
export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
export ANDROID_HOME=~/Library/Android/sdk
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"
```

## 2. Install the app on the phone

1. Enable USB debugging on the phone: Settings → About phone → tap *Build number* 7 times,
   then Developer options → *USB debugging*. Plug the phone in and accept the prompt on it.
2. Build, install and launch:
   ```sh
   adb devices                                   # the phone should be listed
   (cd android && ./gradlew :app:installDebug)
   adb shell am start -n wtf.oxff.blox/.MainActivity
   ```

The phone needs a screen lock (PIN, pattern or password), or the app won't let you create a key.

## 3. Start the relay, a local chain and the adapter

The phone must be on the same Wi-Fi as the computer. Find the computer's LAN address with
`ipconfig getifaddr en0` and use it in place of `my-computer.lan` below.

Run each in its own terminal:

```sh
BLOX_LISTEN=:8080 cargo run -p blox-relay
```
```sh
anvil
```
```sh
cargo run -p blox-cli --bin blox -- rpc --upstream http://localhost:8545 \
    --relay http://my-computer.lan:8080 --listen localhost:8546
```

Debug builds of the app allow this plain-HTTP relay; release builds refuse it.

## 4. Import a test key in the app

Choose **Import** and enter anvil's test phrase:

```
test test test test test test test test test test test junk
```

Your account is then `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`, which anvil funds.
**Never use this phrase for anything real.**

## 5. Sign

```sh
cast send --unlocked --from 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 \
    0x70997970C51812dc3A010C7d01b50e0d17dc79C8 --value 1ether \
    --rpc-url http://localhost:8546 --rpc-timeout 300
```

A QR code appears in the `blox rpc` terminal. In the app, tap **Scan**, scan it, review the
request, tap **Approve** and confirm with your fingerprint or PIN. `cast` prints the receipt.

`--rpc-timeout 300` matters: Foundry gives up after 45 s by default, which is too short to
scan and approve.

## Logs

```sh
adb logcat --pid=$(adb shell pidof wtf.oxff.blox)
```

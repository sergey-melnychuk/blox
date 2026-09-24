# Blox keystore — Android

The phone-side keystore (BLOX.md §10). Kotlin + Jetpack Compose on top of the shared Rust
core (`crates/blox-ffi`, UniFFI). The app does UI, the Android Keystore and networking;
protocol handling, request checks, decoding for display and signing all run in Rust.

## One-time setup

1. **Android Studio**, then in *Settings → Languages & Frameworks → Android SDK*:
   - SDK Platform **36**
   - SDK Tools: **NDK (Side by side)**
2. **Rust Android targets and cargo-ndk** (already installed on this machine):
   ```sh
   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
   cargo install cargo-ndk
   ```
3. Open the `android/` directory in Android Studio, or build from the command line:
   ```sh
   JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:assembleDebug
   ```
   Toolchain: AGP 9.4.1 (built-in Kotlin), Gradle 9.7.1, NDK 30.0.16248370 (pinned in `app/build.gradle.kts`).

If Android Studio can't find `cargo` (common when it's started from the Dock), set `CARGO`
to its full path, e.g. `CARGO=$HOME/.cargo/bin/cargo`. The build looks there by default.

## How the build works

`preBuild` depends on two Gradle tasks in `app/build.gradle.kts`:

- **`cargoNdk`** builds `libblox_ffi.so` into `app/build/rustJniLibs`. Release builds get
  `arm64-v8a`, `armeabi-v7a` and `x86_64`; other builds only `arm64-v8a` (phones and
  Apple-silicon emulators), because each ABI is a full Rust release build. Override with
  `-Pblox.abis=x86_64,arm64-v8a`. The first build compiles the whole Rust stack (~1.5 min per
  ABI); later builds are incremental.
- **`uniffiBindings`** generates `uniffi/blox_ffi/blox_ffi.kt` from the built library into
  `app/build/generated/uniffi`.

Nothing generated is committed. Change Rust code, rebuild the app, and the bindings follow.

## Trying it against a local relay

A debug build allows plain HTTP. On a phone on the same Wi-Fi as your computer:

```sh
# on the computer (replace my-computer.lan with its LAN address)
BLOX_LISTEN=:8080 cargo run -p blox-relay
anvil
cargo run -p blox-cli --bin blox -- rpc --upstream http://localhost:8545 \
    --relay http://my-computer.lan:8080 --listen localhost:8546
cast send --unlocked --from <your address> <to> --value 1 --rpc-url http://localhost:8546 --rpc-timeout 300
```

Scan the QR code the `blox rpc` terminal prints. To test with anvil's funded accounts, import
anvil's test phrase in the app: `test test test test test test test test test test test junk`.
**Never use that phrase for anything real.**

Release builds refuse plain HTTP (`network_security_config.xml`) and the relay URL must be HTTPS.

## What to verify on a device (M3 gates, BLOX.md §13.4)

- [ ] Key creation reports StrongBox or TEE (the home screen shows which)
- [ ] Approve works with fingerprint, face (class 3) and the device-PIN fallback (API 30+)
- [ ] Removing the screen lock invalidates the key, and restoring from the phrase gives the same addresses
- [ ] The terminal QR code scans from dark and light terminal themes
- [ ] Screenshots and screen recording are blocked on every screen
- [ ] Leaving the app for more than 30 s ends the session

## Not in the scaffold yet

- Audit log (Room) — §10.8
- Adding more accounts (derive index 1, 2, …) from the home screen
- Reproducible release builds and signing setup — §10.1
- App icon and visual polish

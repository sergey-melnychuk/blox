# Blox keystore — Android

> **Status:** the connections UI (PLAN.md step 5.2) builds, and the bindings pass the
> instrumented vectors test on a device. The other §13.4 device checks below are still to do.

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

## Instrumented test

`app/src/androidTest/.../BindingsVectorsTest.kt` runs the Rust core through the generated
Kotlin bindings on a device against `test-vectors/proto-v1.json` (packaged as a test asset):
relay URLs, request signatures, the offer, the mnemonic's account, `acceptOffer`, and a request
round trip (open the vectors' `sign_request`, redelivery, review with a Kotlin `EndpointRpc`,
approve, broadcast, a JSON-RPC error thrown from Kotlin, answer).

Install both APKs over what is there (`-r` keeps the app's data) and run the runner:

```sh
./gradlew :app:assembleDebug :app:assembleDebugAndroidTest
adb install -r -t app/build/outputs/apk/debug/app-debug.apk
adb install -r -t app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb shell am instrument -w -r wtf.oxff.blox.test/androidx.test.runner.AndroidJUnitRunner
```

> **Don't run `./gradlew :app:connectedDebugAndroidTest` on a phone with signers.** It
> uninstalls the app after the run (also when an install fails), which deletes its Android
> Keystore keys: every signer on the phone is gone unless its recovery phrase is written
> down. Gradle also prints `BUILD SUCCESSFUL` when the APKs failed to install.

## Trying it locally

See [RUN.md](../RUN.md), section "With the Android app": anvil and a relay on your computer,
the app on a phone on the same Wi-Fi, and the example requester (or the web demo in
`sdk/js/demo`) to connect and send. Import anvil's test phrase as a signer
(`test test test test test test test test test test test junk`; **never use it for anything
real**). Debug builds accept plain HTTP for relays and endpoints; release builds refuse it
(`network_security_config.xml`).

The screens keep `FLAG_SECURE` (no screenshots or recording). For work on the UI, a debug build
made with `./gradlew :app:assembleDebug -Pblox.screenshots` leaves it off, so
`adb exec-out screencap -p` works. Release builds always set it.

## Code layout

- `vault/SignerVault.kt`: signers; one Android Keystore wrapping key per seed
  (`blox.seed.wrap.v1.<id>`, authentication for every use), transport keys under
  `blox.transport.wrap.v1` (no authentication), restore, removal. Migrates the single seed of
  earlier builds as the signer "Main". `vault/Biometric.kt`: BiometricPrompt with a CryptoObject.
- `store/Stores.kt`: settings (endpoints, relays), connections, stored answers (10 minutes,
  written before sending), the audit log (JSON lines).
- `relay/RelayClient.kt`: the relay API with signed requests and relay time.
  `relay/HttpEndpoint.kt`: the `EndpointRpc` foreign trait over OkHttp.
- `keystore/Keystore.kt`: inbox readers per (relay, signer), the connect flow, request review,
  approval, broadcast and answers, cancel, unbind, disconnect.
- `ui/`: home, add signer, connect, review, signer, settings, scanner.

All protocol, decoding, filling and signing logic is in Rust (`crates/blox-ffi`); the API is
described at the top of `crates/blox-ffi/src/lib.rs` and exercised by its tests.

## What to verify on a device (BLOX.md §13.4)

- [x] The app builds
- [x] The bindings pass `test-vectors/` in an instrumented test (on a test phone)
- [~] Adding a signer reports StrongBox or TEE; several signers (both TEE on a test phone); removing one deletes its key
- [ ] Approve works with fingerprint, face (class 3) and the device-PIN fallback (API 30+)
- [ ] Removing the screen lock invalidates the seed keys; restoring each signer from its phrase gives the same address; connections keep working
- [~] Connect: unknown-relay prompt, signer picker, remember-for (done); "already used" on a reused QR code
- [~] Requests appear when the app opens (within 5 minutes), grouped by site; send and messages (done); sign_tx, would-fail, no-endpoint, withdrawn
- [~] Disconnect from the site (done) and from the phone
- [ ] Screenshots and screen recording are blocked on every screen
- [ ] The app contacts only its relays and configured endpoints

## Not done yet

- Audit log in Room (currently JSON lines), its viewer, and export as a file
- More accounts per signer (v2), push (v2)
- Reproducible release builds and signing setup (§10.1)
- App icon and visual polish

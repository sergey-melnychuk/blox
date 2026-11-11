plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// ---- Rust core (crates/blox-ffi) -------------------------------------------
// Needs: rustup targets aarch64-linux-android armv7-linux-androideabi x86_64-linux-android,
// `cargo install cargo-ndk`, and an NDK installed from the SDK Manager.

val repoRoot: File = rootProject.projectDir.parentFile
val cargo: String = providers.environmentVariable("CARGO").orNull
    ?: "${System.getProperty("user.home")}/.cargo/bin/cargo"
// Release builds get every ABI. Other builds compile only arm64-v8a (phones and Apple-silicon
// emulators) to keep the Rust step ~3x faster; override with -Pblox.abis=x86_64,arm64-v8a.
val allAbis = listOf("arm64-v8a", "armeabi-v7a", "x86_64")
val abis: List<String> = providers.gradleProperty("blox.abis").orNull?.split(",")?.map { it.trim() }
    ?: if (gradle.startParameter.taskNames.any { it.contains("release", ignoreCase = true) }) allAbis else listOf("arm64-v8a")
val rustJniLibs = layout.buildDirectory.dir("rustJniLibs")
val uniffiOut = layout.buildDirectory.dir("generated/uniffi")

android {
    namespace = "wtf.oxff.blox"
    compileSdk = 36
    ndkVersion = "30.0.16248370"

    defaultConfig {
        applicationId = "wtf.oxff.blox"
        minSdk = 28
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        ndk { abiFilters += abis }
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            buildConfigField("boolean", "ALLOW_SCREENSHOTS", "false")
        }
        debug {
            // `-Pblox.screenshots` drops FLAG_SECURE so screens can be captured while working
            // on the UI. Debug builds only; never on by default.
            buildConfigField("boolean", "ALLOW_SCREENSHOTS", (findProperty("blox.screenshots") != null).toString())
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    // Plain paths (AGP 9 disallows providers here); the producing tasks run before preBuild.
    sourceSets["main"].kotlin.directories.add("build/generated/uniffi")
    sourceSets["main"].jniLibs.directories.add("build/rustJniLibs")
    // The instrumented binding test reads the repo's wire-format vectors.
    sourceSets["androidTest"].assets.directories.add("../../test-vectors")
}

val cargoNdk = tasks.register<Exec>("cargoNdk") {
    group = "rust"
    description = "Builds libblox_ffi.so for every ABI with cargo-ndk."
    workingDir = repoRoot
    inputs.dir(File(repoRoot, "crates"))
    inputs.file(File(repoRoot, "Cargo.lock"))
    outputs.dir(rustJniLibs)
    val ndk = androidComponents.sdkComponents.ndkDirectory
    doFirst {
        delete(rustJniLibs) // drop ABIs from earlier builds
        environment("ANDROID_NDK_HOME", ndk.get().asFile.absolutePath)
    }
    commandLine(
        listOf(cargo, "ndk") + abis.flatMap { listOf("-t", it) } +
            listOf("--platform", "28", "-o", rustJniLibs.get().asFile.absolutePath, "build", "--release", "-p", "blox-ffi"),
    )
}

val uniffiBindings = tasks.register<Exec>("uniffiBindings") {
    group = "rust"
    description = "Generates Kotlin bindings from the built library."
    dependsOn(cargoNdk)
    workingDir = repoRoot
    // Bindings are ABI-independent; generate them from whichever library was built.
    val triple = mapOf("arm64-v8a" to "aarch64-linux-android", "armeabi-v7a" to "armv7-linux-androideabi", "x86_64" to "x86_64-linux-android")
    val lib = File(repoRoot, "target/${triple.getValue(abis.first())}/release/libblox_ffi.so")
    inputs.file(lib)
    outputs.dir(uniffiOut)
    commandLine(
        cargo, "run", "-q", "-p", "blox-ffi", "--bin", "uniffi-bindgen", "--",
        "generate", "--library", lib.absolutePath, "--language", "kotlin", "--no-format",
        "--out-dir", uniffiOut.get().asFile.absolutePath,
    )
}

tasks.named("preBuild") { dependsOn(uniffiBindings) }

dependencies {
    val bom = platform(libs.compose.bom)
    implementation(bom)
    implementation(libs.compose.ui)
    implementation(libs.compose.material3)
    implementation(libs.compose.icons)
    implementation(libs.compose.tooling.preview)
    debugImplementation(libs.compose.tooling)
    implementation(libs.activity.compose)
    implementation(libs.fragment)
    implementation(libs.lifecycle.runtime)
    implementation(libs.lifecycle.compose)
    implementation(libs.biometric)
    implementation(libs.camerax.camera2)
    implementation(libs.camerax.lifecycle)
    implementation(libs.camerax.view)
    implementation(libs.okhttp)
    implementation(libs.okhttp.sse)
    implementation(libs.zxing.core)
    implementation(libs.coroutines.android)
    // UniFFI's generated Kotlin loads the Rust library through JNA.
    implementation("${libs.jna.get()}@aar")

    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.junit)
    androidTestImplementation(libs.junit)
}

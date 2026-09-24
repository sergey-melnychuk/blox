# UniFFI bindings call into Rust through JNA, which uses reflection.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class uniffi.blox_ffi.** { *; }
-dontwarn java.awt.**

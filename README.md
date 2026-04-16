# Halal Filter by nur

Privacy-focused DNS filtering for Android that protects Muslim app users from surveillance SDKs, data brokers, and invasive tracking.

## What it does

Halal Filter runs a local VPN on your device that intercepts DNS queries and blocks connections to known trackers — no data ever leaves your device, no remote servers involved.

**Your apps keep working.** Trackers don't.

### Benefits

- **Longer battery life** — blocks background tracker connections that drain your battery
- **Faster apps** — no ads or tracking scripts to load
- **Lower data usage** — eliminates unnecessary network traffic
- **Privacy protection** — blocks location brokers, device fingerprinting, and surveillance SDKs
- **Transparency** — see exactly what was blocked and why, in plain language

### What we block

Based on security audits of 21 popular Muslim apps, we identified and block:

| Tracker | Category | Found in |
|---------|----------|----------|
| X-Mode | Location broker → US Military | Muslim Pro |
| Predicio | Location broker → FBI/ICE via Venntel | Salaat First |
| CellRebel | Persistent location tracking | Salaat First |
| Kochava | FTC-sued for religious profiling | Athan Pro |
| ByteDance/Pangle | Chinese government-linked ads | Muslim Pro, Mustakshif |
| Tencent IMSDK | Chinese messaging SDK | Muslim Pro |
| Facebook SDK | Cross-app tracking | Nearly every app |
| + 70 more domains | Various trackers and ad networks | Multiple apps |

## How it works

```
App makes DNS query → Local VPN intercepts → Rust filter engine checks domain
  ├─ Blocked tracker → Returns 0.0.0.0 (connection refused instantly)
  └─ Legitimate domain → Forwards to Quad9 DNS (privacy-focused resolver)
```

- No root required
- No remote servers — everything runs on your device
- Open source — verify the code yourself

## Architecture

- **Core engine**: Rust — XOR16 probabilistic filter with ~65ns lookups
- **Android app**: Kotlin + Jetpack Compose + VpnService
- **Bridge**: JNI (Java Native Interface)
- **Filter size**: ~290 bytes for 81 domains (scales to 1.2MB for 500K domains)

## Building

### Prerequisites

- Rust toolchain with `aarch64-linux-android` target
- Android SDK + NDK 27
- JDK 17

### Build

```bash
# Build Rust core for Android
export ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/27.2.12479018"
cargo ndk -t arm64-v8a build --release

# Copy native library
cp target/aarch64-linux-android/release/libhalal_filter.so \
   android/app/src/main/jniLibs/arm64-v8a/

# Build filter binary
cargo run --release --bin build_filter -- \
   -o android/app/src/main/assets/filter.bin \
   data/trackers/islamic_apps.txt

# Build Android APK
cd android && ./gradlew assembleDebug
```

### Run tests

```bash
cargo test        # 34 tests
cargo bench       # Performance benchmarks
```

## Contributing

Found a tracker we're missing? Have an app that needs analysis?

- Open an issue with the app name
- We'll audit it and add relevant domains to the blocklist

## License

MIT — see [LICENSE](LICENSE)

## Disclaimer

This app blocks known tracking domains based on public research and security audits. It does not modify app code or intercept encrypted traffic. Users are responsible for complying with local laws regarding VPN usage.

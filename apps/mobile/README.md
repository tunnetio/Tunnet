# Tunnet mobile

Expo SDK 57 / React Native 0.86 foundation for the Tunnet Android client. The
route in `src/app/index.tsx` is deliberately a foundation smoke screen, not the
product UI. It verifies the development client, Uniwind, Reanimated, Gesture
Handler, protobuf decoding, the Expo module bridge, and the native VPN host.

## Runtime ownership

Rust is authoritative. `crates/tunnet-mobile` is built as
`libtunnet_mobile.so` and owns identity, membership, routing, DNS policy, and
data-plane state. `TunnetVpnService` owns only Android framework work such as
`VpnService.Builder`, descriptor protection, notification lifecycle, Keystore
wrapping, LAN permission, and Wi-Fi multicast holding.

The bridge is one Expo module at
`modules/tunnet-native`. Its public JNI surface remains:

| Export | Purpose |
| --- | --- |
| `nativeStart` | Start the service/runtime |
| `nativeStop` | Stop the requested connection |
| `nativeJoin` | Join a network after runtime attachment |
| `nativeReleaseHost` | Release the native host |
| `nativeSetLanAvailable` | Publish the Android LAN-permission fact |
| `nativeSetSnapshotListener` | Publish raw protobuf snapshots |

Snapshots cross Kotlin, Expo, and TypeScript as raw protobuf bytes. TypeScript
decodes them only at the UI boundary with the generated schema in
`src/generated/tunnet/agent_pb.ts`. Do not replace this with JSON or an
implicit Kotlin model.

## Requirements

- Bun 1.4.2
- Node.js 24
- JDK 17
- Rust toolchain from `rust-toolchain.toml`
- Android SDK platform `android-37.0`
- Android build tools `36.0.0`
- Android NDK `30.0.16248370`
- CMake `4.1.2`
- `cargo-ndk` 4.1.2
- Rust targets `aarch64-linux-android` and `x86_64-linux-android`

Install JavaScript dependencies from the repository root. `apps/mobile` is a
normal workspace member and shares the root `bun.lock`:

```sh
bun install
```

Then install the native prerequisites:

```sh
rustup target add aarch64-linux-android x86_64-linux-android
cargo install cargo-ndk --version 4.1.2 --locked
```

Set `ANDROID_HOME`/`ANDROID_SDK_ROOT`, or provide the standard SDK path in
`apps/mobile/android/local.properties` after generating native files.

### Why CMake is pinned to 4.1.2

Bun's isolated linker resolves React Native libraries through the nested
`node_modules/.bun/<pkg>@<version>/node_modules/<pkg>` store, so CMake compiles
their C++ from deeply nested paths. Two consequences on Windows:

- CMake emits `CMAKE_OBJECT_PATH_MAX` advisories because generated object paths
  run up to 249 characters against a 250-character limit. These are warnings,
  not errors.
- With the Android Gradle Plugin's default CMake 3.22.1, the bundled Ninja
  1.10.2 never settles and the build dies with
  `ninja: error: manifest 'build.ninja' still dirty after 100 tries`.

`android.cmakeVersion` is set to `4.1.2` in `app.config.ts` through
`expo-build-properties`, which applies it to the app and every autolinked native
module. CMake 4.1.2 bundles Ninja 1.12.1, which resolves the regeneration loop
and lets the isolated workspace install build cleanly. Do not lower this
without re-running a full Android build.

The path margin is real: 249 of 250 characters at the current checkout depth.
Cloning this repository much deeper, or adding dependency nesting, can push
object paths over the limit. If that happens, the fix is a shorter checkout
path or a hoisted install for this app, not a source change.

## Development

The native Android directory is generated and ignored. Do not edit it by hand;
`app.config.ts` and `plugins/with-tunnet-android.js` are the source of truth.

```sh
# From the repository root
bun run --cwd apps/mobile prebuild
bun run --cwd apps/mobile start
```

`start` uses `expo start --dev-client`. Expo Go is not supported because the
app contains a local native module.

To build, install, and launch the development app on a connected emulator or
device, run one command from the repository root:

```sh
bun run android
```

This runs `expo run:android`, which generates the native project if needed,
builds the debug APK, installs it, and starts Metro. The debug build includes
`arm64-v8a` and `x86_64`, so it runs on the Android emulator. The release build
includes `arm64-v8a` only.

To create a release APK locally:

```sh
bun run --cwd apps/mobile android:release
```

The APK is written below the generated `apps/mobile/android/app/build/` tree.
Release signing is enabled only when all of these environment variables are
present:

- `ANDROID_KEYSTORE_PATH`
- `ANDROID_KEYSTORE_PASSWORD`
- `ANDROID_KEY_ALIAS`
- `ANDROID_KEY_PASSWORD`

Without them, Gradle intentionally produces an unsigned release APK. The
release keystore is not stored in the repository.

## Checks

Fast JavaScript/TypeScript checks:

```sh
bun run --cwd apps/mobile check
```

This runs typechecking, Biome, Bun tests, and `expo install --check`. `expo-doctor` is available separately:

```sh
bun run --cwd apps/mobile doctor
```

`expo-doctor` is not part of `check` because one of its checks fails by design
here. The failing check is "no duplicate dependencies installed", which reports
the repository's Bun isolated install rather than a real defect:

- `@expo/ui`, `expo-constants`, and `expo-linking` are each reported twice at
  the same version. These are symlink-aliasing artifacts: both paths resolve to
  one entry in the `node_modules/.bun` store, so there is no second copy in the
  bundle.
- `react-native-screens` is reported at `4.26.2` (this app's pin) and `4.28.0`
  (pulled in by `expo-router`). Both exist in the store, but Gradle autolinks
  and compiles exactly one, and the verified Android build contains a single
  `react-native-screens` native library.

Expo's suggested remedy is to reinstall or delete the lockfile. Do not do that,
and do not downgrade, pin, or otherwise contort the dependency graph to satisfy
this check. `expo install --check`, which `check` does run, is the meaningful
Expo SDK compatibility gate. If a future dependency bump makes two versions of
a native module actually autolink, that is a real problem and should be fixed
then.

Native module tests and APK builds run through the generated Gradle project:

```sh
cd apps/mobile/android
./gradlew :tunnet-native:testDebugUnitTest
./gradlew :app:assembleDebug :app:assembleRelease
```

On Windows use `gradlew.bat`. The native module's Gradle task requires the
pinned NDK and `cargo-ndk` versions above. The release `lintVital` gate is
used for CI; the dependency-only `:react-native-worklets:lintAnalyzeDebug`
task currently fails in Android lint with `Cannot find a KaModule for the
VirtualFile`, while compilation, unit tests, and release lint pass.

After building, verify both ABI policy and JNI exports:

```sh
cd apps/mobile
bash scripts/check-apk.sh debug
bash scripts/check-apk.sh release
# Or pass an explicitly selected APK:
bash scripts/check-apk.sh release path/to/app-release.apk
```

The check requires `unzip` and the NDK's `llvm-nm`. It fails if a required ABI
or JNI export is missing, if release contains an emulator ABI, or if removed
legacy exports reappear.

## Formatting and generated code

The repository Biome configuration formats this app, and the pre-commit hook
formats staged files. The committed protobuf output is formatted, so the CI
drift check compares like with like:

```sh
bun run --cwd apps/mobile proto:generate
```

That script runs `buf generate` and then Biome over `src/generated`. Running
`buf generate` directly leaves unformatted output that the next script run
corrects.

`src/uniwind-types.d.ts` is not committed. Uniwind regenerates it on every
bundle, and `typecheck` regenerates it before `tsc`, so committing it would only
produce drift:

```sh
bun run --cwd apps/mobile uniwind:artifacts
```

## Android behavior

The app requests VPN consent only when the user starts or joins. LAN access and
notifications are requested at the same action; denial is reflected in native
state and does not get silently treated as success. Android backup is disabled.
The service continues to own the desired connection across ordinary lifecycle
transitions, while an explicit stop remains disconnected.

The current emulator can validate the bridge and UI, but it cannot validate the
real VPN consent dialog, arm64 release binary, Wi-Fi multicast behavior, or
device Keystore lifecycle. Those checks require a physical Android device.

## Versioning

`Cargo.toml`'s `[workspace.package].version` is the deterministic default for
Expo and Android. A release build may override it with `TUNNET_VERSION`, which
must be an exact `major.minor.patch` value (an optional leading `v` is
accepted). Android `versionCode` is:

```text
major * 10000 + minor * 100 + patch
```

Minor and patch components must each be at most 99. The app does not use
`git describe`: a dirty checkout, branch name, or abbreviated commit must not
silently become an Android version.

## EAS decision

EAS cloud builds are not configured for this foundation yet. Local development
builds and CI Gradle builds are the supported path while the Rust/cargo-ndk
toolchain and release signing are still being provisioned. Before enabling EAS,
add a project configuration, install/verify `cargo-ndk` in the cloud image,
and provide the Android keystore through EAS secrets. Do not substitute Expo
Go for a development build.

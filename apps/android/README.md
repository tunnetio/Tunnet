# Tunnet — Android app

Connects the phone to a Tunnet mesh and keeps it connected, like the desktop agent. Direct (P2P) mode.

## What it is

- **The full agent runs in-process.** Android cannot host a daemon, so `tunnetd`'s runtime is linked into the app as `libtunnet_mobile.so` (`crates/tunnet-mobile`, wrapping `crates/tunnet-agent` as a library). Desktop and mobile therefore share one runtime rather than a mobile fork of it.
- **Kotlin at the OS edge only.** `TunnetVpnService` owns the tunnel and the notification; `MainActivity` paints state. Neither holds mesh logic: every fact on screen (identity, peers, whether the data plane is up) comes from the agent through the same Local Management API the CLI and desktop app use.
- **The agent asks the app for a tunnel, not the reverse.** Only the framework can open a TUN, but only the agent knows the mesh address, so neither can go first. The agent calls `TunnetVpnService.establishTun(addrs, routes, dns, mtu)` whenever its data plane comes up, passing the addresses to assign, the routes to capture and the resolvers to advertise as three separate lists rather than one address the app has to interpret, and the app answers with a descriptor from `VpnService.Builder.establish()`. This also covers reconnects: each cycle establishes a fresh session, where a cached descriptor would point at a revoked tunnel and drop writes silently.
- **Cross-compiled as a normal Gradle step.** `cargoBuildAgent` runs `cargo build` per ABI with the NDK's clang and stages each `.so` into `jniLibs`, wired into `preBuild`. No cargo-ndk. `./gradlew :app:assembleDebug` just works.

## Build

```sh
rustup target add aarch64-linux-android x86_64-linux-android
export ANDROID_HOME=/path/to/android-sdk      # or set sdk.dir in local.properties
# Also required: JDK 17, and an NDK under $ANDROID_HOME/ndk (API 26 capable).
# rustup targets are per-toolchain, so re-run the target add after a bump.
cd apps/android
./gradlew :app:assembleDebug
```

The APK lands at `app/build/outputs/apk/debug/app-debug.apk`, signed with AGP's debug keystore. Verify it carries the agent for both ABIs:

```sh
./check-apk-abis.sh
```

## Use

1. On a machine already in the mesh: `tunnet invite <network>`.
2. Open the app and grant the VPN prompt. The app connects on open, so the agent is already running by the time you paste; the button then reads **Join** rather than **Start and join**, which is the refused-consent or explicitly-disconnected path.
3. The mesh IP and peers appear once membership syncs.

Afterwards the app reconnects on its own: the service is `START_STICKY`, and it can be set as an always-on VPN in Android's settings.

## The app excludes itself from the tunnel

`establishTun` calls `addDisallowedApplication(packageName)`. The app's own sockets carry the encrypted mesh traffic, so routing them into the tunnel would loop forever: encrypt, into the TUN, read back, encrypt again. Excluding by UID avoids that without plumbing per-socket `VpnService.protect()` into iroh.

Every **other** app still routes through the mesh, which is the point: browsers, SSH clients and the rest reach `10.x.y.z` peers transparently.

What this costs is narrow. The UI reaches the agent over a unix socket, not the mesh; ping is QUIC over iroh rather than ICMP through the TUN; file transfer is iroh streams. The real cost is future: `addDisallowedApplication` and `addAllowedApplication` are mutually exclusive, so a per-app routing feature would have to switch to `protect()`.

## Versioning and signing

`versionCode`/`versionName` come from the release tag (`TUNNET_VERSION`, else `git describe`, else the workspace Cargo version), with the semver triple folded into the monotonic integer Android sequences updates on: `major * 10000 + minor * 100 + patch`, so `v0.9.0` becomes `900`. An untagged local build keeps a placeholder; an *injected* version that cannot be folded fails the build, because a signed release carrying `versionCode = 1` could never be offered as an update.

Release signing is CI-only and gated on environment presence (`ANDROID_KEYSTORE_PATH`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`). Without it the signing config is never created and AGP emits `app-release-unsigned.apk`, so an unsigned build cannot masquerade as a signed one. Nothing about the signing identity is committed.

Installing a release-signed APK over a debug one requires uninstalling first: same `applicationId`, different key.

## Known limits (v1)

- **APK is ~108 MB** (both ABIs; roughly 46 MB of that is the arm64 agent alone), because the packaged agent still carries SSH, the session recorder, bundled SQLite and the updater, none of which a phone reaches. Trimming needs feature gates in `tunnet-agent`, which `tunnet-core` already has.
- **No DNS.** The resolver list handed to `VpnService.Builder` is empty: PeerDNS binds host loopback, which Android cannot use, since port 53 is privileged for an unprivileged app and `netd` resolves per app, so `127.0.0.1` would name the app rather than the agent. Peers are reachable by address, not by name.
- **Sealed state is not device-bound on Android.** The agent reports seal tier `derived`, but the derivation reads a machine id that does not exist here: `read_machine_id` falls into the portable arm and returns the constant `"unknown-machine"`, and `read_boot_id` returns `None`. The salt sits next to the wrapped key, so anything holding the state directory can unwrap it. App-private storage and `allowBackup="false"` keep that to rooted or extracted devices, but the tier is a stronger claim than the platform backs. Tracked separately; the fix is an Android Keystore-backed wrap, which is a change to the seal tiers rather than to this app.
- **Direct mode only.** Managed enrolment is not surfaced.
- **IPv4 only**, matching the agent's data plane. IPv6 is left outside the tunnel rather than blackholed.
- Peer list is polled (2s in the UI, 3s in the service), not driven by the agent's `/v1/events` stream.

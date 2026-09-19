# Tunnet - Android

Direct-mode mesh client. The agent runs in-process inside a `VpnService`; Kotlin only talks to the Android framework.

## Ownership

Rust (`libtunnet_mobile.so`) owns identity, membership, routing, DNS policy, data-plane lifecycle, and which sockets must bypass the TUN.

Android owns:

- `VpnService.Builder` (from a `TunRequest`: addresses, capture routes, resolvers, MTU, IPv6 passthrough, metered inheritance)
- `VpnService.protect(fd)` for those underlay FDs
- Keystore wrap/unwrap of the agent's DEK
- LAN permission and Wi-Fi multicast lock as host facts
- UI, VPN consent, notification, and whether the user wants to stay connected

State on screen and in the notification is a protobuf `Snapshot` pushed over JNI. Commands return a protobuf `NativeResult`. There is no in-app HTTP or Unix socket.

## Prerequisites

- JDK 17
- Android SDK with `platforms;android-37.0` and NDK `30.0.16248370`
- `cargo-ndk` 4.1.2 (`cargo install cargo-ndk --version 4.1.2 --locked`)
- Rust targets `aarch64-linux-android` and `x86_64-linux-android` (re-add them after a toolchain bump)

Set `ANDROID_HOME` or `sdk.dir` in `local.properties`.

```sh
cd apps/android
./gradlew :app:assembleDebug          # Windows: gradlew.bat
./check-apk-abis.sh
```

Debug APK: `app/build/outputs/apk/debug/app-debug.apk` (AGP debug keystore). It includes `arm64-v8a` and `x86_64`. Release is `arm64-v8a` only and uses the Rust `--release` profile.

## Permissions (Android 17)

Requested on Connect/Join, not at first launch:

| Permission | Effect |
|---|---|
| VPN consent (`VpnService`) | Required. Denied → no tunnel. |
| `ACCESS_LOCAL_NETWORK` | LAN/mDNS. Denied → degraded (relay/DHT still work). |
| `POST_NOTIFICATIONS` | Status notification. Optional. |

`CHANGE_WIFI_MULTICAST_STATE` is used only while Rust reports multicast demand, LAN is permitted, and a real Wi-Fi network is up. Always-on VPN is supported via Android settings; an explicit Disconnect stays disconnected.

## Use

1. On a joined desktop: `tunnet invite <network>`.
2. Open the app, tap Connect, grant VPN (and LAN if prompted). Paste the invite to join.
3. Mesh IP and peers appear when membership is admitted. Ping is OS ICMP to the peer’s mesh IPv4.

## Versioning and signing

`versionName`/`versionCode` come from `TUNNET_VERSION`, else `git describe`, else the workspace Cargo version. The integer is `major * 10000 + minor * 100 + patch` (`v0.9.0` → `900`). An injected version that cannot fold fails the build.

Release signing is CI-only (`ANDROID_KEYSTORE_PATH`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`). Missing those vars produces `app-release-unsigned.apk`. Debug and release keys differ; switching requires uninstall.

## Limits

- Direct mode only; managed enrolment is not in the UI.
- IPv4 mesh. IPv6 is allowed to bypass the VPN (`allowFamily(AF_INET6)`).
- In-TUN DNS is `192.0.2.53` (same PeerDNS engine as desktop). Device e2e for that resolver is not finished.
- Secrets are Keystore-wrapped (`io.tunnet.wrap.v1`). Files sealed with a missing or `derived` key will not activate; clear app storage and rejoin. `allowBackup` is false.
- Debug APKs are large (two ABIs, unused desktop agent surface still linked).
- TCP/UDP underlay sockets are `protect()`’d from `/proc` tables because iroh does not expose FDs. ICMP stays on the TUN so in-app ping works.

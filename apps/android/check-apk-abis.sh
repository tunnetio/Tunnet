#!/usr/bin/env bash
# BUILD-leg check: assert the built APK carries the Tunnet agent
# (libtunnet_mobile.so) for BOTH floor ABIs.
#
# A missing ABI is invisible until someone installs on that architecture and
# hits UnsatisfiedLinkError, so it is checked here rather than discovered on a
# device. Separate from the Rust test gate, which cannot host an SDK+NDK build.
#
# Usage: check-apk-abis.sh [path/to/app-debug.apk]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
apk="${1:-$here/app/build/outputs/apk/debug/app-debug.apk}"

lib="libtunnet_mobile.so"
required_abis=("arm64-v8a" "x86_64")

if [[ ! -f "$apk" ]]; then
  echo "FAIL: APK not found: $apk" >&2
  echo "      Build it first: (cd apps/android && ./gradlew :app:assembleDebug)" >&2
  exit 1
fi

entries="$(unzip -Z1 "$apk")"

missing=0
for abi in "${required_abis[@]}"; do
  path="lib/$abi/$lib"
  if grep -qxF "$path" <<<"$entries"; then
    echo "ok: $path"
  else
    echo "FAIL: missing $path in $apk" >&2
    missing=1
  fi
done

# The JNI entry points must survive the release profile's `strip = "symbols"`.
# A stripped export is an UnsatisfiedLinkError at runtime, not a build error.
if command -v llvm-nm >/dev/null 2>&1 || [[ -n "${ANDROID_NDK_HOME:-}" ]]; then
  echo "note: verify JNI exports with:"
  echo "  llvm-nm -D --defined-only target/aarch64-linux-android/release/$lib | grep Java_io_tunnet"
fi

if [[ $missing -ne 0 ]]; then
  exit 1
fi
echo "APK carries the agent for all required ABIs."

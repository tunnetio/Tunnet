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

required_exports=(
  "Java_io_tunnet_android_TunnetNative_nativeStart"
  "Java_io_tunnet_android_TunnetNative_nativeStop"
  "Java_io_tunnet_android_TunnetNative_nativeReleaseHost"
  "Java_io_tunnet_android_TunnetNative_nativeJoin"
  "Java_io_tunnet_android_TunnetNative_nativeSetSnapshotListener"
  "Java_io_tunnet_android_TunnetNative_nativeSetLanAvailable"
)
forbidden_exports=(
  "Java_io_tunnet_android_TunnetNative_nativeUp"
  "Java_io_tunnet_android_TunnetNative_nativeDown"
)
# Note this does NOT guard against `strip = "symbols"` in the release profile,
# despite what an earlier version of this comment claimed: stripping removes
# debug and local symbols, while JNI exports live in `.dynsym` and are required
# for linking, so they survive. What it does catch is the export never being
# built: a crate-type change, a renamed package (the symbol encodes the Java
# package), or a visibility change.
#
# Asserting rather than printing a suggested command: a hint that a reader might
# run is indistinguishable from a passing check once this runs in CI.
nm=""
if command -v llvm-nm >/dev/null 2>&1; then
  nm="llvm-nm"
elif [[ -n "${ANDROID_NDK_HOME:-}" ]]; then
  for prebuilt in linux-x86_64 windows-x86_64 darwin-x86_64; do
    candidate="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$prebuilt/bin/llvm-nm"
    if [[ -x "$candidate" ]]; then
      nm="$candidate"
      break
    fi
    if [[ -x "${candidate}.exe" ]]; then
      nm="${candidate}.exe"
      break
    fi
  done
fi

if [[ -z "$nm" ]]; then
  echo "note: llvm-nm not found, JNI exports NOT verified (set ANDROID_NDK_HOME to check)"
else
  workdir="$(mktemp -d)"
  trap 'rm -rf "$workdir"' EXIT
  for abi in "${required_abis[@]}"; do
    unzip -o -q "$apk" "lib/$abi/$lib" -d "$workdir"
    defined="$("$nm" -D --defined-only "$workdir/lib/$abi/$lib" 2>/dev/null || true)"
    if ! grep -q "Java_io_tunnet" <<<"$defined"; then
      echo "FAIL: $abi exports no Java_io_tunnet_*; wrong crate-type, renamed package, or hidden visibility" >&2
      missing=1
      continue
    fi
    for sym in "${required_exports[@]}"; do
      if grep -q "$sym" <<<"$defined"; then
        echo "ok: $abi exports $sym"
      else
        echo "FAIL: $abi missing $sym" >&2
        missing=1
      fi
    done
    for sym in "${forbidden_exports[@]}"; do
      if grep -q "$sym" <<<"$defined"; then
        echo "FAIL: $abi still exports removed $sym" >&2
        missing=1
      fi
    done
  done
fi

if [[ $missing -ne 0 ]]; then
  exit 1
fi
echo "APK carries the agent for all required ABIs."

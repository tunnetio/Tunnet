#!/usr/bin/env bash
# Verify the Tunnet Rust agent and JNI surface in a built Expo Android APK.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
variant="${1:-debug}"
apk="${2:-}"

case "$variant" in
  debug)
    expected_abis=(arm64-v8a x86_64)
    default_apk="$root_dir/android/app/build/outputs/apk/debug/app-debug.apk"
    ;;
  release)
    expected_abis=(arm64-v8a)
    default_apk="$root_dir/android/app/build/outputs/apk/release/app-release.apk"
    if [[ ! -f "$default_apk" ]]; then
      default_apk="$root_dir/android/app/build/outputs/apk/release/app-release-unsigned.apk"
    fi
    ;;
  *)
    echo "usage: $0 [debug|release] [path/to.apk]" >&2
    exit 2
    ;;
esac

apk="${apk:-$default_apk}"
if [[ ! -f "$apk" ]]; then
  echo "FAIL: APK not found: $apk" >&2
  echo "Build it with: bunx expo run:android --variant $variant" >&2
  exit 1
fi

if ! command -v unzip >/dev/null 2>&1; then
  echo "FAIL: unzip is required to inspect the APK" >&2
  exit 1
fi

entries="$(unzip -Z1 "$apk")"
lib="libtunnet_mobile.so"
missing=0

for abi in "${expected_abis[@]}"; do
  path="lib/$abi/$lib"
  if grep -qxF "$path" <<<"$entries"; then
    echo "ok: $variant carries $path"
  else
    echo "FAIL: $variant is missing $path" >&2
    missing=1
  fi
done

actual_abis=()
while IFS= read -r path; do
  abi="${path#lib/}"
  abi="${abi%%/*}"
  actual_abis+=("$abi")
done < <(grep -E "^lib/[^/]+/$lib$" <<<"$entries" || true)

for abi in "${actual_abis[@]}"; do
  found=0
  for expected in "${expected_abis[@]}"; do
    if [[ "$abi" == "$expected" ]]; then
      found=1
      break
    fi
  done
  if [[ $found -eq 0 ]]; then
    echo "FAIL: $variant contains unexpected Tunnet ABI: $abi" >&2
    missing=1
  fi
done

find_llvm_nm() {
  if command -v llvm-nm >/dev/null 2>&1; then
    command -v llvm-nm
    return
  fi

  normalize_path() {
    if command -v wslpath >/dev/null 2>&1; then
      wslpath -u "$1"
    elif command -v cygpath >/dev/null 2>&1; then
      cygpath -u "$1"
    else
      printf '%s\n' "$1"
    fi
  }

  local roots=()
  [[ -n "${ANDROID_NDK_HOME:-}" ]] && roots+=("$(normalize_path "$ANDROID_NDK_HOME")")

  local android_home="${ANDROID_HOME:-}"
  local android_sdk_root="${ANDROID_SDK_ROOT:-}"
  if [[ -z "$android_home" && -z "$android_sdk_root" ]] && command -v cmd.exe >/dev/null 2>&1; then
    android_home="$(cmd.exe /c 'echo %ANDROID_HOME%' 2>/dev/null | tr -d '\r')"
    android_sdk_root="$(cmd.exe /c 'echo %ANDROID_SDK_ROOT%' 2>/dev/null | tr -d '\r')"
  fi
  [[ -n "$android_home" ]] && roots+=("$(normalize_path "$android_home")/ndk/30.0.16248370")
  [[ -n "$android_sdk_root" ]] && roots+=("$(normalize_path "$android_sdk_root")/ndk/30.0.16248370")

  local local_properties="$root_dir/android/local.properties"
  if [[ -f "$local_properties" ]]; then
    local sdk_dir
    sdk_dir="$(sed -n 's/^sdk.dir=//p' "$local_properties" | head -n 1)"
    if [[ -n "$sdk_dir" ]]; then
      roots+=("$(normalize_path "$sdk_dir")/ndk/30.0.16248370")
    fi
  fi

  local root host candidate
  for root in "${roots[@]}"; do
    for host in linux-x86_64 windows-x86_64 darwin-x86_64 darwin-arm64; do
      candidate="$root/toolchains/llvm/prebuilt/$host/bin/llvm-nm"
      if [[ -x "$candidate" ]]; then
        printf '%s\n' "$candidate"
        return
      fi
      if [[ -x "$candidate.exe" ]]; then
        printf '%s\n' "$candidate.exe"
        return
      fi
    done
  done
}

nm="$(find_llvm_nm)"
if [[ -z "$nm" ]]; then
  echo "FAIL: llvm-nm not found; cannot verify JNI exports" >&2
  exit 1
fi

required_exports=(
  Java_io_tunnet_android_TunnetNative_nativeStart
  Java_io_tunnet_android_TunnetNative_nativeStop
  Java_io_tunnet_android_TunnetNative_nativeJoin
  Java_io_tunnet_android_TunnetNative_nativeReleaseHost
  Java_io_tunnet_android_TunnetNative_nativeSetLanAvailable
  Java_io_tunnet_android_TunnetNative_nativeSetSnapshotListener
)
forbidden_exports=(
  Java_io_tunnet_android_TunnetNative_nativeUp
  Java_io_tunnet_android_TunnetNative_nativeDown
)

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

for abi in "${expected_abis[@]}"; do
  path="lib/$abi/$lib"
  so="$workdir/$abi.so"
  if ! unzip -p "$apk" "$path" >"$so"; then
    echo "FAIL: could not extract $path" >&2
    missing=1
    continue
  fi

  nm_input="$so"
  if [[ "$nm" == *.exe ]] && command -v wslpath >/dev/null 2>&1; then
    nm_input="$(wslpath -w "$so")"
  fi
  defined="$($nm -D --defined-only "$nm_input" 2>/dev/null || true)"
  if [[ -z "$defined" ]]; then
    echo "FAIL: could not read dynamic symbols from $path" >&2
    missing=1
    continue
  fi

  for symbol in "${required_exports[@]}"; do
    if grep -Fq "$symbol" <<<"$defined"; then
      echo "ok: $abi exports $symbol"
    else
      echo "FAIL: $abi is missing $symbol" >&2
      missing=1
    fi
  done

  for symbol in "${forbidden_exports[@]}"; do
    if grep -Fq "$symbol" <<<"$defined"; then
      echo "FAIL: $abi still exports removed $symbol" >&2
      missing=1
    fi
  done
done

if [[ $missing -ne 0 ]]; then
  exit 1
fi

echo "APK native ABI and JNI checks passed for $variant."

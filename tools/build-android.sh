#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=${1:-"$project_dir/out/android-arm64"}
api=${ANDROID_API:-30}
ndk=${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}

if [ -z "$ndk" ]; then
    echo "ANDROID_NDK_HOME or ANDROID_NDK_ROOT must point to an Android NDK" >&2
    exit 2
fi

case "$(uname -s)" in
    Linux) host_tag=linux-x86_64 ;;
    Darwin) host_tag=darwin-x86_64 ;;
    *) echo "unsupported build host" >&2; exit 2 ;;
esac

cxx="$ndk/toolchains/llvm/prebuilt/$host_tag/bin/aarch64-linux-android${api}-clang++"
if [ ! -x "$cxx" ]; then
    echo "Android compiler not found: $cxx" >&2
    exit 2
fi

mkdir -p "$build_dir"
common_flags="-std=c++17 -O2 -g -fPIC -Wall -Wextra -Wpedantic -Wconversion"
includes="-I$project_dir/include"
sources="$project_dir/src/core/runtime.cpp $project_dir/src/activation/kpm_dry_run.cpp $project_dir/src/art/art_probe.cpp $project_dir/src/memory/memory_region.cpp $project_dir/src/loader/elf_image.cpp $project_dir/src/loader/system_library.cpp"

# shellcheck disable=SC2086
$cxx $common_flags $includes $sources "$project_dir/examples/rtgum_probe.cpp" \
    -ldl -o "$build_dir/rtgum_probe"

# shellcheck disable=SC2086
$cxx $common_flags $includes $sources "$project_dir/examples/rtgum_kpm_plan.cpp" \
    -ldl -o "$build_dir/rtgum_kpm_plan"

echo "$build_dir/rtgum_probe"
echo "$build_dir/rtgum_kpm_plan"

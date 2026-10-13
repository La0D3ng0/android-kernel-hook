#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
lock_file=${RTGUM_TOOLCHAIN_LOCK:-"$project_dir/kpm/toolchain-pixel8.lock"}
if [ ! -f "$lock_file" ]; then
    echo "toolchain lock not found: $lock_file" >&2
    exit 2
fi
# shellcheck disable=SC1090
. "$lock_file"

toolchain_root=${RTGUM_TOOLCHAIN_ROOT:-"$HOME/.local/opt"}
kernelpatch_dir=${RTGUM_KERNELPATCH_DIR:-"$HOME/.local/src/KernelPatch-$KERNELPATCH_VERSION"}
target_compile=${TARGET_COMPILE:-"$toolchain_root/$AARCH64_TOOLCHAIN_DIRECTORY/bin/aarch64-none-elf-"}
output_dir=${RTGUM_STAGE1_PROBE_OUT:-"$project_dir/out/kpm-stage1-probe-pixel8"}

if [ ! -x "${target_compile}gcc" ] || [ ! -f "$kernelpatch_dir/kernel/include/kpmodule.h" ]; then
    echo "Pixel 8 KPM toolchain or KernelPatch headers are missing" >&2
    exit 2
fi

make -C "$project_dir/kpm/stage1_probe" \
    TARGET_COMPILE="$target_compile" \
    KP_DIR="$kernelpatch_dir" \
    OUT_DIR="$output_dir"
sha256sum "$output_dir/rtgum-stage1-probe.kpm"

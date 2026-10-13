#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
lock_file=${RTGUM_TOOLCHAIN_LOCK:-"$project_dir/kpm/toolchain.lock"}

if [ ! -f "$lock_file" ]; then
    echo "toolchain lock not found: $lock_file" >&2
    exit 2
fi

# shellcheck disable=SC1090
. "$lock_file"

toolchain_root=${RTGUM_TOOLCHAIN_ROOT:-"$HOME/.local/opt"}
kernelpatch_dir=${RTGUM_KERNELPATCH_DIR:-"$HOME/.local/src/KernelPatch-$KERNELPATCH_VERSION"}
target_compile=${TARGET_COMPILE:-"$toolchain_root/$AARCH64_TOOLCHAIN_DIRECTORY/bin/aarch64-none-elf-"}
output_dir=${RTGUM_STAGE0_OUT:-"$project_dir/out/kpm-stage0"}

if [ ! -x "${target_compile}gcc" ]; then
    echo "aarch64-none-elf-gcc not found; run tools/bootstrap-kpm-kali.sh first" >&2
    exit 2
fi
if [ ! -f "$kernelpatch_dir/kernel/include/kpmodule.h" ]; then
    echo "KernelPatch headers not found; run tools/bootstrap-kpm-kali.sh first" >&2
    exit 2
fi

make -C "$project_dir/kpm/stage0" \
    TARGET_COMPILE="$target_compile" \
    KP_DIR="$kernelpatch_dir" \
    OUT_DIR="$output_dir"

sha256sum "$output_dir/rtgum-stage0.kpm"

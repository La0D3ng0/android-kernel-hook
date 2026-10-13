#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
lock_file="$project_dir/kpm/toolchain.lock"

# shellcheck disable=SC1090
. "$lock_file"

toolchain_root=${RTGUM_TOOLCHAIN_ROOT:-"$HOME/.local/opt"}
kernelpatch_dir=${RTGUM_KERNELPATCH_DIR:-"$HOME/.local/src/KernelPatch-$KERNELPATCH_VERSION"}
target_compile=${TARGET_COMPILE:-"$toolchain_root/$AARCH64_TOOLCHAIN_DIRECTORY/bin/aarch64-none-elf-"}

if [ ! -x "${target_compile}gcc" ] || [ ! -d "$kernelpatch_dir/.git" ]; then
    echo "KPM environment is incomplete; run tools/bootstrap-kpm-kali.sh first" >&2
    exit 2
fi

make -C "$kernelpatch_dir/kernel" \
    TARGET_COMPILE="$target_compile" \
    ANDROID=1 \
    hdr kpimg
make -C "$kernelpatch_dir/tools"

file "$kernelpatch_dir/kernel/kpimg" "$kernelpatch_dir/tools/kptools"
sha256sum "$kernelpatch_dir/kernel/kpimg" "$kernelpatch_dir/tools/kptools"

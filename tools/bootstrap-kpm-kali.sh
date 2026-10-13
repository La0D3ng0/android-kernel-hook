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
cache_dir=${RTGUM_DOWNLOAD_CACHE:-"$HOME/.cache/rtgum"}
archive="$cache_dir/$AARCH64_TOOLCHAIN_ARCHIVE"
toolchain_dir="$toolchain_root/$AARCH64_TOOLCHAIN_DIRECTORY"

for command_name in curl git sha256sum tar; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "required command not found: $command_name" >&2
        exit 2
    fi
done

mkdir -p "$toolchain_root" "$cache_dir" "$(dirname -- "$kernelpatch_dir")"

if [ ! -x "$toolchain_dir/bin/aarch64-none-elf-gcc" ]; then
    archive_ok=0
    if [ -f "$archive" ]; then
        actual_hash=$(sha256sum "$archive" | awk '{print $1}')
        if [ "$actual_hash" = "$AARCH64_TOOLCHAIN_SHA256" ]; then archive_ok=1; fi
    fi

    if [ "$archive_ok" -ne 1 ]; then
        partial="$archive.partial"
        rm -f "$partial"
        curl --fail --location --progress-bar --output "$partial" "$AARCH64_TOOLCHAIN_URL"
        actual_hash=$(sha256sum "$partial" | awk '{print $1}')
        if [ "$actual_hash" != "$AARCH64_TOOLCHAIN_SHA256" ]; then
            echo "toolchain checksum mismatch: expected=$AARCH64_TOOLCHAIN_SHA256 actual=$actual_hash" >&2
            exit 1
        fi
        mv "$partial" "$archive"
    fi

    tar -xzf "$archive" -C "$toolchain_root"
fi

if [ ! -d "$kernelpatch_dir/.git" ]; then
    git clone --filter=blob:none "$KERNELPATCH_REPOSITORY" "$kernelpatch_dir"
fi

current_commit=$(git -C "$kernelpatch_dir" rev-parse HEAD 2>/dev/null || true)
if [ "$current_commit" != "$KERNELPATCH_COMMIT" ]; then
    if [ -n "$(git -C "$kernelpatch_dir" status --porcelain)" ]; then
        echo "KernelPatch checkout has local changes; refusing to switch commits: $kernelpatch_dir" >&2
        exit 1
    fi
    git -C "$kernelpatch_dir" fetch --depth 1 origin "$KERNELPATCH_COMMIT"
    git -C "$kernelpatch_dir" checkout --detach "$KERNELPATCH_COMMIT"
fi

actual_commit=$(git -C "$kernelpatch_dir" rev-parse HEAD)
if [ "$actual_commit" != "$KERNELPATCH_COMMIT" ]; then
    echo "KernelPatch commit mismatch: expected=$KERNELPATCH_COMMIT actual=$actual_commit" >&2
    exit 1
fi

"$toolchain_dir/bin/aarch64-none-elf-gcc" --version | head -1
printf 'kernelpatch=%s\n' "$kernelpatch_dir"
printf 'kernelpatch_commit=%s\n' "$actual_commit"
printf 'TARGET_COMPILE=%s/bin/aarch64-none-elf-\n' "$toolchain_dir"

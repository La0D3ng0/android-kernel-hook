#!/usr/bin/env sh
set -eu

binary=${1:-"$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/out/android-arm64/rtgum_probe"}
library=${2:-}
remote=/data/local/tmp/rtgum_probe

if [ ! -f "$binary" ]; then
    echo "probe binary not found: $binary" >&2
    exit 2
fi

adb push "$binary" "$remote"
adb shell chmod 0755 "$remote"
if [ -n "$library" ]; then
    adb shell "$remote" "$library"
else
    adb shell "$remote"
fi


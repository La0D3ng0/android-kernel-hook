#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
kpm=${1:-"$project_dir/out/kpm-stage0/rtgum-stage0.kpm"}
client=${2:-"$project_dir/out/kpm-stage0/rtgum-stage0-ctl"}
remote_dir=/data/local/tmp/rtgum-stage0

if [ -z "${RTGUM_SUPERKEY:-}" ]; then
    echo "RTGUM_SUPERKEY is required" >&2
    exit 2
fi
case "$RTGUM_SUPERKEY" in
    *[!A-Za-z0-9._-]*|'')
        echo "RTGUM_SUPERKEY must contain only letters, digits, dot, underscore, or dash" >&2
        exit 2
        ;;
esac
if [ "${#RTGUM_SUPERKEY}" -ge 64 ]; then
    echo "RTGUM_SUPERKEY must be shorter than 64 bytes" >&2
    exit 2
fi
if [ ! -f "$kpm" ] || [ ! -f "$client" ]; then
    echo "stage-0 artifact missing: kpm=$kpm client=$client" >&2
    exit 2
fi

device_count=$(adb devices | awk 'NR > 1 && $2 == "device" { count++ } END { print count + 0 }')
if [ "$device_count" -ne 1 ]; then
    echo "expected exactly one online ADB device, found $device_count" >&2
    exit 2
fi

adb shell "mkdir -p $remote_dir"
adb push "$kpm" "$remote_dir/rtgum-stage0.kpm"
adb push "$client" "$remote_dir/rtgum-stage0-ctl"
adb shell "chmod 0755 $remote_dir/rtgum-stage0-ctl"

run="RTGUM_SUPERKEY=$RTGUM_SUPERKEY $remote_dir/rtgum-stage0-ctl"

if ! adb shell "$run ready"; then
    echo "KernelPatch SuperCall is unavailable. Do not attempt KPM load until the device boots a KernelPatch/APatch-patched kernel." >&2
    exit 1
fi

adb shell "$run smoke $remote_dir/rtgum-stage0.kpm"
adb shell "$run info"
adb shell "$run list"

echo "--- recent kernel messages ---"
adb shell "$run dmesg" 2>/dev/null | tail -n 160 | grep -E 'rtgum-stage0|KernelPatch| KP ' || true

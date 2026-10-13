#!/usr/bin/env sh
set -eu

kernel=$(adb shell uname -r | tr -d '\r')
root_id=$(adb shell 'if command -v su >/dev/null 2>&1; then su -c id; else id; fi' | tr -d '\r')
abi=$(adb shell getprop ro.product.cpu.abi | tr -d '\r')
android_release=$(adb shell getprop ro.build.version.release | tr -d '\r')
boot_locked=$(adb shell getprop ro.boot.flash.locked | tr -d '\r')
verified_boot=$(adb shell getprop ro.boot.verifiedbootstate | tr -d '\r')

kernelpatch_host=0
apatch_host=0
kpm_directory=0
magisk_host=0

if adb shell su -c 'test -d /data/adb/kernelpatch' >/dev/null 2>&1 || \
   adb shell su -c 'test -d /data/adb/kp' >/dev/null 2>&1; then
    kernelpatch_host=1
fi
if adb shell su -c 'test -d /data/adb/ap' >/dev/null 2>&1 || \
   adb shell su -c 'test -f /data/adb/apd' >/dev/null 2>&1; then
    apatch_host=1
fi
if adb shell su -c 'test -d /data/adb/kpm' >/dev/null 2>&1; then
    kpm_directory=1
fi
if adb shell su -c 'test -d /data/adb/magisk' >/dev/null 2>&1; then
    magisk_host=1
fi

echo "kernel=$kernel"
echo "root=$root_id"
echo "abi=$abi"
echo "android=$android_release"
echo "boot_flash_locked=$boot_locked"
echo "verified_boot_state=$verified_boot"
echo "kernelpatch_host=$kernelpatch_host"
echo "apatch_host=$apatch_host"
echo "kpm_directory=$kpm_directory"
echo "magisk_host=$magisk_host"

if [ -n "${RTGUM_SUPERKEY:-}" ] && adb shell test -x /data/local/tmp/rtgum-stage0/rtgum-stage0-ctl; then
    case "$RTGUM_SUPERKEY" in
        *[!A-Za-z0-9._-]*|'') echo "supercall_ready=invalid-key-format" ;;
        *)
            if adb shell "RTGUM_SUPERKEY=$RTGUM_SUPERKEY /data/local/tmp/rtgum-stage0/rtgum-stage0-ctl ready"; then
                echo "supercall_ready=1"
            else
                echo "supercall_ready=0"
            fi
            ;;
    esac
fi

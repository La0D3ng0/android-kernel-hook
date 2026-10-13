#!/system/bin/sh

set -eu

work_dir="${1:-}"
boot_name="${2:-boot-current-grus.img}"
output_name="${3:-boot-stock-reconstructed-grus.img}"

case "$work_dir" in
    /data/local/tmp/rtgum-reconstruct-*) ;;
    *)
        echo "work directory must be under /data/local/tmp/rtgum-reconstruct-*" >&2
        exit 2
        ;;
esac

case "$boot_name:$output_name" in
    *[!A-Za-z0-9._:-]*)
        echo "boot and output names may only contain letters, digits, dot, underscore, or dash" >&2
        exit 2
        ;;
esac

cd "$work_dir"

[ -f magiskboot ] || { echo "missing $work_dir/magiskboot" >&2; exit 2; }
[ -f "$boot_name" ] || { echo "missing $work_dir/$boot_name" >&2; exit 2; }
[ ! -e "$output_name" ] || { echo "$work_dir/$output_name already exists" >&2; exit 2; }

for generated in kernel kernel.magisk ramdisk.cpio ramdisk.restored-empty.cpio \
                 kernel_dtb dtb extra config.orig; do
    [ ! -e "$generated" ] || {
        echo "$work_dir is not a fresh unpack directory ($generated exists)" >&2
        exit 2
    }
done

chmod 0700 magiskboot
./magiskboot unpack "$boot_name"

[ -f kernel ] || { echo "unpack did not produce a kernel" >&2; exit 1; }
[ -f ramdisk.cpio ] || { echo "expected the Magisk ramdisk" >&2; exit 1; }
cp -p kernel kernel.magisk

set +e
./magiskboot cpio ramdisk.cpio test
cpio_status=$?
set -e
if [ $((cpio_status & 3)) -ne 1 ]; then
    echo "expected a Magisk-patched ramdisk, status=$cpio_status" >&2
    exit 1
fi

./magiskboot cpio ramdisk.cpio \
    "extract .backup/.magisk config.orig" \
    "restore"

# This device is legacy system-as-root. Its stock boot has ramdisk_size=0;
# Magisk's restore operation leaves a valid but empty 124-byte CPIO archive.
# Preserve that archive for audit, but keep it out of magiskboot's repack input.
mv ramdisk.cpio ramdisk.restored-empty.cpio

# Undo Magisk's legacy-SAR kernel change: want_initramfs -> skip_initramfs.
./magiskboot hexpatch kernel \
    77616E745F696E697472616D667300 \
    736B69705F696E697472616D667300

./magiskboot repack "$boot_name" "$output_name"

echo "reconstructed stock boot: $work_dir/$output_name"
sha256sum kernel.magisk kernel "$output_name"
[ -f kernel_dtb ] && sha256sum kernel_dtb
[ -f dtb ] && sha256sum dtb
ls -l ramdisk.restored-empty.cpio "$output_name"

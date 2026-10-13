#!/system/bin/sh

set -eu

work_dir="${1:-}"
boot_name="${2:-boot-stock-reconstructed-grus.img}"
output_name="${3:-boot-kernelpatch-0.12.2-stock-grus.img}"

case "$work_dir" in
    /data/local/tmp/rtgum-kp0122-*) ;;
    *)
        echo "work directory must be under /data/local/tmp/rtgum-kp0122-*" >&2
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

for required in magiskboot kptools kpimg superkey.txt "$boot_name"; do
    [ -f "$required" ] || { echo "missing $work_dir/$required" >&2; exit 2; }
done
[ ! -e "$output_name" ] || { echo "$work_dir/$output_name already exists" >&2; exit 2; }

for generated in kernel kernel.ori ramdisk.cpio kernel_dtb dtb extra new-boot.img; do
    [ ! -e "$generated" ] || {
        echo "$work_dir is not a fresh unpack directory ($generated exists)" >&2
        exit 2
    }
done

chmod 0700 magiskboot kptools
chmod 0600 superkey.txt
superkey=$(tr -d '\r\n' < superkey.txt)
case "$superkey" in
    ''|*[!A-Za-z0-9._-]*)
        echo "invalid SuperKey file" >&2
        exit 2
        ;;
esac
[ "${#superkey}" -lt 64 ] || { echo "SuperKey is too long" >&2; exit 2; }

./magiskboot unpack "$boot_name"
[ -f kernel ] || { echo "unpack did not produce a kernel" >&2; exit 1; }
[ ! -e ramdisk.cpio ] || { echo "stock base unexpectedly contains a ramdisk" >&2; exit 1; }

./kptools -i kernel -f | grep -q '^CONFIG_KALLSYMS=y$' || {
    echo "kernel lacks CONFIG_KALLSYMS=y" >&2
    exit 1
}

mv kernel kernel.ori
./kptools -p -i kernel.ori -S "$superkey" -k kpimg -o kernel
unset superkey

./kptools -i kernel -l | grep -E 'patched=true|version=' || true
./magiskboot repack "$boot_name"
[ -f new-boot.img ] || { echo "repack did not produce new-boot.img" >&2; exit 1; }
mv new-boot.img "$output_name"

echo "KernelPatch boot candidate: $work_dir/$output_name"
sha256sum kernel.ori kernel "$output_name"
[ -f kernel_dtb ] && sha256sum kernel_dtb
[ -f dtb ] && sha256sum dtb
ls -l "$output_name"

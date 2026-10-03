#!/bin/bash
# Build a minimal Debian guest image. Run on a Linux host with debootstrap.
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo 'Run as root: sudo deploy/microvm/build-rootfs.sh OUTPUT.ext4' >&2
    exit 1
fi
if [[ $# -ne 1 ]]; then
    echo 'Usage: build-rootfs.sh OUTPUT.ext4' >&2
    exit 1
fi
for tool in debootstrap mkfs.ext4 truncate; do
    command -v "$tool" >/dev/null || { echo "Missing $tool" >&2; exit 1; }
done

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
output=$(realpath -m "$1")
if [[ -e $output ]]; then
    echo "Refusing to overwrite $output" >&2
    exit 1
fi
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

debootstrap --variant=minbase --include=python3,iproute2,busybox-static,util-linux \
    trixie "$tmpdir/root" https://deb.debian.org/debian
mkdir -p "$tmpdir/root/app" "$tmpdir/root/proc" "$tmpdir/root/sys" "$tmpdir/root/dev"
cp -a "$project_dir/swarm" "$tmpdir/root/app/"
install -m 0755 "$project_dir/deploy/microvm/guest-init.sh" "$tmpdir/root/sbin/sentinel-guest-init"
rm -f "$tmpdir/root/sbin/init"
ln -s /sbin/sentinel-guest-init "$tmpdir/root/sbin/init"
find "$tmpdir/root/app" -type d -name __pycache__ -prune -exec rm -rf {} +

truncate -s 1G "$output"
if ! mkfs.ext4 -q -F -d "$tmpdir/root" "$output"; then
    rm -f "$output"
    exit 1
fi
chmod 0644 "$output"
echo "Built $output"

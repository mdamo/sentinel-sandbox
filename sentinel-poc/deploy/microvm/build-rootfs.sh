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
if [[ -n ${EXECUTION_GUEST_TOKEN_FILE:-} || -n ${EXECUTION_CA_FILE:-} ]]; then
    : "${EXECUTION_GUEST_TOKEN_FILE:?Set the non-admin agent token file}"
    : "${EXECUTION_CA_FILE:?Set the public CA/certificate file}"
    : "${EXECUTION_HOST_WORKSPACE:?Set the host workspace absolute path for the isolation check}"
    install -m 0400 -o 10002 -g 10002 "$EXECUTION_GUEST_TOKEN_FILE" "$tmpdir/root/app/execution.token"
    install -m 0444 "$EXECUTION_CA_FILE" "$tmpdir/root/app/execution-ca.pem"
    python3 - "$EXECUTION_HOST_WORKSPACE" "$tmpdir/root/app/execution-boot.json" <<'PY'
import json
import sys
with open(sys.argv[2], "w") as destination:
    json.dump({"host_workspace": sys.argv[1]}, destination)
PY
fi
install -m 0755 "$project_dir/deploy/microvm/guest-init.sh" "$tmpdir/root/sbin/sentinel-guest-init"
rm -f "$tmpdir/root/sbin/init"
ln -s /sbin/sentinel-guest-init "$tmpdir/root/sbin/init"
find "$tmpdir/root/app" -type d -name __pycache__ -prune -exec rm -rf {} +

truncate -s 1G "$output"
if ! mkfs.ext4 -q -F -d "$tmpdir/root" "$output"; then
    rm -f "$output"
    exit 1
fi
if [[ -n ${EXECUTION_GUEST_TOKEN_FILE:-} ]]; then
    chmod 0600 "$output"  # Image now contains a scoped agent credential.
else
    chmod 0644 "$output"
fi
echo "Built $output"

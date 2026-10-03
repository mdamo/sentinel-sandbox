#!/bin/bash
# Linux/KVM PoC launcher. Root is needed only for TAP and nftables setup.
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
kernel=${KERNEL_IMAGE:-}
rootfs=${ROOTFS_IMAGE:-}
tap=senttap0
table=sentinel_poc_vm
sentinel_pid=
workdir=

cleanup() {
    echo '[launcher | host] cleaning up sentinel process, guest TAP and firewall'
    [[ -z $sentinel_pid ]] || { kill "$sentinel_pid" 2>/dev/null || true; wait "$sentinel_pid" 2>/dev/null || true; }
    nft delete table inet "$table" 2>/dev/null || true
    ip link delete "$tap" 2>/dev/null || true
    [[ -z $workdir ]] || rm -rf "$workdir"
}

if [[ ${EUID} -ne 0 || $(uname -s) != Linux ]]; then
    echo 'Run this launcher as root on a Linux KVM host.' >&2
    exit 1
fi
if [[ -z $kernel || -z $rootfs || ! -f $kernel || ! -f $rootfs ]]; then
    echo 'Set KERNEL_IMAGE and ROOTFS_IMAGE to existing guest images.' >&2
    exit 1
fi
for tool in firecracker nft ip python3.13; do
    command -v "$tool" >/dev/null || { echo "Missing $tool" >&2; exit 1; }
done
if [[ ! -r /dev/kvm ]]; then
    echo '/dev/kvm is unavailable.' >&2
    exit 1
fi
if ip link show "$tap" >/dev/null 2>&1 || nft list table inet "$table" >/dev/null 2>&1; then
    echo 'sentinel PoC TAP or firewall table already exists; refusing to replace it.' >&2
    exit 1
fi

kernel=$(realpath "$kernel")
rootfs=$(realpath "$rootfs")
workdir=$(mktemp -d)
trap cleanup EXIT INT TERM
echo "[microVM | host] preparing Firecracker kernel=$kernel rootfs=$rootfs vcpus=1 memory=256MiB"

ip tuntap add dev "$tap" mode tap
ip addr add 172.16.0.1/30 dev "$tap"
ip link set "$tap" up

# The guest can only reach the sentinel on the host. In particular, it cannot
# forward through the host or reach another host service, even with a route.
nft add table inet "$table"
nft 'add chain inet sentinel_poc_vm input { type filter hook input priority -50; policy accept; }'
nft 'add chain inet sentinel_poc_vm forward { type filter hook forward priority -50; policy accept; }'
nft add rule inet "$table" input iifname "$tap" ip saddr 172.16.0.2 ip daddr 172.16.0.1 tcp dport 8085 accept
nft add rule inet "$table" input iifname "$tap" drop
nft add rule inet "$table" forward iifname "$tap" drop
echo "[network | host] tap=$tap host=172.16.0.1 guest=172.16.0.2; guest access limited to sentinel TCP/8085"

cd "$project_dir"
SENTINEL_BIND=172.16.0.1:8085 python3.13 -m sentinel.serve &
sentinel_pid=$!
echo "[sentinel | host] launched pid=$sentinel_pid; waiting for service ready log"

python3.13 - "$kernel" "$rootfs" "$tap" "$workdir/vm.json" <<'PY'
import json
import sys

kernel, rootfs, tap, output = sys.argv[1:]
boot_args = "console=ttyS0 reboot=k panic=1 root=/dev/vda ro init=/sbin/init"
if __import__("platform").machine() == "aarch64":
    boot_args = "keep_bootcon " + boot_args
config = {
    "boot-source": {
        "kernel_image_path": kernel,
        "boot_args": boot_args,
    },
    "drives": [{
        "drive_id": "rootfs", "path_on_host": rootfs,
        "is_root_device": True, "is_read_only": True,
    }],
    "machine-config": {"vcpu_count": 1, "mem_size_mib": 256, "smt": False},
    "network-interfaces": [{
        "iface_id": "sentinel", "host_dev_name": tap,
        "guest_mac": "06:00:ac:10:00:02",
    }],
}
with open(output, "w", encoding="utf-8") as file:
    json.dump(config, file)
PY

echo '[microVM | host] starting Firecracker; guest boot and agent logs follow on serial console'
firecracker --no-api --config-file "$workdir/vm.json"

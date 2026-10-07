#!/bin/bash
# Linux/KVM integration test: boot the real guest, verify host mediation, exit.
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
launcher="$project_dir/deploy/microvm/run.sh"

if [[ $(uname -s) != Linux || ! -r /dev/kvm ]]; then
    echo 'SKIP: Firecracker boot test requires a Linux host with /dev/kvm.' >&2
    exit 77
fi
if [[ ${EUID} -ne 0 ]]; then
    echo 'Run as root; the launcher must create a TAP and nftables rules.' >&2
    exit 1
fi
if [[ -z ${KERNEL_IMAGE:-} || -z ${ROOTFS_IMAGE:-} ]]; then
    echo 'Set KERNEL_IMAGE and ROOTFS_IMAGE before running this test.' >&2
    exit 1
fi
if ! command -v timeout >/dev/null; then
    echo 'Missing GNU timeout (coreutils).' >&2
    exit 1
fi

log=$(mktemp)
trap 'rm -f "$log"' EXIT

# Firecracker exits when guest PID 1 reboots. Bound the run so a failed boot or
# unreachable sentinel cannot hang CI indefinitely. The launcher removes its
# TAP and firewall table on exit.
if timeout --signal=TERM --kill-after=5s 120s "$launcher" >"$log" 2>&1; then
    :
else
    status=$?
    cat "$log"
    echo "FAIL: Firecracker launcher exited with status $status." >&2
    exit 1
fi

if [[ -n ${SENTINEL_EXEC_CONFIG:-} ]]; then
    if ! grep -Fq 'SENTINEL_EXECUTION_BOOT_PASS authentication adapters direct-access-denied' "$log" || \
       grep -Fq 'SENTINEL_BOOT_TEST_FAIL' "$log"; then
        cat "$log"
        echo 'FAIL: authenticated execution or guest isolation checks failed.' >&2
        exit 1
    fi
    echo 'PASS: guest authenticated to trusted adapters; direct-access checks denied.'
    exit 0
fi
if ! grep -Fq 'SENTINEL_BOOT_TEST_PASS' "$log" || \
   grep -Fq 'SENTINEL_BOOT_TEST_FAIL' "$log" || \
   ! grep -Fq 'drop.attacker.example' "$log" || \
   ! grep -Fq 'egress-allowlist' "$log"; then
    cat "$log"
    echo 'FAIL: guest did not prove expected allow and deny decisions.' >&2
    exit 1
fi

echo 'PASS: Firecracker guest booted and the host sentinel mediated all three actions.'

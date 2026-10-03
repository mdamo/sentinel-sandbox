#!/bin/sh
# PID 1 inside the Firecracker guest. The root filesystem is mounted read-only.
set -eu
echo '[microVM | guest] booted; configuring read-only guest networking'

/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev
/usr/sbin/ip link set lo up
/usr/sbin/ip addr add 172.16.0.2/30 dev eth0
/usr/sbin/ip link set eth0 up

# There is deliberately no default route. The host firewall also blocks every
# guest packet except HTTP to the sentinel, even if guest networking is changed.
export BROKER_URL=http://172.16.0.1:8085/submit
export AGENT_RUNTIME='microVM guest'
export PYTHONDONTWRITEBYTECODE=1
cd /app
echo '[agents | microVM guest] launching agent-1 as uid=10002; guest=172.16.0.2; sentinel=172.16.0.1:8085'
if /usr/bin/setpriv --reuid=10002 --regid=10002 --clear-groups \
    /usr/bin/python3 -B -m swarm.agent_client; then
    echo SENTINEL_BOOT_TEST_PASS
else
    echo SENTINEL_BOOT_TEST_FAIL
fi
echo '[microVM | guest] agent run finished; shutting down guest'
/bin/busybox reboot -f

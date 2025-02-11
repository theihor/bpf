#!/bin/bash

/bin/mount bpffs /sys/fs/bpf -t bpf
ip link set lo up

echo 10 > /proc/sys/kernel/hung_task_timeout_secs
echo 1 >/sys/kernel/debug/tracing/events/netfs/netfs_read/enable
echo 1 >/sys/kernel/debug/tracing/events/netfs/netfs_write/enable
echo 1 >/sys/kernel/debug/tracing/events/netfs/netfs_write_iter/enable
echo 1 >/sys/kernel/debug/tracing/events/netfs/netfs_rreq/enable
echo 1 >/sys/kernel/debug/tracing/events/netfs/netfs_rreq_ref/enable
echo 1 >/sys/kernel/debug/tracing/events/netfs/netfs_sreq/enable
echo 1 >/sys/kernel/debug/tracing/events/netfs/netfs_sreq_ref/enable
echo 1 >/sys/kernel/debug/tracing/events/netfs/netfs_failure/enable

echo 1 >/sys/kernel/debug/tracing/events/netfs/netfs_collect/enable
echo 1 >/sys/kernel/debug/tracing/events/netfs/netfs_collect_sreq/enable
echo 1 >/sys/kernel/debug/tracing/events/netfs/netfs_collect_state/enable

function tail_proc {
    src=$1
    dst=$2
    echo -n > $dst
    while true; do
        echo >> $dst
        cat $src >> $dst
        sleep 1
    done
}
export -f tail_proc

nohup bash -c 'tail_proc /proc/fs/netfs/stats netfs-stats.log' & disown
nohup bash -c 'tail_proc /proc/fs/netfs/requests netfs-requests.log' & disown
nohup bash -c 'trace-cmd show -p > trace-cmd.log' & disown

cd tools/testing/selftests/bpf
./test_progs-no_alu32 -j


// SPDX-License-Identifier: GPL-2.0
/* Probe: subprog acquires RCU lock and throws */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"

extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

__noinline static int lock_then_throw_sub(void)
{
	bpf_rcu_read_lock();
	bpf_throw(0);
	return 0;
}

SEC("tc")
int throw_rcu_in_subprog(void *ctx)
{
	lock_then_throw_sub();
	return 0;
}

char _license[] SEC("license") = "GPL";

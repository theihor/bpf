// SPDX-License-Identifier: GPL-2.0
/* Probe: always-throwing subprog, caller holds RCU lock */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"

extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

__noinline static int always_throws_sub(void)
{
	bpf_throw(0);
	return 0;
}

SEC("tc")
int throw_rcu_subprog_always(void *ctx)
{
	bpf_rcu_read_lock();
	always_throws_sub();
	bpf_rcu_read_unlock();
	return 0;
}

char _license[] SEC("license") = "GPL";

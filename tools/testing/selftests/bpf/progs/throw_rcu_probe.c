// SPDX-License-Identifier: GPL-2.0
/* Standalone probe: bpf_throw + RCU lock from subprog.
 * Each SEC has a unique name so we can load selectively.
 */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"

extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

/* Test 1: Baseline — bpf_throw + RCU in main (should be rejected) */
SEC("tc")
int throw_rcu_main(void *ctx)
{
	bpf_rcu_read_lock();
	bpf_throw(0);
	return 0;
}

/* Test 2: always-throwing subprog, caller holds RCU lock */
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

/* Test 3: subprog acquires RCU lock and throws */
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

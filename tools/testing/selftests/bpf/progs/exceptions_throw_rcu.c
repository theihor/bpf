// SPDX-License-Identifier: GPL-2.0
/* Test: bpf_throw from subprog while holding RCU/locks.
 *
 * The verifier's check_resource_leak() uses check_lock=!curframe.
 * When bpf_throw is called from a static subprog (curframe > 0),
 * check_lock is false and active_rcu_locks / active_preempt_locks
 * are not validated. This means RCU lock leaks via exception exit
 * from subprogs may escape verification.
 */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#include "bpf_misc.h"
#include "bpf_experimental.h"

extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

/* --- Baseline: bpf_throw + RCU in main prog is correctly rejected --- */

SEC("?tc")
__failure __msg("BPF_EXIT instruction in main prog cannot be used inside bpf_rcu_read_lock-ed region")
int throw_rcu_main_reject(void *ctx)
{
	bpf_rcu_read_lock();
	bpf_throw(0);
	return 0;
}

/* --- Gap test: subprog that always throws, caller holds RCU lock --- */

__noinline static int always_throws(void)
{
	bpf_throw(0);
	return 0;
}

SEC("?tc")
__failure __msg("BPF_EXIT instruction in main prog cannot be used inside bpf_rcu_read_lock-ed region")
int throw_rcu_subprog_always(void *ctx)
{
	bpf_rcu_read_lock();
	always_throws();
	/* never reached — subprog always throws */
	bpf_rcu_read_unlock();
	return 0;
}

/* --- Gap test: subprog acquires RCU lock then throws --- */

__noinline static int lock_then_throw(void)
{
	bpf_rcu_read_lock();
	bpf_throw(0);
	return 0;
}

SEC("?tc")
__failure __msg("inside bpf_rcu_read_lock-ed region")
int throw_rcu_in_subprog(void *ctx)
{
	lock_then_throw();
	return 0;
}

/* --- Gap test: conditional throw, one path leaks RCU --- */

__noinline static int maybe_throws(struct __sk_buff *ctx)
{
	bpf_rcu_read_lock();
	if (ctx->len > 100)
		bpf_throw(0);  /* exception path leaks RCU lock */
	bpf_rcu_read_unlock();
	return 0;
}

SEC("?tc")
__failure __msg("inside bpf_rcu_read_lock-ed region")
int throw_rcu_conditional_subprog(void *ctx)
{
	maybe_throws(ctx);
	return 0;
}

char _license[] SEC("license") = "GPL";

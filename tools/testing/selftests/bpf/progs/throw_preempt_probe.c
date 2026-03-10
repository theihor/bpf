// SPDX-License-Identifier: GPL-2.0
/* Probe: bpf_throw from subprog while preempt-disabled */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"

extern void bpf_preempt_disable(void) __ksym;
extern void bpf_preempt_enable(void) __ksym;

__noinline static int always_throws_sub(void)
{
	bpf_throw(0);
	return 0;
}

SEC("tc")
int throw_preempt_subprog(void *ctx)
{
	bpf_preempt_disable();
	always_throws_sub();
	bpf_preempt_enable();
	return 0;
}

char _license[] SEC("license") = "GPL";

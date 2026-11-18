// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

int tid;
__u64 fentry_c;
char fentry_a;
int fexit_b, fexit_ret;
long sys_enter_id;
int lsm_cmd, lsm_ret, lsm_has_cmd, lsm_has_nonexistent;
unsigned int lsm_size;
int setsockopt_optlen;
void *setsockopt_optval;
unsigned long mmap_ino, mmap_prot;
__u16 rst_port;
int rst_seen;

static bool is_tid(void)
{
	return (__u32)bpf_get_current_pid_tgid() == tid;
}

/* bpf_fentry_test3(char a, int b, u64 c), arguments in a different order */
SEC("fentry/bpf_fentry_test3")
int BPF_PROG_ARGS(fentry_args, __u64, c, char, a)
{
	fentry_c = c;
	fentry_a = a;
	return 0;
}

SEC("fexit/bpf_fentry_test3")
int BPF_PROG_ARGS(fexit_args, int, ret, int, b)
{
	fexit_ret = ret;
	fexit_b = b;
	return 0;
}

SEC("tp_btf/sys_enter")
int BPF_PROG_ARGS(tp_btf_args, long, id)
{
	if (is_tid())
		sys_enter_id = id;
	return 0;
}

struct bpf_func_args___opt {
	int cmd;
	int nonexistent;
} __attribute__((preserve_access_index));

SEC("lsm/bpf")
int BPF_PROG_ARGS(lsm_args, unsigned int, size, int, cmd, int, ret)
{
	struct bpf_func_args___opt *args = (void *)ctx;

	if (!is_tid() || cmd != BPF_PROG_TEST_RUN)
		return ret;
	lsm_cmd = cmd;
	lsm_size = size;
	lsm_ret = ret;
	lsm_has_cmd = bpf_core_field_exists(args->cmd);
	lsm_has_nonexistent = bpf_core_field_exists(args->nonexistent);
	return ret;
}

/* do_sock_setsockopt(sock, compat, level, optname, sockptr_t optval, optlen):
 * 16-byte optval takes two context slots
 */
struct bpf_func_args___setsockopt {
	sockptr_t optval;
} __attribute__((preserve_access_index));

SEC("fentry/do_sock_setsockopt")
int BPF_PROG_ARGS(struct_arg, int, optlen)
{
	struct bpf_func_args___setsockopt *args = (void *)ctx;

	if (!is_tid())
		return 0;
	setsockopt_optval = args->optval.user;
	setsockopt_optlen = optlen;
	return 0;
}

/* bpf_lsm_mmap_file(struct file *file__nullable, ...) */
SEC("lsm/mmap_file")
int BPF_PROG_ARGS(nullable_lsm, struct file *, file, unsigned long, prot, int, ret)
{
	if (is_tid() && file) {
		mmap_ino = file->f_inode->i_ino;
		mmap_prot = prot;
	}
	return ret;
}

/* tcp_send_reset(const struct sock *sk, const struct sk_buff *skb__nullable, ...) */
SEC("tp_btf/tcp_send_reset")
int BPF_PROG_ARGS(nullable_tp_btf, const struct sk_buff *, skb)
{
	const struct tcphdr *th;
	__u16 dport;

	if (!skb)
		return 0;
	th = (void *)(skb->head + skb->transport_header);
	if (!bpf_probe_read_kernel(&dport, sizeof(dport), &th->dest) && dport == rst_port)
		rst_seen = 1;
	return 0;
}

SEC("?fentry/bpf_fentry_test3")
int BPF_PROG_ARGS(missing_arg, int, d)
{
	fexit_b = d;
	return 0;
}

SEC("?fentry/bpf_fentry_test3")
int BPF_PROG_ARGS(type_mismatch, __u64, b)
{
	fentry_c = b;
	return 0;
}

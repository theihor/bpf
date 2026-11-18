// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include "named_args.skel.h"

static void test_success(void)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	socklen_t addr_len = sizeof(addr);
	struct named_args *skel;
	int fd, val = 1 << 16;
	struct stat st;
	void *mem;

	skel = named_args__open_and_load();
	if (!ASSERT_OK_PTR(skel, "named_args__open_and_load"))
		return;
	skel->bss->tid = sys_gettid();

	if (!ASSERT_OK(named_args__attach(skel), "named_args__attach"))
		goto out;

	/* calls bpf_fentry_test3(4, 5, 6) */
	ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.fentry_args), &topts),
		  "test_run");
	ASSERT_EQ(skel->bss->fentry_a, 4, "fentry_a");
	ASSERT_EQ(skel->bss->fentry_c, 6, "fentry_c");
	ASSERT_EQ(skel->bss->fexit_b, 5, "fexit_b");
	ASSERT_EQ(skel->bss->fexit_ret, 15, "fexit_ret");

	ASSERT_EQ(skel->bss->lsm_cmd, BPF_PROG_TEST_RUN, "lsm_cmd");
	ASSERT_EQ(skel->bss->lsm_size, offsetofend(union bpf_attr, test), "lsm_size");
	ASSERT_EQ(skel->bss->lsm_ret, 0, "lsm_ret");
	ASSERT_EQ(skel->bss->lsm_has_cmd, 1, "lsm_has_cmd");
	ASSERT_EQ(skel->bss->lsm_has_nonexistent, 0, "lsm_has_nonexistent");

	syscall(__NR_getppid);
	ASSERT_EQ(skel->bss->sys_enter_id, __NR_getppid, "sys_enter_id");

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (!ASSERT_OK_FD(fd, "socket"))
		goto out;
	ASSERT_OK(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val)), "setsockopt");
	ASSERT_EQ(skel->bss->setsockopt_optlen, sizeof(val), "optlen");
	ASSERT_EQ(skel->bss->setsockopt_optval, &val, "optval");
	close(fd);

	/* "__nullable" suffix of bpf_lsm_mmap_file()'s file argument */
	fd = memfd_create("named_args", 0);
	if (!ASSERT_OK_FD(fd, "memfd_create"))
		goto out;
	if (ASSERT_OK(ftruncate(fd, getpagesize()), "ftruncate") &&
	    ASSERT_OK(fstat(fd, &st), "fstat")) {
		mem = mmap(NULL, getpagesize(), PROT_READ, MAP_PRIVATE, fd, 0);
		if (ASSERT_NEQ(mem, MAP_FAILED, "mmap"))
			munmap(mem, getpagesize());
		ASSERT_EQ(skel->bss->mmap_ino, st.st_ino, "mmap_ino");
		ASSERT_EQ(skel->bss->mmap_prot, PROT_READ, "mmap_prot");
	}
	close(fd);

	/* "__nullable" suffix of tcp_send_reset's skb argument: connecting to
	 * a bound, but not listening, socket makes the kernel send a reset
	 */
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (!ASSERT_OK_FD(fd, "socket"))
		goto out;
	if (ASSERT_OK(bind(fd, (struct sockaddr *)&addr, addr_len), "bind") &&
	    ASSERT_OK(getsockname(fd, (struct sockaddr *)&addr, &addr_len), "getsockname")) {
		int cli = socket(AF_INET, SOCK_STREAM, 0);

		skel->bss->rst_port = addr.sin_port;
		if (ASSERT_OK_FD(cli, "socket")) {
			ASSERT_ERR(connect(cli, (struct sockaddr *)&addr, addr_len), "connect");
			close(cli);
		}
		ASSERT_EQ(skel->bss->rst_seen, 1, "rst_seen");
	}
	close(fd);
out:
	named_args__destroy(skel);
}

static char libbpf_log[16384];

static int libbpf_print_cb(enum libbpf_print_level level, const char *fmt, va_list args)
{
	size_t len = strlen(libbpf_log);

	if (level == LIBBPF_WARN)
		vsnprintf(libbpf_log + len, sizeof(libbpf_log) - len, fmt, args);
	return 0;
}

static void test_failure(const char *prog_name, const char *msg)
{
	libbpf_print_fn_t old_print_cb;
	struct named_args *skel;
	int err;

	skel = named_args__open();
	if (!ASSERT_OK_PTR(skel, "named_args__open"))
		return;
	bpf_program__set_autoload(bpf_object__find_program_by_name(skel->obj, prog_name), true);

	libbpf_log[0] = '\0';
	old_print_cb = libbpf_set_print(libbpf_print_cb);
	err = named_args__load(skel);
	libbpf_set_print(old_print_cb);

	ASSERT_ERR(err, "named_args__load");
	ASSERT_HAS_SUBSTR(libbpf_log, msg, "libbpf_log");
	named_args__destroy(skel);
}

void test_named_args(void)
{
	if (test__start_subtest("success"))
		test_success();
	if (test__start_subtest("missing_arg"))
		test_failure("missing_arg", "struct bpf_func_args___missing_arg.d");
	if (test__start_subtest("type_mismatch"))
		test_failure("type_mismatch", "argument 'b' of bpf_fentry_test3() is 'int', but");
}

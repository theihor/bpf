// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include <bpf/btf.h>
#include <linux/btf.h>

struct kfunc_annotation_test {
	const char *func_name;
	bool expect_kfunc_tag;
	bool expect_fastcall_tag;
};

static const struct kfunc_annotation_test test_kfuncs[] = {
	{ "bpf_cast_to_kern_ctx", true, true },
	{ "bpf_rdonly_cast",      true, true },
	{ "bpf_obj_new_impl",    true, false },
};

static bool has_decl_tag(struct btf *btf, __s32 func_id, const char *tag)
{
	__u32 nr = btf__type_cnt(btf);

	for (__u32 i = 1; i < nr; i++) {
		const struct btf_type *t = btf__type_by_id(btf, i);
		const char *val;

		if (!t || !btf_is_decl_tag(t))
			continue;
		if ((__s32)t->type != func_id)
			continue;

		val = btf__name_by_offset(btf, t->name_off);
		if (val && strcmp(val, tag) == 0)
			return true;
	}
	return false;
}

void test_kfunc_btf_annotations(void)
{
	struct btf *btf;
	unsigned int i;

	btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(btf, "load vmlinux btf"))
		return;

	for (i = 0; i < ARRAY_SIZE(test_kfuncs); i++) {
		const struct kfunc_annotation_test *tc = &test_kfuncs[i];
		__s32 func_id;

		if (!test__start_subtest(tc->func_name))
			continue;

		func_id = btf__find_by_name_kind(btf, tc->func_name,
						 BTF_KIND_FUNC);
		if (!ASSERT_GE(func_id, 0, "find func"))
			continue;

		ASSERT_EQ(has_decl_tag(btf, func_id, "bpf_kfunc"),
			  tc->expect_kfunc_tag, "bpf_kfunc tag");
		ASSERT_EQ(has_decl_tag(btf, func_id, "bpf_fastcall"),
			  tc->expect_fastcall_tag, "bpf_fastcall tag");
	}

	btf__free(btf);
}

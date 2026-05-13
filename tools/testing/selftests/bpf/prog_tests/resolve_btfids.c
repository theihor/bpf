// SPDX-License-Identifier: GPL-2.0

#include <linux/err.h>
#include <string.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/btf.h>
#include <linux/kernel.h>
#define CONFIG_DEBUG_INFO_BTF
#include <linux/btf_ids.h>
#include "test_progs.h"

#ifndef KF_FASTCALL
#define KF_FASTCALL (1 << 12)
#endif

#ifndef KF_ARENA_RET
#define KF_ARENA_RET  (1 << 13)
#endif

#ifndef KF_ARENA_ARG1
#define KF_ARENA_ARG1 (1 << 14)
#endif

static int duration;

struct symbol {
	const char	*name;
	int		 type;
	int		 id;
};

struct symbol test_symbols[] = {
	{ "unused",  BTF_KIND_UNKN,     0 },
	{ "S",       BTF_KIND_TYPEDEF, -1 },
	{ "T",       BTF_KIND_TYPEDEF, -1 },
	{ "U",       BTF_KIND_TYPEDEF, -1 },
	{ "S",       BTF_KIND_STRUCT,  -1 },
	{ "U",       BTF_KIND_UNION,   -1 },
	{ "func",    BTF_KIND_FUNC,    -1 },
};

struct kfunc_symbol {
	const char	*name;
	int		 id;
	__u32		 flags;
};

static struct kfunc_symbol kfunc_symbols[] = {
	{ "kfunc_a", -1, 0 },
	{ "kfunc_b", -1, 0 },
	{ "kfunc_c", -1, KF_FASTCALL },
	{ "kfunc_arena", -1, KF_ARENA_RET | KF_ARENA_ARG1 },
};

/* Align the .BTF_ids section to 4 bytes */
asm (
".pushsection " BTF_IDS_SECTION " ,\"a\"; \n"
".balign 4, 0;                            \n"
".popsection;                             \n");

BTF_ID_LIST(test_list_local)
BTF_ID_UNUSED
BTF_ID(typedef, S)
BTF_ID(typedef, T)
BTF_ID(typedef, U)
BTF_ID(struct,  S)
BTF_ID(union,   U)
BTF_ID(func,    func)

extern __u32 test_list_global[];
BTF_ID_LIST_GLOBAL(test_list_global, 1)
BTF_ID_UNUSED
BTF_ID(typedef, S)
BTF_ID(typedef, T)
BTF_ID(typedef, U)
BTF_ID(struct,  S)
BTF_ID(union,   U)
BTF_ID(func,    func)

BTF_SET_START(test_set)
BTF_ID(typedef, S)
BTF_ID(typedef, T)
BTF_ID(typedef, U)
BTF_ID(struct,  S)
BTF_ID(union,   U)
BTF_ID(func,    func)
BTF_SET_END(test_set)

BTF_KFUNCS_START(test_kfunc_set)
BTF_ID_FLAGS(func, kfunc_c, KF_FASTCALL)
BTF_ID_FLAGS(func, kfunc_a)
BTF_ID_FLAGS(func, kfunc_b)
BTF_ID_FLAGS(func, kfunc_arena, KF_ARENA_RET | KF_ARENA_ARG1)
BTF_KFUNCS_END(test_kfunc_set)

static int
__resolve_symbol(struct btf *btf, int type_id)
{
	const struct btf_type *type;
	const char *str;
	unsigned int i;

	type = btf__type_by_id(btf, type_id);
	if (!type) {
		PRINT_FAIL("Failed to get type for ID %d\n", type_id);
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE(test_symbols); i++) {
		if (test_symbols[i].id >= 0)
			continue;

		if (BTF_INFO_KIND(type->info) != test_symbols[i].type)
			continue;

		str = btf__name_by_offset(btf, type->name_off);
		if (!str) {
			PRINT_FAIL("Failed to get name for BTF ID %d\n", type_id);
			return -1;
		}

		if (!strcmp(str, test_symbols[i].name))
			test_symbols[i].id = type_id;
	}

	if (BTF_INFO_KIND(type->info) == BTF_KIND_FUNC) {
		str = btf__name_by_offset(btf, type->name_off);
		if (str) {
			for (i = 0; i < ARRAY_SIZE(kfunc_symbols); i++) {
				if (kfunc_symbols[i].id >= 0)
					continue;
				if (!strcmp(str, kfunc_symbols[i].name))
					kfunc_symbols[i].id = type_id;
			}
		}
	}

	return 0;
}

static int resolve_symbols(void)
{
	struct btf *btf;
	int type_id;
	__u32 nr;

	btf = btf__parse_raw("resolve_btfids.test.o.BTF");
	if (CHECK(libbpf_get_error(btf), "resolve",
		  "Failed to load BTF from resolve_btfids.test.o.BTF\n"))
		return -1;

	nr = btf__type_cnt(btf);

	for (type_id = 1; type_id < nr; type_id++) {
		if (__resolve_symbol(btf, type_id))
			break;
	}

	btf__free(btf);
	return 0;
}

static void verify_arena_type_tags(void)
{
	const struct btf_type *func, *proto, *ptr, *type_tag;
	const struct btf_param *params;
	struct btf *btf;
	const char *str;
	__u32 nr;
	int func_id = -1;

	btf = btf__parse_raw("resolve_btfids.test.o.BTF");
	if (!ASSERT_OK_PTR(btf, "parse_btf_for_arena_tags"))
		return;

	nr = btf__type_cnt(btf);

	/* Find kfunc_arena FUNC */
	for (__u32 id = 1; id < nr; id++) {
		const struct btf_type *t = btf__type_by_id(btf, id);

		if (!t || !btf_is_func(t))
			continue;
		str = btf__name_by_offset(btf, t->name_off);
		if (str && strcmp(str, "kfunc_arena") == 0) {
			func_id = id;
			break;
		}
	}

	if (!ASSERT_GE(func_id, 0, "find_kfunc_arena"))
		goto out;

	func = btf__type_by_id(btf, func_id);
	proto = btf__type_by_id(btf, func->type);
	if (!ASSERT_OK_PTR(proto, "arena_func_proto"))
		goto out;
	if (!ASSERT_TRUE(btf_is_func_proto(proto), "is_func_proto"))
		goto out;

	/* Verify return pointer is wrapped with TYPE_TAG("address_space(1)") */
	ptr = btf__type_by_id(btf, proto->type);
	if (!ASSERT_OK_PTR(ptr, "arena_ret_ptr"))
		goto out;
	ASSERT_TRUE(btf_is_ptr(ptr), "ret_is_ptr");
	type_tag = btf__type_by_id(btf, ptr->type);
	if (!ASSERT_OK_PTR(type_tag, "arena_ret_type_tag"))
		goto out;
	ASSERT_TRUE(btf_is_type_tag(type_tag), "ret_is_type_tag");
	ASSERT_TRUE(btf_kflag(type_tag), "ret_type_tag_is_attr");
	str = btf__name_by_offset(btf, type_tag->name_off);
	ASSERT_STREQ(str, "address_space(1)", "ret_type_tag_value");

	/* Verify param[0] pointer is wrapped with TYPE_TAG("address_space(1)") */
	params = btf_params(proto);
	if (!ASSERT_EQ(btf_vlen(proto), 2, "arena_nr_params"))
		goto out;

	ptr = btf__type_by_id(btf, params[0].type);
	if (!ASSERT_OK_PTR(ptr, "arena_arg1_ptr"))
		goto out;
	ASSERT_TRUE(btf_is_ptr(ptr), "arg1_is_ptr");
	type_tag = btf__type_by_id(btf, ptr->type);
	if (!ASSERT_OK_PTR(type_tag, "arena_arg1_type_tag"))
		goto out;
	ASSERT_TRUE(btf_is_type_tag(type_tag), "arg1_is_type_tag");
	ASSERT_TRUE(btf_kflag(type_tag), "arg1_type_tag_is_attr");
	str = btf__name_by_offset(btf, type_tag->name_off);
	ASSERT_STREQ(str, "address_space(1)", "arg1_type_tag_value");

	/* Verify param[1] is NOT wrapped (no KF_ARENA_ARG2) */
	type_tag = btf__type_by_id(btf, params[1].type);
	if (!ASSERT_OK_PTR(type_tag, "arena_arg2_type"))
		goto out;
	ASSERT_TRUE(btf_is_ptr(type_tag), "arg2_is_ptr");
	type_tag = btf__type_by_id(btf, type_tag->type);
	if (!ASSERT_OK_PTR(type_tag, "arena_arg2_pointee"))
		goto out;
	ASSERT_FALSE(btf_is_type_tag(type_tag), "arg2_not_type_tag");

out:
	btf__free(btf);
}

static void verify_decl_tags(void)
{
	bool kfunc_tagged[ARRAY_SIZE(kfunc_symbols)] = {};
	bool fastcall_tagged[ARRAY_SIZE(kfunc_symbols)] = {};
	const struct btf_type *type, *tagged_type;
	unsigned int i, nr_kfunc_tags = 0;
	unsigned int nr_fastcall_tags = 0;
	struct btf *btf;
	const char *str;
	__u32 nr;

	btf = btf__parse_raw("resolve_btfids.test.o.BTF");
	if (!ASSERT_OK_PTR(btf, "parse_btf_for_decl_tags"))
		return;

	nr = btf__type_cnt(btf);

	for (__u32 id = 1; id < nr; id++) {
		type = btf__type_by_id(btf, id);
		if (!type || !btf_is_decl_tag(type))
			continue;

		str = btf__name_by_offset(btf, type->name_off);
		if (!str)
			continue;

		if (strcmp(str, "bpf_kfunc") != 0 &&
		    strcmp(str, "bpf_fastcall") != 0)
			continue;

		tagged_type = btf__type_by_id(btf, type->type);
		if (!ASSERT_OK_PTR(tagged_type, "decl_tag_target_type"))
			goto out;

		if (!ASSERT_TRUE(btf_is_func(tagged_type), "decl_tag_targets_func"))
			goto out;

		const char *func_name = btf__name_by_offset(btf, tagged_type->name_off);

		if (!ASSERT_OK_PTR(func_name, "func_name"))
			goto out;

		for (i = 0; i < ARRAY_SIZE(kfunc_symbols); i++) {
			if (strcmp(func_name, kfunc_symbols[i].name) != 0)
				continue;

			if (strcmp(str, "bpf_kfunc") == 0) {
				kfunc_tagged[i] = true;
				nr_kfunc_tags++;
			} else if (strcmp(str, "bpf_fastcall") == 0) {
				fastcall_tagged[i] = true;
				nr_fastcall_tags++;
			}
			break;
		}
	}

	ASSERT_EQ(nr_kfunc_tags, ARRAY_SIZE(kfunc_symbols), "nr_bpf_kfunc_tags");

	for (i = 0; i < ARRAY_SIZE(kfunc_symbols); i++)
		ASSERT_TRUE(kfunc_tagged[i], kfunc_symbols[i].name);

	for (i = 0; i < ARRAY_SIZE(kfunc_symbols); i++) {
		bool expect_fastcall = !!(kfunc_symbols[i].flags & KF_FASTCALL);

		ASSERT_EQ(fastcall_tagged[i], expect_fastcall,
			  kfunc_symbols[i].name);
	}

out:
	btf__free(btf);
}

void test_resolve_btfids(void)
{
	__u32 *test_list, *test_lists[] = { test_list_local, test_list_global };
	unsigned int i, j;
	int ret = 0;

	if (resolve_symbols())
		return;

	/* Check BTF_ID_LIST(test_list_local) and
	 * BTF_ID_LIST_GLOBAL(test_list_global) IDs
	 */
	for (j = 0; j < ARRAY_SIZE(test_lists); j++) {
		test_list = test_lists[j];
		for (i = 0; i < ARRAY_SIZE(test_symbols); i++) {
			ret = CHECK(test_list[i] != test_symbols[i].id,
				    "id_check",
				    "wrong ID for %s (%d != %d)\n",
				    test_symbols[i].name,
				    test_list[i], test_symbols[i].id);
			if (ret)
				return;
		}
	}

	/* Check BTF_SET_START(test_set) IDs */
	for (i = 0; i < test_set.cnt; i++) {
		bool found = false;

		for (j = 0; j < ARRAY_SIZE(test_symbols); j++) {
			if (test_symbols[j].id != test_set.ids[i])
				continue;
			found = true;
			break;
		}

		ret = CHECK(!found, "id_check",
			    "ID %d not found in test_symbols\n",
			    test_set.ids[i]);
		if (ret)
			break;

		if (i > 0) {
			if (!ASSERT_LE(test_set.ids[i - 1], test_set.ids[i], "sort_check"))
				return;
		}
	}

	/* Check BTF_KFUNCS_START(test_kfunc_set) */
	if (!ASSERT_EQ(test_kfunc_set.flags, BTF_SET8_KFUNCS, "kfunc_set_flags"))
		return;

	if (!ASSERT_EQ(test_kfunc_set.cnt, ARRAY_SIZE(kfunc_symbols), "kfunc_set_cnt"))
		return;

	for (i = 0; i < test_kfunc_set.cnt; i++) {
		bool found = false;

		for (j = 0; j < ARRAY_SIZE(kfunc_symbols); j++) {
			if (kfunc_symbols[j].id != (__s32)test_kfunc_set.pairs[i].id)
				continue;
			found = true;
			if (!ASSERT_EQ(test_kfunc_set.pairs[i].flags,
				       kfunc_symbols[j].flags,
				       "kfunc_flags_check"))
				return;
			break;
		}

		if (!ASSERT_TRUE(found, "kfunc_id_found"))
			return;

		if (i > 0) {
			if (!ASSERT_LE(test_kfunc_set.pairs[i - 1].id,
				       test_kfunc_set.pairs[i].id,
				       "kfunc_sort_check"))
				return;
		}
	}

	verify_decl_tags();
	verify_arena_type_tags();
}

// SPDX-License-Identifier: GPL-2.0
/*
 * Provide kernel BTF information for introspection and use by eBPF tools.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/init.h>
#include <linux/sysfs.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/btf.h>
#include <linux/vmalloc.h>
#include <linux/zstd.h>

#ifdef CONFIG_DEBUG_INFO_BTF_LAZY
/* See scripts/gen-btf.sh, gen_btf_o() for details */
extern char __start_BTF_zst[];
extern char __stop_BTF_zst[];

static DEFINE_MUTEX(btf_vmlinux_data_lock);
static void *btf_vmlinux_raw;
static u32 btf_vmlinux_raw_size;
/* Compressed BTF: init data until btf_vmlinux_keep_zst(), freed once decompressed */
static void *btf_zst = __start_BTF_zst;

static u32 btf_vmlinux_size(void)
{
	zstd_frame_header hdr;

	if (!btf_vmlinux_raw_size && btf_zst &&
	    !zstd_get_frame_header(&hdr, btf_zst, __stop_BTF_zst - __start_BTF_zst) &&
	    hdr.frameContentSize < U32_MAX)
		btf_vmlinux_raw_size = hdr.frameContentSize;
	return btf_vmlinux_raw_size;
}

/* The raw vmlinux BTF, decompressed on first use and never freed */
void *btf_vmlinux_data(u32 *size)
{
	size_t ret, ws_size = zstd_dctx_workspace_bound();
	void *raw, *ws;

	/* Pairs with smp_store_release() below */
	raw = smp_load_acquire(&btf_vmlinux_raw);
	if (raw) {
		*size = btf_vmlinux_raw_size;
		return raw;
	}

	guard(mutex)(&btf_vmlinux_data_lock);
	*size = btf_vmlinux_size();
	if (btf_vmlinux_raw || !*size || !btf_zst)
		return btf_vmlinux_raw;
	/* vmalloc_user(): btf_sysfs_vmlinux_mmap() maps it to user space */
	raw = vmalloc_user(*size);
	ws = kvmalloc(ws_size, GFP_KERNEL);
	if (raw && ws) {
		ret = zstd_decompress_dctx(zstd_init_dctx(ws, ws_size), raw, *size,
					   btf_zst, __stop_BTF_zst - __start_BTF_zst);
		if (!zstd_is_error(ret) && ret == *size) {
			/* Pairs with smp_load_acquire() above */
			smp_store_release(&btf_vmlinux_raw, raw);
			if (btf_zst != __start_BTF_zst)
				vfree(btf_zst);
			btf_zst = NULL;
		}
	}
	kvfree(ws);
	if (!btf_vmlinux_raw)
		vfree(raw);
	return btf_vmlinux_raw;
}

/* Keep a copy of the compressed BTF before init memory is freed */
static int __init btf_vmlinux_keep_zst(void)
{
	size_t size = __stop_BTF_zst - __start_BTF_zst;

	guard(mutex)(&btf_vmlinux_data_lock);
	if (btf_zst) {
		/* vmalloc(): kmalloc() would round up to a power of 2 */
		btf_zst = vmalloc(size);
		if (btf_zst)
			memcpy(btf_zst, __start_BTF_zst, size);
		else
			pr_err("BTF: out of memory, vmlinux BTF unavailable\n");
	}
	return 0;
}
late_initcall_sync(btf_vmlinux_keep_zst);
#else
/* See scripts/link-vmlinux.sh, gen_btf() func for details */
extern char __start_BTF[];
extern char __stop_BTF[];

static u32 btf_vmlinux_size(void)
{
	return __stop_BTF - __start_BTF;
}

void *btf_vmlinux_data(u32 *size)
{
	*size = btf_vmlinux_size();
	return __start_BTF;
}
#endif

#ifdef CONFIG_SYSFS
static int btf_sysfs_vmlinux_mmap(struct file *filp, struct kobject *kobj,
				  const struct bin_attribute *attr,
				  struct vm_area_struct *vma)
{
	unsigned long pages = PAGE_ALIGN(attr->size) >> PAGE_SHIFT;
	size_t vm_size = vma->vm_end - vma->vm_start;
	void *data;
	u32 size;

	if (vma->vm_pgoff)
		return -EINVAL;

	if (vma->vm_flags & (VM_WRITE | VM_EXEC | VM_MAYSHARE))
		return -EACCES;

	if ((vm_size >> PAGE_SHIFT) > pages)
		return -EINVAL;

	data = btf_vmlinux_data(&size);
	if (!data)
		return -ENOMEM;

	vm_flags_mod(vma, VM_DONTDUMP, VM_MAYEXEC | VM_MAYWRITE);
	if (IS_ENABLED(CONFIG_DEBUG_INFO_BTF_LAZY))
		return remap_vmalloc_range(vma, data, 0);
	if (!PAGE_ALIGNED(__pa_symbol(data)))
		return -EINVAL;
	return remap_pfn_range(vma, vma->vm_start, __pa_symbol(data) >> PAGE_SHIFT,
			       vm_size, vma->vm_page_prot);
}

static ssize_t btf_sysfs_vmlinux_read(struct file *file, struct kobject *kobj,
				      const struct bin_attribute *attr, char *buf,
				      loff_t off, size_t count)
{
	void *data;
	u32 size;

	data = btf_vmlinux_data(&size);
	if (!data)
		return -ENOMEM;
	memcpy(buf, data + off, count);
	return count;
}

static struct bin_attribute bin_attr_btf_vmlinux __ro_after_init = {
	.attr = { .name = "vmlinux", .mode = 0444, },
	.read = btf_sysfs_vmlinux_read,
	.mmap = btf_sysfs_vmlinux_mmap,
};

struct kobject *btf_kobj;

static int __init btf_vmlinux_init(void)
{
	bin_attr_btf_vmlinux.size = btf_vmlinux_size();

	if (bin_attr_btf_vmlinux.size == 0)
		return 0;

	btf_kobj = kobject_create_and_add("btf", kernel_kobj);
	if (!btf_kobj)
		return -ENOMEM;

	return sysfs_create_bin_file(btf_kobj, &bin_attr_btf_vmlinux);
}

subsys_initcall(btf_vmlinux_init);
#endif /* CONFIG_SYSFS */

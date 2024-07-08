// SPDX-License-Identifier: GPL-2.0
/*
 * ION Memory Allocator CMA heap exporter
 *
 * Copyright (C) Linaro 2012
 * Author: <benjamin.gaignard@linaro.org> for ST-Ericsson.
 */

#include <linux/device.h>
#include <linux/ion.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/cma.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>
#include <uapi/linux/sprd_ion.h>
#include <linux/sprd_ion.h>
#include <linux/genalloc.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/jiffies.h>
#include <linux/workqueue.h>
#include "ion_ipc_trusty.h"
#include "cma.h"

struct ion_cma_heap {
	struct ion_heap heap;
	struct cma *cma;
	phys_addr_t cma_base;
} cma_heaps[MAX_CMA_AREAS];

#define to_cma_heap(x) container_of(x, struct ion_cma_heap, heap)

#define ION_CMA_ALLOCATE_FAIL  -1

static struct gen_pool *pool;
static bool gen_tags;
static unsigned long pool_alloc_size;
static struct ion_cma_heap *wv_cma_heap;
static struct page *wv_pages;
static unsigned long wv_nr_pages;
static struct sg_table *wv_table;
static unsigned long  widevine_size;
static phys_addr_t widevine_base;
static DEFINE_MUTEX(gen_pool_lock);
static struct delayed_work destroy_pool_work;

static phys_addr_t ion_cma_to_genallocate(unsigned long size)
{
	unsigned long offset = gen_pool_alloc(pool, size);

	pr_info("%s, pool: %p, offset: %lu\n", __func__, pool, offset);

	if (!offset)
		return ION_CMA_ALLOCATE_FAIL;
	return offset;
}

static void destroy_gen_pool(struct work_struct *work)
{
	struct ion_message in_buf;
	struct ion_message out_buf;

	pr_info("%s, cma_pool: %p, destroyed gen pool!\n", __func__, pool);
	gen_tags = false;
	/*close firewall*/
	in_buf.cmd = TA_UNLOCK_DRM_MEM;
	ion_tipc_write(&in_buf, sizeof(in_buf));
	ion_tipc_read(&out_buf, sizeof(out_buf));
	if ((out_buf.cmd == TA_UNLOCK_DRM_MEM) && (out_buf.payload[0] == 1))
		pr_debug("TA_UNLOCK_DRM_MEM success\n");
	ion_tipc_exit();

	mutex_lock(&gen_pool_lock);
	gen_pool_destroy(pool);
	cma_release(wv_cma_heap->cma, wv_pages, wv_nr_pages);
	sg_free_table(wv_table);
	kfree(wv_table);
	wv_table = NULL;
	pool = NULL;
	mutex_unlock(&gen_pool_lock);
}

/*start-up firewall*/
static void ion_notice_firewall(void)
{
	unsigned char buf[32];
	struct ion_message in_buf;
	struct ion_message out_buf;

	int ret;

	ret = ion_tipc_init();
	if (!ret) {
		ion_tipc_read(buf, sizeof(buf));
		pr_debug("tipc init succsess\n");
		in_buf.cmd = TA_LOCK_DRM_MEM;
		in_buf.payload[0] = widevine_base;
		in_buf.payload[1] = widevine_size;
		ion_tipc_write(&in_buf, sizeof(in_buf));
		ion_tipc_read(&out_buf, sizeof(out_buf));
		if ((out_buf.cmd == TA_LOCK_DRM_MEM) && (out_buf.payload[0] == 1))
			pr_debug("TA_LOCK_DRM_MEM success\n");

	} else {
		pr_debug("tipc init failed\n");
	}
}

static int ion_cma_create_pool(struct ion_cma_heap *cma_heap)
{
	struct sg_table *table;
	struct page *pages;
	unsigned long nr_pages;
	unsigned long align;
	int ret;

	widevine_size = cma_heap->cma->count << PAGE_SHIFT;

	widevine_base = PFN_PHYS(cma_heap->cma->base_pfn);
	pr_debug("%s, widevine paddr: 0x%llx, widevine size: %lu\n", __func__, (u64)widevine_base, widevine_size);
	nr_pages = widevine_size >> PAGE_SHIFT;
	align = get_order(widevine_size);

	if (align > CONFIG_CMA_ALIGNMENT)
		align = CONFIG_CMA_ALIGNMENT;

	pages = cma_alloc(cma_heap->cma, nr_pages, align, false);

	if (!pages)
		return -ENOMEM;

	if (PageHighMem(pages)) {
		unsigned long nr_clear_pages = nr_pages;
		struct page *page = pages;

		while (nr_clear_pages > 0) {
			void *vaddr = kmap_atomic(page);

			memset(vaddr, 0, PAGE_SIZE);
			kunmap_atomic(vaddr);
			page++;
			nr_clear_pages--;
		}
	} else {
		memset(page_address(pages), 0, widevine_size);
	}

	table = kmalloc(sizeof(*table), GFP_KERNEL);
	if (!table)
		goto err;

	ret = sg_alloc_table(table, 1, GFP_KERNEL);
	if (ret)
		goto free_mem;

	sg_set_page(table->sgl, pages, widevine_size, 0);

	pool = gen_pool_create(PAGE_SHIFT, -1);
	if (!pool) {
		pr_err("%s, cma_pool: %p, create gen pool failure!\n", __func__, pool);
		goto err;
	}

	cma_heap->cma_base = PFN_PHYS(page_to_pfn(pages));
	gen_pool_add(pool, cma_heap->cma_base, widevine_size, -1);
	gen_tags = true;
	pr_info("%s, cma_pool: %p, cma_heap: %p, cma_heap_base: 0x%llx,  widevine_size: %lu, gen_pool_add success!\n",
					__func__, pool, cma_heap, cma_heap->cma_base, widevine_size);

	wv_cma_heap = cma_heap;
	wv_pages = pages;
	wv_nr_pages = nr_pages;
	wv_table = table;

	return 0;

free_mem:
	kfree(table);
err:
	cma_release(cma_heap->cma, pages, nr_pages);
	return -ENOMEM;
}

static int cma_create_pool(struct ion_cma_heap *cma_heap)
{
	return ion_cma_create_pool(cma_heap);
}

/* ION CMA heap operations functions */
static int ion_cma_allocate(struct ion_heap *heap, struct ion_buffer *buffer,
			    unsigned long len,
			    unsigned long flags)
{
	struct ion_cma_heap *cma_heap = to_cma_heap(heap);
	struct sg_table *table;
	struct page *pages;
	unsigned long size = PAGE_ALIGN(len);
	unsigned long nr_pages = size >> PAGE_SHIFT;
	unsigned long align = get_order(size);
	phys_addr_t alloc_base;
	int ret;

	if (align > CONFIG_CMA_ALIGNMENT)
		align = CONFIG_CMA_ALIGNMENT;

	pr_info("%s, buffer_size: %lu, heap id: %d\n", __func__, size, cma_heap->heap.id);
	if (cma_heap->heap.id == 1) {
		pr_debug("%s, cma_heap: %p, heap: %p, cma_pool: %p, gen_tags: %d, start from gen_pool allocate!\n",
			 __func__, cma_heap, heap, pool, gen_tags);

		if (delayed_work_pending(&destroy_pool_work))
			cancel_delayed_work_sync(&destroy_pool_work);

		mutex_lock(&gen_pool_lock);
		if (gen_tags) {
			alloc_base = ion_cma_to_genallocate(size);
			pr_debug("%s, second paddr: 0x%llx,get buffer from gen pool!\n", __func__, (u64)alloc_base);
			if (alloc_base == ION_CMA_ALLOCATE_FAIL) {
				pr_err("%s: second failed to alloc heap id: %d, size: %lu\n",
					__func__, cma_heap->heap.id, size);
				mutex_unlock(&gen_pool_lock);
				return -ENOMEM;
			}
			pool_alloc_size += size;
			pages = pfn_to_page(PFN_DOWN(alloc_base));
			pr_debug("%s, second gen_alloc pages range: %p!\n", __func__, pages);
			mutex_unlock(&gen_pool_lock);

		} else {
			if (cma_create_pool(cma_heap) == 0) {
				alloc_base = ion_cma_to_genallocate(size);
				pr_debug("%s, first paddr: 0x%llx,get buffer from gen pool!\n", __func__, (u64)alloc_base);
				if (alloc_base == ION_CMA_ALLOCATE_FAIL) {
					pr_err("%s: first failed to alloc heap id: %d, size: %lu\n",
						__func__, cma_heap->heap.id, size);
					mutex_unlock(&gen_pool_lock);
					return -ENOMEM;
				}
				pool_alloc_size += size;
				pages = pfn_to_page(PFN_DOWN(alloc_base));
				pr_debug("%s, first gen_alloc pages range: %p!\n", __func__, pages);
				mutex_unlock(&gen_pool_lock);
				ion_notice_firewall();
			} else {
				mutex_unlock(&gen_pool_lock);
				return -ENOMEM;
			}
		}
	} else {
		pages = cma_alloc(cma_heap->cma, nr_pages, align, false);
	}

	if (!pages)
		return -ENOMEM;

	if (PageHighMem(pages)) {
		unsigned long nr_clear_pages = nr_pages;
		struct page *page = pages;

		while (nr_clear_pages > 0) {
			void *vaddr = kmap_atomic(page);

			memset(vaddr, 0, PAGE_SIZE);
			kunmap_atomic(vaddr);
			page++;
			nr_clear_pages--;
		}
	} else {
		memset(page_address(pages), 0, size);
	}

	table = kmalloc(sizeof(*table), GFP_KERNEL);
	if (!table)
		goto err;

	ret = sg_alloc_table(table, 1, GFP_KERNEL);
	if (ret)
		goto free_mem;

	sg_set_page(table->sgl, pages, size, 0);

	buffer->priv_virt = pages;
	buffer->sg_table = table;

	ion_buffer_prep_noncached(buffer);

	return 0;

free_mem:
	kfree(table);
err:
	if (gen_tags) {
		gen_pool_free(pool, PFN_PHYS(page_to_pfn(pages)), size);
	} else {
		cma_release(cma_heap->cma, pages, nr_pages);
	}
	return -ENOMEM;
}

static void ion_cma_free(struct ion_buffer *buffer)
{
	struct ion_cma_heap *cma_heap = to_cma_heap(buffer->heap);
	struct page *pages = buffer->priv_virt;
	unsigned long nr_pages = PAGE_ALIGN(buffer->size) >> PAGE_SHIFT;
	phys_addr_t addrs = PFN_PHYS(page_to_pfn(pages));
	phys_addr_t offset = widevine_size;
	phys_addr_t low = cma_heap->cma_base;
	phys_addr_t high = low + offset;

	pr_info("%s, cma_pool: %p, size: %zu, cma_addrs: 0x%llx, offset: 0x%llx, low: 0x%llx\n",
				__func__, pool, buffer->size, addrs, offset, low);

	if (cma_heap->heap.id == 1) {
		if (pool != NULL) {
			if (addrs >= low && addrs < high) {
				pr_debug("%s, cma_pool: %p, free to gen pool,pool_alloc_size: %lu!\n", __func__, pool, pool_alloc_size);
				mutex_lock(&gen_pool_lock);
				gen_pool_free(pool, addrs, buffer->size);
				pool_alloc_size -= buffer->size;
				mutex_unlock(&gen_pool_lock);
				pr_debug("%s, remain pool_alloc_size: %lu, buffer_size: %zu\n", __func__, pool_alloc_size, buffer->size);
			} else {
				pr_err("%s: addr out of range\n", __func__);
				return;
			}
		} else {
			/*release memory*/
			pr_err("%s, buffer release process exception!\n", __func__);
		}
	} else {
		/*release memory*/
		cma_release(cma_heap->cma, pages, nr_pages);
	}

	/* release sg table */
	sg_free_table(buffer->sg_table);
	kfree(buffer->sg_table);

	if ((cma_heap->heap.id == 1) && (pool_alloc_size == 0) && (pool != NULL)) {
		pr_debug("%s, cma_pool: %p, wait for destroying gen pool!\n", __func__, pool);
		schedule_delayed_work(&destroy_pool_work, msecs_to_jiffies(5000));
	}

}

static struct ion_heap_ops ion_cma_ops = {
	.allocate = ion_cma_allocate,
	.free = ion_cma_free,
};

struct cma_ion_heap_desc {
	unsigned int heap_id;
	const char *name;
} cma_heap_desc[] = {
	{
		.heap_id = ION_HEAP_ID_MM,
		.name = ION_DRM_HEAP_NAME
	},
	{
		.heap_id = ION_HEAP_ID_FB,
		.name = ION_FB_HEAP_NAME
	},
	{
		.heap_id = ION_HEAP_ID_CAM,
		.name = ION_FACEID_HEAP_NAME
	},
	{
		.heap_id = ION_HEAP_ID_VDSP,
		.name = ION_VDSP_HEAP_NAME
	}
};

static int get_heap_id_by_name(const char *name)
{
	int i, ret = -1;
	const char *heap_desc_name;

	if (!name)
		return ret;

	for (i = 0; i < ARRAY_SIZE(cma_heap_desc); i++) {
		heap_desc_name = cma_heap_desc[i].name;
		pr_err("cma name %s, heap name %s heap id %d\n",
			name, heap_desc_name, cma_heap_desc[i].heap_id);
		if (!strncmp(name, heap_desc_name, strlen(heap_desc_name)))
			return cma_heap_desc[i].heap_id;
	}

	return ret;
}

static int __ion_add_cma_heap(struct cma *cma, void *data)
{
	int *cma_nr = data;
	int heap_id;
	struct ion_cma_heap *cma_heap;
	int ret;

	if (*cma_nr >= MAX_CMA_AREAS)
		return -EINVAL;

	heap_id = get_heap_id_by_name(cma_get_name(cma));
	if (heap_id == -1)
		goto out;

	cma_heap = &cma_heaps[*cma_nr];
	cma_heap->heap.ops = &ion_cma_ops;
	cma_heap->heap.type = ION_HEAP_TYPE_DMA;
	cma_heap->heap.name = cma_get_name(cma);
	cma_heap->heap.id = 1 << heap_id;

	ret = ion_device_add_heap(&cma_heap->heap);
	if (ret)
		goto out;

	cma_heap->cma = cma;
	*cma_nr += 1;

	pr_err("cma heap info %s : heap id: 0x%x.\n",
		cma_heap->heap.name, cma_heap->heap.id);
out:
	return 0;
}

static int __init ion_cma_heap_init(void)
{
	int ret;
	int nr = 0;
	gen_tags = false;

	INIT_DELAYED_WORK(&destroy_pool_work, destroy_gen_pool);
	ret = cma_for_each_area(__ion_add_cma_heap, &nr);
	if (ret) {
		for (nr = 0; nr < MAX_CMA_AREAS && cma_heaps[nr].cma; nr++)
			ion_device_remove_heap(&cma_heaps[nr].heap);
	}

	return ret;
}

static void __exit ion_cma_heap_exit(void)
{
	int nr;

	for (nr = 0; nr < MAX_CMA_AREAS && cma_heaps[nr].cma; nr++)
		ion_device_remove_heap(&cma_heaps[nr].heap);
}

subsys_initcall(ion_cma_heap_init);
module_exit(ion_cma_heap_exit);
MODULE_LICENSE("GPL v2");

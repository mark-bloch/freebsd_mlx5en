
#ifndef _FBSD_DMAPOOL_H_
#define	_FBSD_DMAPOOL_H_

#include <linux/types.h>
#include <linux/io.h>
#include <linux/scatterlist.h>
#include <linux/device.h>
#include <linux/slab.h>

struct dma_pool {
	uma_zone_t	pool_zone;
};

static inline struct dma_pool *
dma_pool_create(char *name, struct device *dev, size_t size,
    size_t align, size_t boundary)
{
	struct dma_pool *pool;

	pool = kmalloc(sizeof(*pool), GFP_KERNEL);
	align--;
	/*
	 * XXX Eventually this could use a seperate allocf to honor boundary
	 * and physical address requirements of the device.
	 */
	pool->pool_zone = uma_zcreate(name, size, NULL, NULL, NULL, NULL,
	    align, UMA_ZONE_OFFPAGE|UMA_ZONE_HASH);

	return (pool);
}

static inline void
dma_pool_destroy(struct dma_pool *pool)
{
	uma_zdestroy(pool->pool_zone);
	kfree(pool);
}

static inline void *
dma_pool_alloc(struct dma_pool *pool, gfp_t mem_flags, dma_addr_t *handle)
{
	void *vaddr;

	vaddr = uma_zalloc(pool->pool_zone, mem_flags);
	if (vaddr)
		*handle = vtophys(vaddr);
	return (vaddr);
}

static inline void
dma_pool_free(struct dma_pool *pool, void *vaddr, dma_addr_t addr)
{
	uma_zfree(pool->pool_zone, vaddr);
}


#endif /* _FBSD_DMAPOOL_H_ */

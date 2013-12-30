#ifndef	_FBSD_SLAB_H_
#define	_FBSD_SLAB_H_

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <vm/uma.h>

#include <linux/types.h>
#include <linux/gfp.h>

MALLOC_DECLARE(M_KMALLOC);

#define	kmalloc(size, flags)		malloc((size), M_KMALLOC, (flags))
#define	kzalloc(size, flags)		kmalloc((size), (flags) | M_ZERO)
#define	kfree(ptr)			free(__DECONST(void *, (ptr)), M_KMALLOC)
#define	krealloc(ptr, size, flags)	realloc((ptr), (size), M_KMALLOC, (flags))
#define	kcalloc(n, size, flags)	        kmalloc((n) * (size), flags | M_ZERO)
#define	vzalloc(size)			kzalloc(size, GFP_KERNEL | __GFP_NOWARN)
#define	is_vmalloc_addr(arg)		0
#define	vfree(arg)			kfree(arg)



struct kmem_cache {
	uma_zone_t	cache_zone;
	void		(*cache_ctor)(void *);
};

#define	SLAB_HWCACHE_ALIGN	0x0001

static inline int
kmem_ctor(void *mem, int size, void *arg, int flags)
{
	void (*ctor)(void *);

	ctor = arg;
	ctor(mem);

	return (0);
}

static inline struct kmem_cache *
kmem_cache_create(char *name, size_t size, size_t align, u_long flags,
    void (*ctor)(void *))
{
	struct kmem_cache *c;

	c = malloc(sizeof(*c), M_KMALLOC, M_WAITOK);
	if (align)
		align--;
	if (flags & SLAB_HWCACHE_ALIGN)
		align = UMA_ALIGN_CACHE;
	c->cache_zone = uma_zcreate(name, size, ctor ? kmem_ctor : NULL,
	    NULL, NULL, NULL, align, 0);
	c->cache_ctor = ctor;

	return c;
}

static inline void *
kmem_cache_alloc(struct kmem_cache *c, int flags)
{
	return uma_zalloc_arg(c->cache_zone, c->cache_ctor, flags);
}

static inline void
kmem_cache_free(struct kmem_cache *c, void *m)
{
	uma_zfree(c->cache_zone, m);
}

static inline void
kmem_cache_destroy(struct kmem_cache *c)
{
	uma_zdestroy(c->cache_zone);
	free(c, M_KMALLOC);
}

#endif	/* _FBSD_SLAB_H_ */


#ifndef	_FBSD_IO_MAPPING_H_
#define	_FBSD_IO_MAPPING_H_

#include <linux/types.h>
#include <linux/io.h>

struct io_mapping;

static inline struct io_mapping *
io_mapping_create_wc(resource_size_t base, unsigned long size)
{

	return ioremap_wc(base, size);
}

static inline void
io_mapping_free(struct io_mapping *mapping)
{

	iounmap(mapping);
}

static inline void *
io_mapping_map_atomic_wc(struct io_mapping *mapping, unsigned long offset)
{

	return (((char *)mapping) + offset);
}

static inline void
io_mapping_unmap_atomic(void *vaddr)
{

}

static inline void *
io_mapping_map_wc(struct io_mapping *mapping, unsigned long offset)
{

	return (((char *) mapping) + offset);
}

static inline void
io_mapping_unmap(void *vaddr)
{

}

#endif	/* _FBSD_IO_MAPPING_H_ */

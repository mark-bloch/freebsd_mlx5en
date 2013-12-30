#ifndef	_FBSD_DMA_ATTR_H_
#define	_FBSD_DMA_ATTR_H_

enum dma_attr { DMA_ATTR_WRITE_BARRIER, DMA_ATTR_WEAK_ORDERING, DMA_ATTR_MAX, };

#define __DMA_ATTRS_LONGS BITS_TO_LONGS(DMA_ATTR_MAX)

struct dma_attrs {
	unsigned long flags;
};
 
#define DEFINE_DMA_ATTRS(x) struct dma_attrs x = { }

static inline void
init_dma_attrs(struct dma_attrs *attrs)
{
	attrs->flags = 0;
}

#endif	/* _FBSD_DMA_ATTR_H_ */

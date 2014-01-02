#ifndef	_FBSD_MM_H_
#define	_FBSD_MM_H_

struct vm_area_struct {
        vm_offset_t     vm_start;
        vm_offset_t     vm_end;
        vm_offset_t     vm_pgoff;
        vm_paddr_t      vm_pfn;         /* PFN For mmap. */
        vm_memattr_t    vm_page_prot;
};

/*
 *  * Compute log2 of the power of two rounded up count of pages
 *   * needed for size bytes.
 *    */
static inline int
get_order(unsigned long size)
{
        int order;

        size = (size - 1) >> PAGE_SHIFT;
        order = 0;
        while (size) {
                order++;
                size >>= 1;
        }
        return (order);
}

static inline void *
lowmem_page_address(struct page *page)
{

        return page_address(page);
}

#endif	/* _FBSD_MM_H_ */

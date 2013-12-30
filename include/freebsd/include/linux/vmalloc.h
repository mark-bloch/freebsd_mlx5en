#ifndef _FBSD_VMALLOC_H_
#define	_FBSD_VMALLOC_H_

#include <asm/page.h>

#define VM_MAP          0x0000
#define PAGE_KERNEL     0x0000

void *vmap(struct page **pages, unsigned int count, unsigned long flags,
    int prot);
void vunmap(void *addr);


#endif	/* _FBSD_VMALLOC_H_ */

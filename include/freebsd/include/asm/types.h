#ifndef	_ASM_TYPES_H_
#define	_ASM_TYPES_H_
 


#ifdef _KERNEL


typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/* DMA addresses come in generic and 64-bit flavours.  */
typedef vm_paddr_t dma_addr_t;
typedef vm_paddr_t dma64_addr_t;

#endif	/* _KERNEL */

#endif	/* _ASM_TYPES_H_ */

#ifndef	_FBSD_TYPES_H_
#define	_FBSD_TYPES_H_

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <linux/compiler.h>

#include <asm/types.h>


typedef uint16_t __le16;
typedef uint16_t __be16;
typedef uint32_t __le32;
typedef uint32_t __be32;
typedef uint64_t __le64;
typedef uint64_t __be64;

typedef unsigned gfp_t;
typedef vm_paddr_t resource_size_t;

#define	DECLARE_BITMAP(n, bits)						\
	unsigned long n[howmany(bits, sizeof(long) * 8)]

#endif	/* _FBSD_TYPES_H_ */

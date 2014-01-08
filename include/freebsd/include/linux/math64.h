/*
 * Copyright (c) 2007 Cisco Systems, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef FBSD_MATH64_H
#define FBSD_MATH64_H 1

#include <linux/types.h>
#include <linux/bitops.h>

#if BITS_PER_LONG == 64
 
/**
* div_u64_rem - unsigned 64bit divide with 32bit divisor with remainder
*
* This is commonly provided by 32bit archs to provide an optimized 64bit
* divide.
*/
static inline u64 div_u64_rem(u64 dividend, u32 divisor, u32 *remainder)
{
        *remainder = dividend % divisor;
        return dividend / divisor;
}


#elif BITS_PER_LONG == 32
 
#ifndef div_u64_rem
static inline u64 div_u64_rem(u64 dividend, u32 divisor, u32 *remainder)
{
        *remainder = do_div(dividend, divisor);
        return dividend;
}
#endif
 

#endif /* BITS_PER_LONG */



/**
 ** div_u64 - unsigned 64bit divide with 32bit divisor
 **
 ** This is the most common 64bit divide and should be used if possible,
 ** as many 32bit archs can optimize this variant better than a full 64bit
 ** divide.
 *  */
#ifndef div_u64

static inline u64 div_u64(u64 dividend, u32 divisor)
{
        u32 remainder;
        return div_u64_rem(dividend, divisor, &remainder);
}
#endif

#endif	/* FBSD_MATH64_H */
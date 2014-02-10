/*
 * Copyright (c) 2005 Mellanox Technologies. All rights reserved.
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
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * $Id: mr_test.c 2013-06-16 17:18 Daria Zasipko $
 *
 */

#include "mlx4_core_tests.h"
#include <mlx4.h>

MALLOC_DEFINE(M_MR_VAL, "MR buffer", "buffer for MR tests");

/* Taken from </drivers/net/ethernet/mellanox/mlx4/mlx4.h> */
enum mlx4_mr_state {
	MLX4_MR_DISABLED = 0,
	MLX4_MR_EN_HW,
	MLX4_MR_EN_SW
};

/* Taken from </drivers/net/ethernet/mellanox/mlx4/mr.c> */
static u32 key_to_hw_index(u32 key)
{
        return (key << 24) | (key >> 8);
}

#define MLX4_MPT_STATUS_HW              0x00

/* MTT allocation test */
static int mtt_test (struct mlx4_dev *dev, char *log, int npages) {

        struct mlx4_mtt *mtt;
        struct mlx4_buf *buf;
        int err;
        int expected_rc = 0;
	int ret_val 	= FAIL;
        int page_shift 	= get_order(dev->caps.cqe_size) + PAGE_SHIFT;
        u64 mtt_addr;

	mtt = malloc(sizeof (struct mlx4_mtt), M_MR_VAL, M_WAITOK);
        VL_CHECK_MALLOC(mtt, goto without_free, log);

	err = mlx4_mtt_init(dev, npages, page_shift, mtt);
        VL_CHECK_RC(err, expected_rc, goto free_mtt , log, "failed to initialize MTT");
        uprintf( "MTT was initialized successfuly\n");

	if(0 == npages) {
		VL_CHECK_INT_VALUE(mtt->order, -1, goto cleanup_mtt, log, "mtt->order is wrong");
	        VL_CHECK_INT_VALUE(mtt->page_shift, 12, goto cleanup_mtt, log, "mtt->page_shift is wrong");

                mtt_addr = mlx4_mtt_addr(dev, mtt);
                uprintf( "MTT address is: %lu\n", mtt_addr);

                ret_val = SUCCESS;

                goto cleanup_mtt;
	}
	else {
		VL_CHECK_INT_VALUE(mtt->order, 0, goto cleanup_mtt, log, "mtt->order is wrong");
	        VL_CHECK_INT_VALUE(mtt->page_shift, page_shift, goto cleanup_mtt, log, "mtt->page_shift is wrong");

                mtt_addr = mlx4_mtt_addr(dev, mtt);
                uprintf( "MTT address is: %lu\n", mtt_addr);

                buf = malloc(sizeof (struct mlx4_buf), M_MR_VAL, M_WAITOK);
                VL_CHECK_MALLOC(buf, goto cleanup_mtt, log);

                err = mlx4_buf_alloc(dev, 64 * dev->caps.cqe_size, PAGE_SIZE * 2, buf);
                VL_CHECK_RC(err, expected_rc, goto free_buf , log, "failed to allocate buf");
                uprintf( "buf was allocated successfuly\n");

                err = mlx4_buf_write_mtt(dev, mtt, buf);
                VL_CHECK_RC(err, expected_rc, goto dealloc_buf , log, "buf write mtt failed");
                uprintf( "buf write mtt was successful\n");

                ret_val = SUCCESS;
	}

dealloc_buf:
	mlx4_buf_free(dev, 64 * dev->caps.cqe_size, buf);
        uprintf( "buf free was successful\n");

free_buf:
	free(buf, M_MR_VAL);

cleanup_mtt:
	mlx4_mtt_cleanup(dev, mtt);
        uprintf( "MTT clean-up was successful\n");

free_mtt:
        free(mtt, M_MR_VAL);

without_free:
        return ret_val;
}

/* MTT allocation test with npages = 0 parameter, address won't be legitimate */
int mtt_without_pages_test(struct mlx4_dev *dev, char *log) {
	return mtt_test(dev, log, 0);
}

/* MTT allocation test with npages = 1 parameter, address will be legitimate */
int mtt_with_pages_test (struct mlx4_dev *dev, char *log) {
	return mtt_test(dev, log, 1);
}

/* MR allocation and enabling test  */
int mr_test(struct mlx4_dev *dev, char *log) {

	struct mlx4_mr *mr;
        int err;
	int iova		= 0; //The virtual address of the start of the fast memory region
	int size		= 0;
	int access		= 0;
	int page_shift		= 0;
        int expected_rc 	= 0;
        int max_page_list_size	= 256;
	int ret_val 		= FAIL;
        u32 pdn;

	err = mlx4_pd_alloc(dev, &pdn);
        VL_CHECK_RC(err, expected_rc, goto without_free , log, "failed to allocate PD");

	mr = malloc(sizeof (struct mlx4_mr), M_MR_VAL, M_WAITOK);
        VL_CHECK_MALLOC(mr, goto dealloc_pd, log);

        err = mlx4_mr_alloc(dev, pdn, iova, size, access, max_page_list_size, page_shift, mr);
        VL_CHECK_RC(err, expected_rc, goto free_mr , log, "failed to allocate MR");
        uprintf("MR was allocatd successfuly\n");

        VL_CHECK_INT_VALUE(mr->enabled, MLX4_MR_DISABLED, goto dealloc_mr, log, "MR should be disabled (mr->enabled != MLX4_MR_DISABLED)");

	err = mlx4_mr_enable(dev, mr);
        VL_CHECK_RC(err, expected_rc, goto dealloc_mr , log, "MR enable failed");
        uprintf("MR was enabled successfuly\n");

	VL_CHECK_INT_VALUE(mr->enabled, MLX4_MR_EN_HW, goto dealloc_mr, log, "MR should be HW enabled (mr->enabled != MLX4_MR_EN_HW)");
        uprintf("mr->enabled = %d\n", mr->enabled);

        ret_val = SUCCESS;

dealloc_mr:
	mlx4_mr_free(dev, mr);
        uprintf("MR was freed successfuly\n");

free_mr:
        free(mr, M_MR_VAL);

dealloc_pd:
	mlx4_pd_free(dev, pdn);
        uprintf("PD free was successful\n");

without_free:
        return ret_val;
}

/* FMR allocation, enabling, mapping and unmapping test */
int fmr_test(struct mlx4_dev *dev, char* log) {

        struct mlx4_fmr *fmr;
        struct mlx4_buf *buf;
        int err, i;
        int expected_rc 	= 0;
        int max_pages 		= 0x80000>>12;
        int max_maps 		= 32;
	int ret_val 		= FAIL;

        u64 *page_list;
        u64 iova 		= 0;
        u32 access 		= 1024;
        u32 reset_key           = 256; /*reset key = key_to_hw_index(fmr->mr.key) & (dev->caps.num_mpts - 1) [(dev->caps.num_mpts - 1) = 0x7FFFF] */
        u32 pdn;
        u32 *lkey;
        u32 *rkey;
        u8 page_shift 		= 12;

        err = mlx4_pd_alloc(dev, &pdn);
        VL_CHECK_RC(err, expected_rc, goto without_free, log, "failed to allocate PD");

	fmr = malloc(sizeof *fmr, M_MR_VAL, M_WAITOK);
        VL_CHECK_MALLOC(fmr, goto dealloc_pd, log);

	lkey = malloc(sizeof(u32), M_MR_VAL, M_WAITOK);
        VL_CHECK_MALLOC(lkey, goto free_fmr, log);

	rkey = malloc(sizeof(u32), M_MR_VAL, M_WAITOK);
        VL_CHECK_MALLOC(rkey, goto free_lkey, log);

        err = mlx4_fmr_alloc(dev, pdn, access, max_pages, max_maps, page_shift ,fmr);
        VL_CHECK_RC(err, expected_rc, goto free_rkey , log, "FMR allocation failed");
        uprintf( "FMR was allocatd successfuly\n");

	VL_CHECK_INT_VALUE(fmr->mr.enabled, MLX4_MR_DISABLED, goto free_rkey, log, "FMR should be disabled (fmr->mr.enabled != MLX4_MR_DISABLED)");

	//enabling fmr
	err = mlx4_fmr_enable(dev, fmr);
        VL_CHECK_RC(err, expected_rc, goto dealloc_fmr , log, "FMR enable failed");
        uprintf( "FMR was enabled successfuly\n");

	VL_CHECK_INT_VALUE(fmr->mr.enabled, MLX4_MR_EN_HW, goto dealloc_fmr, log, "FMR should be HW enabled (fmr->mr.enabled != MLX4_MR_EN_HW)");
        uprintf( "fmr->mr->enabled = %d\n", fmr->mr.enabled);

        buf = malloc(sizeof *buf, M_MR_VAL, M_WAITOK);
        VL_CHECK_MALLOC(buf, goto dealloc_fmr, log);

        err = mlx4_buf_alloc(dev, 64 * dev->caps.cqe_size, PAGE_SIZE * 2, buf);
        VL_CHECK_RC(err, expected_rc, goto free_buf , log, "failed to allocate buf");

	page_list = malloc(buf->npages * sizeof *page_list, M_MR_VAL, M_WAITOK);
        VL_CHECK_MALLOC(page_list, goto dealloc_buf, log);
        uprintf( "page_list was allocated successfuly\n");

        for (i = 0; i < buf->npages; ++i) {
                if (buf->nbufs == 1)
                        page_list[i] = buf->direct.map + (i << buf->page_shift);
                else
                        page_list[i] = buf->page_list[i].map;
        }

	// mapping fmr
	// mapping is needed because in fmr_alloc (unlike mr_alloc) there is no mapping of virtual - physical memory, mapping happenes on the run when we need it.
	err = mlx4_map_phys_fmr(dev, fmr, page_list, buf->npages, iova, lkey, rkey); //rkey = 0
        VL_CHECK_RC(err, expected_rc, goto free_page_list , log, "map_phys_fmr failed");
        uprintf( "map_phys_fmr was successful\n");

	VL_CHECK_INT_VALUE(*(u8 *) fmr->mpt, MLX4_MPT_STATUS_HW,
                goto free_page_list, log, "mpt status should be HW");
        VL_CHECK_LONG_LONG_INT_VALUE(fmr->mpt->length,
                cpu_to_be64(buf->npages * (1ull << fmr->page_shift)),
                        goto free_page_list, log, "wrong mpt length");
        VL_CHECK_LONG_LONG_INT_VALUE(fmr->mpt->start, cpu_to_be64(iova),
                goto free_page_list, log, "wrong mpt start");
        VL_CHECK_EQUALS(key_to_hw_index(fmr->mr.key), 0,
                goto free_page_list, log, "lkey = 0 after map_phys_fmr");

	err = mlx4_SYNC_TPT(dev);
        VL_CHECK_RC(err, expected_rc, goto free_page_list , log, "SYNC_TPT failed");
        uprintf( "SYNC_TPT was successful\n");

	//cleanup
	// unmapping fmr
        mlx4_fmr_unmap(dev, fmr, lkey, rkey);
        uprintf( "fmr_unmap was successful\n");

	VL_CHECK_INT_VALUE(*(u8 *)fmr->mpt, MLX4_MPT_STATUS_HW,
                goto free_page_list, log, "After unmap mpt status should be HW");
        VL_CHECK_LONG_LONG_INT_VALUE(fmr->mpt->length, (unsigned long) 0,
                goto free_page_list, log, "mpt length should be 0");
        VL_CHECK_LONG_LONG_INT_VALUE(fmr->mpt->start, (unsigned long) 0,
                goto free_page_list, log, "mpt start should be 0");
        VL_CHECK_INT_VALUE(key_to_hw_index(fmr->mr.key), reset_key,
                        goto free_page_list, log, "fmr->mr.key should be 256");

        err = mlx4_SYNC_TPT(dev);
        VL_CHECK_RC(err, expected_rc, goto free_page_list , log, "SYNC_TPT failed");
        uprintf( "SYNC_TPT was successful\n");

        ret_val = SUCCESS;

free_page_list:
        free(page_list, M_MR_VAL);

dealloc_buf:
	mlx4_buf_free(dev, 64 * dev->caps.cqe_size, buf);
        uprintf( "buf free was successful\n");

free_buf:
        free(buf, M_MR_VAL);

dealloc_fmr:
	err = mlx4_fmr_free(dev, fmr);
        VL_CHECK_RC(err, expected_rc, ret_val = FAIL, log, "FMR free failed");
        uprintf( "FMR was freed successfuly\n");

free_rkey:
        free(rkey, M_MR_VAL);

free_lkey:
        free(lkey, M_MR_VAL);

free_fmr:
        free(fmr, M_MR_VAL);

dealloc_pd:
	mlx4_pd_free(dev, pdn);
        uprintf("PD free was successful\n");

without_free:
        return ret_val;
}




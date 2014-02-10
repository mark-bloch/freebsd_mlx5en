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
 * $Id: cq_test.c 2013-06-16 18:43 Daria Zasipko $
 *
 */

#include <mlx4.h>
#include <linux/mlx4/cq.h>
#include "mlx4_core_tests.h"

MALLOC_DEFINE(M_CQ_VAL, "CQ buffer", "buffer for CQ tests");

/* Taken from <infiniband/hw/mlx4/mlx4_ib.h> */
enum {
	MLX4_NUM_TUNNEL_BUFS		= 256,
};

/* CQ allocation and modification test  */
int cq_test(struct mlx4_dev *dev, char* log) {

	struct mlx4_cq *cq;
	struct mlx4_mtt *mtt;
	struct mlx4_uar *uar;
	struct mlx4_db *db;

	int err;
	int expected_rc 		= 0;
	int collapsed 			= 0;
	int timestamp_en 		= 0;
	int npages 			= 1;
	int page_shift			= get_order(dev->caps.cqe_size) + PAGE_SHIFT;
	int ret_val 			= FAIL;
	int vector 			= 0;
	int nent 			= 2 * MLX4_NUM_TUNNEL_BUFS;

	u16 count 			= 88;
	u16 period 			= 0;
	u64 mtt_addr;

	uar = malloc(sizeof *uar ,M_CQ_VAL, M_WAITOK );
	VL_CHECK_MALLOC(uar, goto without_free, log);

	mtt = malloc(sizeof *mtt ,M_CQ_VAL, M_WAITOK );
        VL_CHECK_MALLOC(mtt, goto free_uar, log);

	cq = malloc(sizeof *cq ,M_CQ_VAL, M_WAITOK );
        VL_CHECK_MALLOC(cq, goto free_mtt, log);

	db = malloc(sizeof *db ,M_CQ_VAL, M_WAITOK );
        VL_CHECK_MALLOC(db, goto free_cq, log);

	err = mlx4_mtt_init(dev, npages, page_shift, mtt);
        VL_CHECK_RC(err, expected_rc, goto free_db , log, "failed to initialize MTT");
        uprintf("MTT was initialized successfuly\n");
	VL_CHECK_INT_VALUE(mtt->order, 0, goto cleanup_mtt, log, "mtt->order is wrong");
        VL_CHECK_INT_VALUE(mtt->page_shift, 12, goto cleanup_mtt, log, "mtt->page_shift is wrong");
        mtt_addr = mlx4_mtt_addr(dev, mtt);
        uprintf("MTT address is: %lu\n", mtt_addr);

	err = mlx4_uar_alloc(dev, uar);
	VL_CHECK_RC(err, expected_rc, goto cleanup_mtt , log, "failed to allocate UAR");
	uprintf("UAR was allocated successfuly\n");

	err = mlx4_db_alloc(dev, db, 1);
	VL_CHECK_RC(err, expected_rc, goto dealloc_uar , log, "failed to allocate DB");
	uprintf("DB was allocated successfuly\n");

	err = mlx4_cq_alloc(dev, nent, mtt, uar, db->dma, cq, vector, collapsed, timestamp_en);
	VL_CHECK_RC(err, expected_rc, goto dealloc_db , log, "failed to allocate CQ");
	uprintf("CQ allocated successfuly\n");

	VL_CHECK_INT_VALUE(cq->cons_index, 0, goto dealloc_cq, log, "cq->cons_index is wrong");
	VL_CHECK_INT_VALUE(cq->arm_sn, 1, goto dealloc_cq, log, "cq->arm_sn is wrong");
	uprintf("cq->cqn = %d, cq->uar->pfn = %lu, cq->eqn = %d, cq->irq = %u\n", cq->cqn, cq->uar->pfn, cq->eqn, cq->irq );
	VL_CHECK_UNSIGNED_INT_VALUE(cq->cons_index, (unsigned int)0, goto dealloc_cq, log, "cq->cons_index != 0");
	VL_CHECK_INT_VALUE(cq->arm_sn, 1, goto dealloc_cq, log, "cq->arm_sn != 1");

	err = mlx4_cq_modify(dev, cq, count, period);
	VL_CHECK_RC(err, expected_rc, goto dealloc_cq , log, "failed to modify CQ");
	uprintf("CQ was modifyed successfuly\n");

	ret_val = SUCCESS;

dealloc_cq:
	mlx4_cq_free(dev, cq);
        uprintf("CQ was freed successfuly\n");

dealloc_db:
	mlx4_db_free(dev, db);
	uprintf( "DB free was successful\n");

dealloc_uar:
	mlx4_uar_free(dev,uar);
	uprintf("UAR free was successful\n");

cleanup_mtt:
	mlx4_mtt_cleanup(dev, mtt);
	uprintf( "mtt clean-up was successful\n");

free_db:
	free(db, M_CQ_VAL);

free_cq:
        free(cq, M_CQ_VAL);

free_mtt:
        free(mtt, M_CQ_VAL);

free_uar:
        free(uar, M_CQ_VAL);

without_free:
	return ret_val;
}

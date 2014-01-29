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
 * $Id: srq_test.c 2013-06-16 17:20 Daria Zasipko $
 *
 */

#include <../../../drivers/net/ethernet/mellanox/mlx4/mlx4.h>
#include "mlx4_core_tests.h"

MALLOC_DEFINE(M_SRQ_VAL, "SRQ buffer", "buffer for SRQ tests");

/* Taken from <infiniband/hw/mlx4/mlx4_ib.h> */
enum {
        MLX4_NUM_TUNNEL_BUFS            = 256,
};

/* SRQ allocation, arm and query test  */
int srq_test(struct mlx4_dev *dev, char* log)
{
	struct mlx4_srq *srq;
	struct mlx4_mtt *mtt;
	struct mlx4_cq *cq;
        struct mlx4_uar *uar;
        struct mlx4_db *db;

	int* lwm; //Limit Water Mark. Valid values are 0x1 to RQ size (i.e., number of WQEs in the RQ)
	int err;
	int expected_rc 	= 0;
        int vector 		= 0;
        int collapsed 		= 0;
        int timestamp_en 	= 0;
	int npages_case 	= 1;
	int page_shift 		= get_order(dev->caps.cqe_size) + PAGE_SHIFT;
        int nent 		= 2 * MLX4_NUM_TUNNEL_BUFS;
	int ret_val 		= FAIL;
	u32 pdn;
	u32 xrcd;

/*---------------------------------- allocation of all needed resources -------------------------------------*/

	uar = malloc(sizeof (struct mlx4_uar), M_SRQ_VAL, M_WAITOK);
	VL_CHECK_MALLOC(uar, goto without_free, log);

        mtt = malloc(sizeof (struct mlx4_mtt), M_SRQ_VAL, M_WAITOK);
	VL_CHECK_MALLOC(mtt, goto free_uar, log);

        cq = malloc(sizeof (struct mlx4_cq), M_SRQ_VAL, M_WAITOK);
	VL_CHECK_MALLOC(cq, goto free_mtt, log);

        db = malloc(sizeof (struct mlx4_db), M_SRQ_VAL, M_WAITOK);
        VL_CHECK_MALLOC(db, goto free_cq, log);

	srq = malloc(sizeof (struct mlx4_srq), M_SRQ_VAL, M_WAITOK);
	VL_CHECK_MALLOC(srq, goto free_db, log);

	lwm = malloc(sizeof (int), M_SRQ_VAL, M_WAITOK);
        VL_CHECK_MALLOC(lwm, goto free_srq, log);

/*----------------------------------- initialization of all needed resources --------------------------------*/

	err = mlx4_mtt_init(dev, npages_case, page_shift, mtt);
	VL_CHECK_RC(err, expected_rc, goto free_lwm , log, "failed to initialize MTT");
        uprintf( "MTT was initialized successfuly\n");

	err = mlx4_pd_alloc(dev, &pdn);
        VL_CHECK_RC(err, expected_rc, goto cleanup_mtt , log, "failed to allocate PD");
        uprintf( "PD was allocated successfuly\n");

	err = mlx4_uar_alloc(dev, uar);
        VL_CHECK_RC(err, expected_rc, goto dealloc_pd , log, "failed to allocate UAR");
        uprintf( "UAR was allocated successfuly\n");

        err = mlx4_db_alloc(dev, db, 1);
        VL_CHECK_RC(err, expected_rc, goto dealloc_uar , log, "failed to allocate DB");
        uprintf( "DB was allocated successfuly\n");

	err = mlx4_cq_alloc(dev, nent, mtt, uar, db->dma, cq, vector, collapsed, timestamp_en);
        VL_CHECK_RC(err, expected_rc, goto dealloc_db , log, "failed to allocate CQ");
        uprintf( "CQ was allocated successfuly\n");

	err = mlx4_xrcd_alloc(dev, &xrcd);
        VL_CHECK_RC(err, expected_rc, goto dealloc_cq , log, "failed to allocate XRCD");
        uprintf( "XRCD was allocated successfuly\n");

/*-----------------------------------------------------------------------------------------------------------*/

	// SRQ allocation
	err = mlx4_srq_alloc(dev, pdn, cq->cqn, xrcd, mtt, db->dma, srq);
        VL_CHECK_RC(err, expected_rc, goto dealloc_xrcd , log, "failed to allocate SRQ");
	uprintf( "SRQ was allocated successfuly\n");

	*lwm = 1;
	err = mlx4_srq_query(dev, srq, lwm);
        VL_CHECK_RC(err, expected_rc, goto dealloc_srq , log, "SRQ query failed");
	uprintf( "SRQ query was successful\n");
	uprintf( "limit-water-mark = %d\n", *lwm);

	ret_val = SUCCESS;

/*-------------------------------------------- test clean up -----------------------------------------------*/

dealloc_srq:
	mlx4_srq_free(dev, srq);
        uprintf( "SRQ free was successful\n");

dealloc_xrcd:
	mlx4_xrcd_free(dev, xrcd);
        uprintf( "XRCD free was successful\n");

dealloc_cq:
	mlx4_cq_free(dev, cq);
        uprintf( "CQ free was successful\n");

dealloc_db:
	mlx4_db_free(dev, db);
        uprintf( "DB free was successful\n");

dealloc_uar:
	mlx4_uar_free(dev, uar);
        uprintf( "UAR free was successful\n");

dealloc_pd:
	mlx4_pd_free(dev, pdn);
        uprintf( "PD free was successful\n");

cleanup_mtt:
	mlx4_mtt_cleanup(dev, mtt);
        uprintf( "mtt was cleaned-up successfuly\n");

free_lwm:
	free(lwm, M_SRQ_VAL);

free_srq:
	free(srq, M_SRQ_VAL);

free_db:
        free(db, M_SRQ_VAL);

free_cq:
        free(cq, M_SRQ_VAL);

free_mtt:
        free(mtt, M_SRQ_VAL);

free_uar:
	free(uar, M_SRQ_VAL);

without_free:
	return ret_val;
}


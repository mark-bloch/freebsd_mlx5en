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
 * $Id: qp_test.c 2013-05-23 16:38 Daria Zasipko $
 *
 */

#include "mlx4_core_tests.h"
#include <linux/mlx4/qp.h>

#define TXBB_SIZE 64

MALLOC_DEFINE(M_QP_VAL, "qp buffer", "buffer for qp tests");

/* Taken from <infiniband/hw/mlx4/mlx4_ib.h> */
enum {
        MLX4_NUM_TUNNEL_BUFS            = 256,
};

/* QP allocation and mlx4_qp_to_ready test */
int qp_to_ready_test(struct mlx4_dev *dev, char* log)
{
	struct mlx4_mtt *mtt;
	struct mlx4_qp *qp;
	struct mlx4_qp_context *context;
	struct mlx4_db *db;
	struct mlx4_uar *uar;
	struct mlx4_cq *cq;

	int mlx4_state;
	int err;
	int expected_rc 		= 0;
	int cnt 			= 1;
	int align 			= 1;
	int npages 			= 1;
	int rss 			= 0;
	int page_shift 			= get_order(dev->caps.cqe_size) + PAGE_SHIFT;
	int nent 			= 2 * MLX4_NUM_TUNNEL_BUFS;
        int collapsed 			= 0;
        int timestamp_en 		= 0;
	int ret_val 			= FAIL;
	int vector 			= 0;
	enum mlx4_qp_state qp_state 	= MLX4_QP_STATE_RST;

	u64 mtt_addr;
	u32 qpn ;
	u32 pdn;
	u8 flags = MLX4_RESERVE_BF_QP;

/* ---------------------------------------- allocation of resources for qp creation ------------------------------------------- */
	qp = malloc(sizeof (struct mlx4_qp), M_QP_VAL, M_WAITOK);
        VL_CHECK_MALLOC(qp, goto without_free, log);

	context = malloc(sizeof (struct mlx4_qp_context), M_QP_VAL, M_WAITOK);
        VL_CHECK_MALLOC(context, goto free_qp, log);
	memset(context, 0, sizeof (struct mlx4_qp_context));

	db = malloc(sizeof (struct mlx4_db), M_QP_VAL, M_WAITOK);
        VL_CHECK_MALLOC(db, goto free_context, log);
	err = mlx4_db_alloc(dev, db, 1);
	VL_CHECK_RC(err, expected_rc, goto free_db , log, "DB allocation failed");
        uprintf("DB was allocated successfuly\n");

	uar = malloc(sizeof (struct mlx4_uar), M_QP_VAL, M_WAITOK);
        VL_CHECK_MALLOC(uar, goto dealloc_db, log);
	err = mlx4_uar_alloc(dev, uar);
        VL_CHECK_RC(err, expected_rc, goto free_uar , log, "UAR allocation failed");
        uprintf("UAR was allocated successfuly\n");

	err = mlx4_pd_alloc(dev, &pdn);
        VL_CHECK_RC(err, expected_rc, goto dealloc_uar , log, "PD allocation failed");
	uprintf("PD was allocated successfuly\n");

	mtt = malloc(sizeof (struct mlx4_mtt), M_QP_VAL, M_WAITOK);
        VL_CHECK_MALLOC(mtt, goto dealloc_pd, log);
	err = mlx4_mtt_init(dev, npages, page_shift, mtt);
	VL_CHECK_RC(err, expected_rc, goto free_mtt , log, "MTT initialization failed");
	uprintf("MTT was initialized successfuly\n");
	mtt_addr = mlx4_mtt_addr(dev, mtt);

	cq = malloc(sizeof (struct mlx4_cq), M_QP_VAL, M_WAITOK);
        VL_CHECK_MALLOC(cq, goto cleanup_mtt, log);
        err = mlx4_cq_alloc(dev, nent, mtt, uar, db->dma, cq, vector, collapsed, timestamp_en);
        VL_CHECK_RC(err, expected_rc, goto free_cq , log, "CQ allocation failed");
        uprintf("CQ was allocated successfuly\n");

/* ----------------------------------------- all qp resources were allocated -------------------------------------------------- */

        err = mlx4_qp_reserve_range(dev, cnt, align, &qpn, flags);
	VL_CHECK_RC(err, expected_rc, goto dealloc_cq , log, "mlx4_qp_reserve_range failed");
	uprintf("mlx4_qp_reserve_range was successful\n");

	err = mlx4_qp_alloc(dev, qpn, qp);
	VL_CHECK_RC(err, expected_rc, goto qp_release_range , log, "QP allocation failed");
	uprintf("mlx4_qp_alloc was successful\n");

	//prepare context for mlx4_qp_tp_ready use.
	context->db_rec_addr 		= cpu_to_be64(db->dma);
        context->flags 			= cpu_to_be32(7 << 16 | rss << MLX4_RSS_QPC_FLAG_OFFSET);
        context->pd 			= cpu_to_be32(pdn);
        context->mtu_msgmax 		= 0xff;
        context->rq_size_stride 	= 3;
        context->sq_size_stride 	= 3;
        context->usr_page 		= cpu_to_be32(uar->index);
        context->local_qpn 		= cpu_to_be32(qpn);
        context->pri_path.ackto 	= 1 & 0x07;
        context->cqn_send 		= cpu_to_be32(cq->cqn);
        context->cqn_recv 		= cpu_to_be32(cq->cqn);
        context->db_rec_addr 		= cpu_to_be64(db->dma << 2);

	err = mlx4_qp_to_ready(dev, mtt, context,qp ,&qp_state);
	VL_CHECK_RC(err, expected_rc, goto qp_free , log, "mlx4_qp_to_ready failed");
        uprintf("mlx4_qp_to_ready was successful\n");

	mlx4_state = be32_to_cpu(context->flags) >> 28;
	VL_CHECK_RC(mlx4_state, MLX4_QP_STATE_RTS, goto qp_free , log, "QP state is not MLX4_QP_STATE_RTS");

	ret_val = SUCCESS;

/* ----------------------------------------------------- test clean up -------------------------------------------------------- */

qp_free:
	//move QP back to MLX4_QP_STATE_RST state before its removal
        err = mlx4_qp_modify(dev, mtt, MLX4_QP_STATE_RTS, MLX4_QP_STATE_RST, context, 0, 0, qp);
	VL_CHECK_RC(err, expected_rc, ret_val = FAIL, log, "mlx4_qp_modify failed");
        uprintf("mlx4_qp_modify was successful\n");
	
	mlx4_qp_remove(dev, qp);
        uprintf("mlx4_qp_remove was successful\n");
        mlx4_qp_free(dev, qp);
        uprintf("mlx4_qp_free was successful\n");

qp_release_range:
        mlx4_qp_release_range(dev, qpn, cnt);
        uprintf("mlx4_qp_release_range was successful\n");

dealloc_cq:
	mlx4_cq_free(dev, cq);
	uprintf("CQ free was successful\n");

free_cq:
	free(cq, M_QP_VAL);

cleanup_mtt:
	mlx4_mtt_cleanup(dev, mtt);
	uprintf("mtt was cleaned-up successfuly\n");

free_mtt:
	free(mtt, M_QP_VAL);

dealloc_pd:
	mlx4_pd_free(dev, pdn);
        uprintf("PD free was successful\n");

dealloc_uar:
	mlx4_uar_free(dev,uar);
        uprintf("UAR was freed\n");

free_uar:
	free(uar, M_QP_VAL);

dealloc_db:
	mlx4_db_free(dev, db);
	uprintf("db was freed successfuly\n");

free_db:
	free(db, M_QP_VAL);

free_context:
	free(context, M_QP_VAL);

free_qp:
	free(qp, M_QP_VAL);

without_free:
	return ret_val;
}

/* QP allocation, mlx4_qp_modify, mlx4_qp_query test */
int qp_modify_test(struct mlx4_dev *dev, char* log) {

	struct mlx4_mtt *mtt;
	struct mlx4_qp *qp;
	struct mlx4_qp_context *context;
	struct mlx4_qp_context *context2;
	struct mlx4_qp_context *context3;
	struct mlx4_db *db;
	struct mlx4_uar *uar;
	struct mlx4_cq *cq;

	int err;
	int mlx4_state;
	int cnt 			= 1;
	int align 			= 1;
	int npages 			= 1;
	int rss 			= 0;
	int page_shift 			= get_order(dev->caps.cqe_size) + PAGE_SHIFT;
	int nent 			= 2 * MLX4_NUM_TUNNEL_BUFS;
	unsigned vector 		= 0;
	int collapsed 			= 0;
	int timestamp_en 		= 0;
	int ret_val 			= FAIL;
	int expected_rc 		= 0;

	u64 mtt_addr;
	u32 qpn ;
	u32 pdn;
	u8 flags 			= MLX4_RESERVE_BF_QP;

/* ---------------------------------------- allocation of resources for qp creation ------------------------------------------- */

	qp = malloc(sizeof (struct mlx4_qp), M_QP_VAL, M_WAITOK);
	VL_CHECK_MALLOC(qp, goto without_free, log);

	context = malloc(sizeof (struct mlx4_qp_context), M_QP_VAL, M_WAITOK);
        VL_CHECK_MALLOC(context, goto free_qp, log);
        memset(context, 0, sizeof (struct mlx4_qp_context));

	//context for the first mlx4_qp_query
	context2 = malloc(sizeof (struct mlx4_qp_context), M_QP_VAL, M_WAITOK);
        VL_CHECK_MALLOC(context2, goto free_context, log);
        memset(context2, 0, sizeof (struct mlx4_qp_context));

	//context for the second mlx4_qp_query
	context3 = malloc(sizeof (struct mlx4_qp_context), M_QP_VAL, M_WAITOK);
	VL_CHECK_MALLOC(context3, goto free_context2, log);
	memset(context3, 0, sizeof (struct mlx4_qp_context));

	db = malloc(sizeof (struct mlx4_db), M_QP_VAL, M_WAITOK);
        VL_CHECK_MALLOC(db, goto free_context3, log);
        err = mlx4_db_alloc(dev, db, 1);
        VL_CHECK_RC(err, expected_rc, goto free_db, log, "DB allocation failed");
        uprintf("DB was allocated successfuly\n");

	uar = malloc(sizeof (struct mlx4_uar), M_QP_VAL, M_WAITOK);
        VL_CHECK_MALLOC(uar, goto dealloc_db, log);
        err = mlx4_uar_alloc(dev, uar);
        VL_CHECK_RC(err, expected_rc, goto free_uar, log, "UAR allocation failed");
        uprintf("UAR was allocated successfuly\n");

	err = mlx4_pd_alloc(dev, &pdn);
	VL_CHECK_RC(err, expected_rc, goto dealloc_uar, log, "PD allocation failed");
	uprintf("PD was allocated successfuly\n");

	mtt = malloc(sizeof (struct mlx4_mtt), M_QP_VAL, M_WAITOK);
        VL_CHECK_MALLOC(mtt, goto dealloc_pd, log);
        err = mlx4_mtt_init(dev, npages, page_shift, mtt);
        VL_CHECK_RC(err, expected_rc, goto free_mtt, log, "MTT initialization failed");
        uprintf("MTT was initialized successfuly\n");
        mtt_addr = mlx4_mtt_addr(dev, mtt);

	cq = malloc(sizeof (struct mlx4_cq), M_QP_VAL, M_WAITOK);
        VL_CHECK_MALLOC(cq, goto cleanup_mtt, log);
        err = mlx4_cq_alloc(dev, nent, mtt, uar, db->dma, cq, vector, collapsed, timestamp_en);
        VL_CHECK_RC(err, expected_rc, goto free_cq, log, "CQ allocation failed");
        uprintf("CQ was allocated successfuly\n");

/* ----------------------------------------- all qp resources were allocated --------------------------------------------------*/

	err = mlx4_qp_reserve_range(dev, cnt, align, &qpn, flags);
	VL_CHECK_RC(err, expected_rc, goto dealloc_cq , log, "mlx4_qp_reserve_range failed");
        uprintf("mlx4_qp_reserve_range was successful\n");

	err = mlx4_qp_alloc(dev, qpn, qp);
	VL_CHECK_RC(err, expected_rc, goto qp_free_range , log, "QP allocation failed");
        uprintf("mlx4_qp_alloc was successful\n");

	//prepare context for mlx4_qp_tp_ready use.
	// Taken from mlx4_en_fill_qp_context function in the <en_resources.c>
	context->db_rec_addr 			= cpu_to_be64(db->dma);
	context->flags 				= cpu_to_be32(7 << 16 | rss << MLX4_RSS_QPC_FLAG_OFFSET);
	context->pd 				= cpu_to_be32(pdn);
	context->mtu_msgmax 			= 0xff;
	context->rq_size_stride 		= 3;
	context->sq_size_stride 		= 3;
	context->usr_page 			= cpu_to_be32(uar->index);
	context->local_qpn 			= cpu_to_be32(qpn);
	context->pri_path.ackto 		= 1 & 0x07;
	context->cqn_send 			= cpu_to_be32(cq->cqn);
	context->cqn_recv 			= cpu_to_be32(cq->cqn);
	context->db_rec_addr 			= cpu_to_be64(db->dma << 2);

	err = mlx4_qp_modify(dev, mtt, MLX4_QP_STATE_RST, MLX4_QP_STATE_INIT, context, 0, 0, qp);
	VL_CHECK_RC(err, expected_rc, goto qp_dealloc, log, "mlx4_qp_modify failed");
        uprintf("mlx4_qp_modify was successful\n");

	err = mlx4_qp_query(dev, qp, context2);
	VL_CHECK_RC(err, expected_rc, goto qp_dealloc, log, "mlx4_qp_query failed");
        uprintf("mlx4_qp_query was successful\n");
	uprintf("context.flags = %d\n", be32_to_cpu(context2->flags));

	mlx4_state = be32_to_cpu(context2->flags) >> 28;
	VL_CHECK_RC(mlx4_state, MLX4_QP_STATE_INIT, goto qp_dealloc , log, "QP state is not MLX4_QP_STATE_INIT");

	err = mlx4_qp_modify(dev, mtt, MLX4_QP_STATE_INIT, MLX4_QP_STATE_RTR, context, 0, 0, qp);
	VL_CHECK_RC(err, expected_rc, goto qp_dealloc, log, "mlx4_qp_modify failed");
        uprintf("mlx4_qp_modify was successful\n");

	err = mlx4_qp_query(dev, qp, context3);
	VL_CHECK_RC(err, expected_rc, goto qp_dealloc, log, "mlx4_qp_query failed");
        uprintf("mlx4_qp_query was successful\n");
        uprintf("context.flags = %d\n", be32_to_cpu(context3->flags));

	mlx4_state = be32_to_cpu(context3->flags) >> 28;
	VL_CHECK_RC(mlx4_state, MLX4_QP_STATE_RTR, goto qp_dealloc , log, "QP state is not MLX4_QP_STATE_RTR");

	//context2 should be different from context3
        if(context2->flags == context3->flags) {
                uprintf("fail - context3->flags should be different from context2->flags\n");
                strncpy(log, "fail - context3->flags should be different from context2->flags\n", MAX_BUF_SIZE);
                goto qp_dealloc;
        }

	ret_val = SUCCESS;

/* ----------------------------------------------------- test clean up -------------------------------------------------------- */

qp_dealloc:
	//move QP back to MLX4_QP_STATE_RST state before its removal
	err = mlx4_qp_modify(dev, mtt, MLX4_QP_STATE_RTR, MLX4_QP_STATE_RST, context, 0, 0, qp);
	VL_CHECK_RC(err, expected_rc, ret_val = FAIL, log, "mlx4_qp_modify failed");
        uprintf("mlx4_qp_modify was successful\n");

	mlx4_qp_remove(dev, qp);
        uprintf("mlx4_qp_remove was successful\n");
        mlx4_qp_free(dev, qp);
        uprintf("mlx4_qp_free was successful\n");

qp_free_range:
	mlx4_qp_release_range(dev, qpn, cnt);
        uprintf("mlx4_qp_release_range was successful\n");

dealloc_cq:
	mlx4_cq_free(dev, cq);
        uprintf("CQ free was successful\n");

free_cq:
	free(cq, M_QP_VAL);

cleanup_mtt:
	mlx4_mtt_cleanup(dev, mtt);
        uprintf("mtt was cleaned-up successfuly\n");

free_mtt:
	free(mtt, M_QP_VAL);

dealloc_pd:
	mlx4_pd_free(dev, pdn);
	uprintf("PD free was successful\n");

dealloc_uar:
	mlx4_uar_free(dev,uar);
	uprintf("UAR was freed\n");

free_uar:
	free(uar, M_QP_VAL);

dealloc_db:
	mlx4_db_free(dev, db);
        uprintf("db was freed successfuly\n");

free_db:
	free(db, M_QP_VAL);

free_context3:
	free(context3, M_QP_VAL);

free_context2:
	free(context2, M_QP_VAL);

free_context:
	free(context, M_QP_VAL);

free_qp:
        free(qp, M_QP_VAL);

without_free:
	return ret_val;
}


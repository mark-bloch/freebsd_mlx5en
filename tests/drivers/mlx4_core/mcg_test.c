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
 * $Id: mcg_test.c 2013-07-24 16:38 Daria Zasipko $
 *
 */

#include <linux/mlx4/qp.h>
#include "mlx4_core_tests.h"

MALLOC_DEFINE(M_MCG_VAL, "mcg buffer", "buffer for mcg tests");

enum communication_state {
	UNICAST = 0,
	MULTICAST,
};

/* Taken from <infiniband/hw/mlx4/mlx4_ib.h> */
enum {
        MLX4_NUM_TUNNEL_BUFS            = 256,
};


/* 	Steering Mode:
 *	- B0 steering mode - Common low level API for ib and (if supported) eth.
 *	- A0 steering mode - Limited low level API for eth. In case of IB,
 *			     B0 mode is in use.
 * 	More about steering mode in <device.h>
 */

static int multicast_unicast_test(struct mlx4_dev *dev, char *log, int steering_mode, enum mlx4_protocol prot, enum communication_state communication_mode) {

	struct mlx4_mtt *mtt;
	struct mlx4_qp *qp;
	struct mlx4_qp_context *context;
	struct mlx4_db *db;
	struct mlx4_uar *uar;
	struct mlx4_cq *cq;

	int err;
	int mlx4_state;
        int expected_rc                 = 0;
	int ret_val                     = FAIL;
	int port                        = 1;
	int cnt                         = 1;
	int align                       = 1;
	int npages                      = 1;
	int rss                         = 0;
	int page_shift                  = get_order(dev->caps.cqe_size) + PAGE_SHIFT;
	int nent                        = 2 * MLX4_NUM_TUNNEL_BUFS;
	int collapsed                   = 0;
	int timestamp_en                = 0;
	int block_mcast_loopback        = 0;
        int vector                      = 0;

	enum mlx4_qp_state qp_state     = MLX4_QP_STATE_RST;

	/* gid should be from the folowing structure for ethernet : 5th bit = port, 10th-15th bits = mac */
	u8 gid[16]                      = {0,0,0,0,0,0x1,0,0,0,0,1,1,1,1,1,1};
	u8 flags                        = MLX4_RESERVE_BF_QP;
	u32 pdn;
	u32 qpn ;
	u64 reg_id;

	qp = malloc(sizeof (struct mlx4_qp), M_MCG_VAL, M_WAITOK);
	VL_CHECK_MALLOC(qp, goto without_free, log);

	context = malloc(sizeof (struct mlx4_qp_context), M_MCG_VAL, M_WAITOK);
	VL_CHECK_MALLOC(context, goto free_qp, log);
	memset(context, 0, sizeof (struct mlx4_qp_context));

	db = malloc(sizeof (struct mlx4_db), M_MCG_VAL, M_WAITOK);
	VL_CHECK_MALLOC(db, goto free_context, log);

	err = mlx4_db_alloc(dev, db, 1);
	VL_CHECK_RC(err, expected_rc, goto free_db, log, "DB allocation failed");
	uprintf("DB was allocated successfuly\n");

	uar = malloc(sizeof (struct mlx4_uar), M_MCG_VAL, M_WAITOK);
	VL_CHECK_MALLOC(uar, goto dealloc_db, log);

	err = mlx4_uar_alloc(dev, uar);
	VL_CHECK_RC(err, expected_rc, goto free_uar, log, "UAR allocation failed");
	uprintf("UAR was allocated successfuly\n");

	err = mlx4_pd_alloc(dev, &pdn);
	VL_CHECK_RC(err, expected_rc, goto dealloc_uar, log, "PD allocation failed");
	uprintf("PD was allocated successfuly, PD number is:%u\n", pdn);

	mtt = malloc(sizeof (struct mlx4_mtt), M_MCG_VAL, M_WAITOK);
	VL_CHECK_MALLOC(mtt, goto dealloc_pd, log);

	err = mlx4_mtt_init(dev, npages, page_shift, mtt);
	VL_CHECK_RC(err, expected_rc, goto free_mtt, log, "MTT initialization failed");
	uprintf("MTT was initialized successfuly\n");

	cq = malloc(sizeof (struct mlx4_cq), M_MCG_VAL, M_WAITOK);
	VL_CHECK_MALLOC(cq, goto cleanup_mtt, log);

	err = mlx4_cq_alloc(dev, nent, mtt, uar, db->dma, cq, vector, collapsed, timestamp_en);
	VL_CHECK_RC(err, expected_rc, goto free_cq, log, "CQ allocation failed");
	uprintf("CQ allocated successfuly\n");

	err = mlx4_qp_reserve_range(dev, cnt, align, &qpn, flags);
	VL_CHECK_RC(err, expected_rc, goto dealloc_cq, log, "mlx4_qp_reserve_range failed");
	uprintf("mlx4_qp_reserve_range was successful\n");
	uprintf("qp number = %d\n", qpn);

	err = mlx4_qp_alloc(dev, qpn, qp);
	VL_CHECK_RC(err, expected_rc, goto qp_release_range, log, "QP allocation failed");
	uprintf("mlx4_qp_alloc was successful\n");

	// prepare context for mlx4_qp_tp_ready use.
	// Taken from mlx4_en_fill_qp_context function in the <en_resources.c>
	context->db_rec_addr    = cpu_to_be64(db->dma);
	context->flags          = cpu_to_be32(7 << 16 | rss << MLX4_RSS_QPC_FLAG_OFFSET);
	context->pd             = cpu_to_be32(pdn);
	context->mtu_msgmax     = 0xff;
	context->rq_size_stride = 3;
	context->sq_size_stride = 3;
        context->usr_page       = cpu_to_be32(uar->index);
	context->local_qpn      = cpu_to_be32(qpn);
	context->pri_path.ackto = 1 & 0x07;
	context->cqn_send       = cpu_to_be32(cq->cqn);
	context->cqn_recv       = cpu_to_be32(cq->cqn);
	context->db_rec_addr    = cpu_to_be64(db->dma << 2);

	err = mlx4_qp_to_ready(dev, mtt, context,qp ,&qp_state);
	VL_CHECK_RC(err, expected_rc, goto remove_qp, log, "mlx4_qp_to_ready failed");
	uprintf("mlx4_qp_to_ready was successful\n");
	mlx4_state = be32_to_cpu(context->flags) >> 28;
	VL_CHECK_UNSIGNED_INT_VALUE(mlx4_state, MLX4_QP_STATE_RTS, goto remove_qp, log, "QP state != MLX4_QP_STATE_RTS");

	if(MULTICAST == communication_mode && (MLX4_STEERING_MODE_A0 == steering_mode))
		dev->caps.steering_mode = MLX4_STEERING_MODE_A0;

	uprintf("dev->caps.steering_mode = %d\n",dev->caps.steering_mode);

        if(MULTICAST == communication_mode) { //multicast
		err = mlx4_multicast_attach(dev, qp, gid, port, block_mcast_loopback, prot, &reg_id);
		VL_CHECK_RC(err, expected_rc, goto remove_qp, log, "mlx4_multicast_attach failed");
		uprintf("mlx4_multicast_attach was successful\n");

		err = mlx4_multicast_detach(dev, qp,  gid, prot, reg_id);
		VL_CHECK_RC(err, expected_rc, goto remove_qp, log, "mlx4_multicast_detach failed");
		uprintf("mlx4_multicast_detach was successful\n");
        }
        else { //unicast
                err = mlx4_unicast_attach(dev, qp, gid, block_mcast_loopback, prot);
                VL_CHECK_RC(err, expected_rc, goto remove_qp, log, "mlx4_unicast_attach failed");
                uprintf("mlx4_unicast_attach was successful\n");

                err = mlx4_unicast_detach(dev, qp, gid, prot);
                VL_CHECK_RC(err, expected_rc, goto remove_qp, log, "mlx4_unicast_detach failed");
                uprintf("mlx4_unicast_detach was successful\n");
        }

        ret_val = SUCCESS;

remove_qp:
        //move QP back to MLX4_QP_STATE_RST state before its removal
        err = mlx4_qp_modify(dev, mtt, MLX4_QP_STATE_RTS, MLX4_QP_STATE_RST, context, 0, 0, qp);
        VL_CHECK_RC(err, expected_rc, ret_val = FAIL, log, "QP modify failed");
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
	free(cq, M_MCG_VAL);

cleanup_mtt:
        mlx4_mtt_cleanup(dev, mtt);
	uprintf("mtt was cleaned-up successfuly\n");

free_mtt:
	free(mtt, M_MCG_VAL);

dealloc_pd:
        mlx4_pd_free(dev, pdn);
	uprintf("PD free was successful\n");

dealloc_uar:
        mlx4_uar_free(dev,uar);
	uprintf("UAR was freed\n");

free_uar:
	free(uar, M_MCG_VAL);

dealloc_db:
        mlx4_db_free(dev, db);
	uprintf("db was freed successfuly\n");

free_db:
	free(db, M_MCG_VAL);

free_context:
        free(context, M_MCG_VAL);

free_qp:
	free(qp, M_MCG_VAL);

without_free:
        return ret_val;
}

/* IPV6 over IB with steering mode B0 multicast rule attach and detach test */
int ipv6_over_ib_steering_mode_B0_multicast_test(struct mlx4_dev *dev, char *log)
{
	return multicast_unicast_test(dev, log, MLX4_STEERING_MODE_A0, MLX4_PROT_IB_IPV6, MULTICAST);
}

/* ETH with steering mode B0 multicast rule attach and detach test  */
int eth_steering_mode_BO_multicast_test(struct mlx4_dev *dev, char *log)
{
	return multicast_unicast_test(dev, log, MLX4_STEERING_MODE_A0, MLX4_PROT_ETH, MULTICAST);
}

/* ib with steering mode A0 multicast rule attach and detach test  */
int ib_steering_mode_A0_multicast_test(struct mlx4_dev *dev, char *log)
{
	return multicast_unicast_test(dev, log, MLX4_STEERING_MODE_B0, MLX4_PROT_IB_IPV6, MULTICAST);
}

/* ipv6 over ib unicast rule attach and detach test */
int ipv6_ib_unicast_test(struct mlx4_dev *dev, char *log)
{
	return multicast_unicast_test(dev, log, MLX4_STEERING_MODE_B0, MLX4_PROT_IB_IPV6, UNICAST);
}

/* ETH unicast rule attach and detach test */
int eth_unicast_test(struct mlx4_dev *dev, char *log)
{
	return multicast_unicast_test(dev, log, MLX4_STEERING_MODE_B0, MLX4_PROT_ETH, UNICAST);
}

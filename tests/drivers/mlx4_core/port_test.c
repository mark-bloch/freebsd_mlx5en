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
 * $Id: fw_test.c 2013-06-16 17:20 Daria Zasipko $
 *
 */

#include <../drivers/net/ethernet/mellanox/mlx4/mlx4.h>
#include "mlx4_core_tests.h"
#include <linux/mlx4/qp.h>

/* mac registration, replacement and unregistration test  */
int mac_functionality_test(struct mlx4_dev *dev, char *log) {

	int err;
	int base_qpn;
	int index 	= 0;
        int ret_val 	= FAIL;
        int expected_rc = 0;

	u8 port 	= 1;
	u64 mac 	= dev->caps.def_mac[port];
	u64 new_mac 	= mac + 1;

	uprintf("MAC: %lu\n",mac);

	index = mlx4_register_mac(dev, port, mac);
        VL_CHECK_LESS(index, 0, goto out, log, "Failed to add MAC");
	uprintf("MAC: %lu was added successfuly, index = %d\n", mac, index);

	base_qpn = mlx4_get_base_qpn(dev, port);
        uprintf("bace qpn: %d\n",base_qpn);

	err = __mlx4_replace_mac(dev, port, base_qpn+index, new_mac);
        VL_CHECK_RC(err, expected_rc, goto out, log, "Failed replace MAC with new_mac");
        uprintf("replace MAC with %lu was successful\n",new_mac);

	mlx4_unregister_mac(dev, port, new_mac);
        uprintf("MAC was unregistered successfuly\n");
        ret_val = SUCCESS;

out:
	return ret_val;
}

/* vlan registration, unregistration and lookup test */
int vlan_functionality_test(struct mlx4_dev *dev, char *log)
{
	int err;
	int index 	= 0;
	int expected_rc = 0;
	int ret_val 	= FAIL;

	u16 vlan 	= 1000;
	u8 port 	= 1;

	err = mlx4_find_cached_vlan(dev, port, vlan, &index);
	VL_CHECK_EQUALS(err, 0, goto out, log, "vlan was found in the vlan table");
	uprintf("vlan 0x%x is not in the vlan table\n", vlan);

	err = mlx4_register_vlan(dev, port, vlan, &index);
	VL_CHECK_RC(err, expected_rc, goto out, log, "Failed to register vlan");
	uprintf("vlan 0x%x was registered successfuly, index = %d\n", vlan, index);

	err = mlx4_find_cached_vlan(dev, port, vlan, &index);
	VL_CHECK_RC(err, expected_rc, goto out, log, "vlan is not in the vlan table");
	uprintf("vlan 0x%x was found, index = %d\n", vlan, index);

	mlx4_unregister_vlan(dev, port, vlan);
	uprintf("vlan 0x%x was unregistered successfuly\n", vlan);

	err = mlx4_find_cached_vlan(dev, port, vlan, &index);
	VL_CHECK_EQUALS(err, 0, goto out, log, "vlan still registered");
        uprintf("vlan 0x%x is not in the vlan table\n", vlan);
	ret_val = SUCCESS;
out:
        return ret_val;
}

/* Taken from <en_main.c> */
#define MLX4_EN_PARM_INT(X, def_val, desc) \
        static unsigned int X = def_val;\
        module_param(X , uint, 0444); \
        MODULE_PARM_DESC(X, desc);

/* Taken from <device.h> */
MLX4_EN_PARM_INT(pfcrx, 0, "Priority based Flow Control policy on RX[7:0]. Per priority bit mask");

MALLOC_DEFINE(M_PORT_VAL, "port buffer", "buffer for port tests");

/* PORT functionaluty test */
int SET_PORT_general_test(struct mlx4_dev *dev, char *log) {

	int err;
	int mtu  		= 1500;
	int ret_val 		= FAIL;
	int expected_rc 	= 0;

	u8 port 		= 1;
	u8 pptx 		= 1;
	u8 pfctx 		= pfcrx;
	u8 pprx 		= 1;

	err = mlx4_SET_PORT_general(dev, port, mtu, pptx, pfctx, pprx, pfcrx);
	VL_CHECK_RC(err, expected_rc, goto out, log, "SET_PORT_general FAILED");
	uprintf("SET_PORT_general was successful\n");

	ret_val = SUCCESS;

out:
        return ret_val;
}

/* PORT functionaluty test */
int SET_PORT_qpn_calc_test(struct mlx4_dev *dev, char *log) {

        struct mlx4_qp *qp;

        int err;
        int ret_val             = FAIL;
        int expected_rc         = 0;
        int cnt                 = 1;
        int align               = 1;

        u8 port                 = 1;
        u8 promisc              = 0;
        u8 flags                = MLX4_RESERVE_BF_QP;
        u32 qpn ;

        /* allocate qp to get base qpn */
        qp = malloc(sizeof (struct mlx4_qp), M_PORT_VAL, M_WAITOK);
        VL_CHECK_MALLOC(qp, goto out, log);

        err = mlx4_qp_reserve_range(dev, cnt, align, &qpn, flags);
        VL_CHECK_RC(err, expected_rc, goto qp_dealloc, log, "mlx4_qp_reserve_range FAILED");
        uprintf("qp number = %d\n", qpn);
        uprintf("mlx4_qp_reserve_range was successful\n");

        err = mlx4_qp_alloc(dev, qpn, qp);
        VL_CHECK_RC(err, expected_rc, goto qp_release_range, log, "QP allocation FAILED");
        uprintf("mlx4_qp_alloc was successful\n");
        /* end of qp allocation */

        err = mlx4_SET_PORT_qpn_calc(dev, port, qpn, promisc);
        VL_CHECK_RC(err, expected_rc, goto qp_free, log, "SET_PORT_qpn_calc FAILED");
        uprintf("SET_PORT_qpn_calc was successful\n");

	ret_val = SUCCESS;

qp_free:
	mlx4_qp_remove(dev, qp);
        uprintf("mlx4_qp_remove was successful\n");
        mlx4_qp_free(dev, qp);
        uprintf("mlx4_qp_free was successful\n");

qp_release_range:
	mlx4_qp_release_range(dev, qpn, cnt);
	uprintf("mlx4_qp_release_range was successful\n");
	
qp_dealloc:
	free(qp, M_PORT_VAL);

out:
	return ret_val;
}

/* PORT functionaluty test */
int SET_PORT_PRIO2TC_test(struct mlx4_dev *dev, char *log) {

        int err;
        int ret_val             = FAIL;
        int expected_rc         = 0;

        u8 port                 = 1;
        u8 prio2tc              = 1;

        err = mlx4_SET_PORT_PRIO2TC(dev, port, &prio2tc);
        VL_CHECK_RC(err, expected_rc, goto out, log, "SET_PORT_PRIO2TC FAILED");
        uprintf("SET_PORT_PRIO2TC was successful\n");

        ret_val = SUCCESS;

out:
        return ret_val;
}

/* PORT functionaluty test */
int SET_PORT_SCHEDULER_test(struct mlx4_dev *dev, char *log) {

        int err;
        int ret_val             = FAIL;
        int expected_rc         = 0;

        u8 port                 = 1;
        u8 tc_tx_bw             = 1;
        u8 pg                   = 1;
        u16 ratelimit           = 1;

        err = mlx4_SET_PORT_SCHEDULER(dev, port, &tc_tx_bw, &pg, &ratelimit);
        VL_CHECK_RC(err, expected_rc, goto out, log, "SET_PORT_SCHEDULER FAILED");
        uprintf("SET_PORT_SCHEDULER was successful\n");

        ret_val = SUCCESS;

out:
        return ret_val;
}

/* PORT functionaluty test */
int SET_MCAST_FLTR_test(struct mlx4_dev *dev, char *log) {

        int err;
        int ret_val             = FAIL;
        int expected_rc         = 0;

        u8 port                 = 1;
        u8 mode                 = 0;
        u64 mac                 = 0;
        u64 clear               = 1;

        err = mlx4_SET_MCAST_FLTR(dev, port, mac, clear, mode);
        VL_CHECK_RC(err, expected_rc, goto out, log, "SET_PORT_FLTR FAILED");
        uprintf("SET_MCAST_FLTR was successful\n");

        ret_val = SUCCESS;

out:
        return ret_val;
}

/* Taken from port.c */
#define MLX4_STATS_TRAFFIC_COUNTERS_MASK	0xfULL
#define MLX4_STATS_TRAFFIC_DROPS_MASK		0xc0ULL
#define MLX4_STATS_ERROR_COUNTERS_MASK		0x1ffc30ULL
#define MLX4_STATS_PORT_COUNTERS_MASK		0x1fe00000ULL
#define MLX4_STATS_IF_RX_ERRORS_COUNTERS_MASK	0x8010ULL

/* PORT functionaluty test */
int SET_stats_bitmap_test(struct mlx4_dev *dev, char *log) {

        int ret_val             		= FAIL;

        u64 expected_rc         		= 0;
        u64 stats_bitmap        		= 1024;
	u64 expected_stats_bitmap        	= MLX4_STATS_TRAFFIC_COUNTERS_MASK |
			 				MLX4_STATS_TRAFFIC_DROPS_MASK |
			 				MLX4_STATS_PORT_COUNTERS_MASK |
			 				MLX4_STATS_IF_RX_ERRORS_COUNTERS_MASK;
	u64 expected_stats_bitmap_master        = expected_stats_bitmap | MLX4_STATS_ERROR_COUNTERS_MASK;

        mlx4_set_stats_bitmap(dev, &stats_bitmap);
        uprintf("mlx4_set_stats_bitmap was successful\n");

        if (!(dev->flags & (MLX4_FLAG_SLAVE | MLX4_FLAG_MASTER))) {//!mfunc
                VL_CHECK_LONG_LONG_INT_VALUE(stats_bitmap, expected_rc, goto out, log, "stats_bitmap should be 0");
	}
	else if (dev->flags & MLX4_FLAG_MASTER) {//master
		VL_CHECK_LONG_LONG_INT_VALUE(stats_bitmap, expected_stats_bitmap_master, goto out, log, "stats_bitmap is wrong");
	}
	else {
		VL_CHECK_LONG_LONG_INT_VALUE(stats_bitmap, expected_stats_bitmap, goto out, log, "stats_bitmap is wrong");		
	}

        ret_val = SUCCESS;

out:
        return ret_val;
}


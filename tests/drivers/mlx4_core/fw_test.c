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

#include <linux/jiffies.h>
#include "mlx4_core_tests.h"
#include <../../../drivers/net/ethernet/mellanox/mlx4/mlx4.h>

/* Taken from /drivers/net/ethernet/mellanox/mlx4/mlx4_en.h */
#define MLX4_EN_WOL_DO_MODIFY (1ULL << 63)

/* Taken from /drivers/net/ethernet/mellanox/mlx4/mlx4_en.h */
enum mlx4_en_wol {
	MLX4_EN_WOL_MAGIC = (1ULL << 61),
	MLX4_EN_WOL_ENABLED = (1ULL << 62),
};

/* PORT and 'wake on LAN' functionality test  */
int fw_test(struct mlx4_dev *dev, char* log) {

	int err;
	int gid_tbl_len;
	int pkey_tbl_len;
	int port 	= 1;
        int expected_rc = 0;
	int ret_val 	= FAIL;
	u64 config 	= 0;

	err = mlx4_INIT_PORT(dev, port);
	VL_CHECK_RC(err, expected_rc, goto fw_out , log, "failed to initialize port");
	uprintf( "Port was initialized successfuly\n");

	err = mlx4_query_diag_counters(dev, 0,3,NULL,NULL);
	VL_CHECK_RC(err, expected_rc, goto fw_out , log, "failed to query_diag_counters");
	uprintf( "query_diag_counters was successful: return = %d\n", err);

	err = mlx4_wol_read(dev, &config, port);
	VL_CHECK_RC(err, expected_rc, goto fw_out , log, "Failed to get WoL info, unable to modify");
	uprintf( "WoL info read was successful\n");

	config |= MLX4_EN_WOL_DO_MODIFY | MLX4_EN_WOL_ENABLED |	MLX4_EN_WOL_MAGIC;
	err = mlx4_wol_write(dev, config, port);
        VL_CHECK_RC(err, expected_rc, goto fw_out , log, "Failed to set WoL information");
	uprintf( "WoL info write was successful\n");

	config &= ~(MLX4_EN_WOL_ENABLED | MLX4_EN_WOL_MAGIC);
	config |= MLX4_EN_WOL_DO_MODIFY;
	err = mlx4_wol_write(dev, config, port);
        VL_CHECK_RC(err, expected_rc, goto fw_out , log, "Failed to set WoL information");
	uprintf( "WoL info write was successful\n");

	err = mlx4_get_slave_pkey_gid_tbl_len(dev, port, &gid_tbl_len, &pkey_tbl_len);
	VL_CHECK_RC(err, expected_rc, goto fw_out , log, "Failed to get gid_tbl_len and pkey_tbl_len");
	uprintf( "mlx4_get_slave_pkey_gid_tbl_len was successful, gid_tbl_len = %d, pkey_tbl_len = %d\n",gid_tbl_len  ,pkey_tbl_len);

	err = mlx4_CLOSE_PORT(dev, port);
	VL_CHECK_RC(err, expected_rc, goto fw_out , log, "Failed to close port");
	uprintf( "Closed port successfuly\n");

	err = mlx4_INIT_PORT(dev, port);
        VL_CHECK_RC(err, expected_rc, goto fw_out , log, "Failed to initialize port");
	uprintf( "Port was initialized successfuly after CLOSE_PORT\n");

	//sleep untill the port will go up again
        pause("lnxsleep", msecs_to_jiffies(30000));
	uprintf("Port should be up\n");
	ret_val = SUCCESS;

fw_out:
	return ret_val;
}


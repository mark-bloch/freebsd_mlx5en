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
 * $Id: pd_test.c 2013-05-23 16:21 Daria Zasipko $
 *
 */

#include "mlx4_core_tests.h"

MALLOC_DEFINE(M_PD_VAL, "pd buffer", "buffer for pd tests");

/* Blue-Flame allocation test */
int bf_test (struct mlx4_dev *dev, char *log)
{
	struct mlx4_bf *bf;
        int expected_rc = 0;
	int node = 0;
	int ret_val = FAIL;

        bf = malloc(sizeof (struct mlx4_bf), M_PD_VAL, M_WAITOK);
	VL_CHECK_MALLOC(bf, goto bf_without_free, log);

        int err = mlx4_bf_alloc(dev, bf, node);
	VL_CHECK_RC(err, expected_rc, goto bf_free_bf , log, "failed to allocate BF");

        uprintf( "BF was allocated successfuly\n");
	uprintf( "bf offset = %lu bf->uar->pfn = %lu ,bf->uar->index = %d\n",bf->offset, bf->uar->pfn, bf->uar->index);

        mlx4_bf_free(dev,bf);
	uprintf( "BF free was successful\n");
	ret_val = SUCCESS;

bf_free_bf:
	free(bf, M_PD_VAL);
bf_without_free:
	return ret_val;
}

/* User Access Region allocation test  */
int uar_test (struct mlx4_dev *dev, char *log)
{
        struct mlx4_uar *uar;
	struct mlx4_uar *uar2;
        int err;
	int ret_val = FAIL;
        int expected_rc = 0;

        uar = malloc(sizeof (struct mlx4_uar), M_PD_VAL, M_WAITOK);
        VL_CHECK_MALLOC(uar, goto uar_without_free, log);
        uar2 = malloc(sizeof (struct mlx4_uar), M_PD_VAL, M_WAITOK);
        VL_CHECK_MALLOC(uar2, goto uar_free_uar, log);

        err = mlx4_uar_alloc(dev, uar);
        VL_CHECK_RC(err, expected_rc, goto uar_free_second_uar , log, "failed to allocate UAR");
        uprintf("UAR was allocated successfuly\n");
        uprintf("pfn = %lu ,index = %d\n", uar->pfn, uar->index);

	err = mlx4_uar_alloc(dev, uar2);
        VL_CHECK_RC(err, expected_rc, goto uar_dealloc_uar , log, "failed to allocate UAR");
        uprintf("Second UAR was allocated successfuly\n");
        uprintf("pfn = %lu ,index = %d\n", uar2->pfn, uar2->index);

        VL_CHECK_GREATER_LONG(uar2->pfn, uar->pfn, goto uar_dealloc_second_uar , log, "Fail - UAR pfn should increase");
	uprintf("UAR pfn is incrementing\n");
	ret_val = SUCCESS;

uar_dealloc_second_uar:
        mlx4_uar_free(dev,uar2);
        uprintf("Second UAR free was successful\n");
uar_dealloc_uar:
	mlx4_uar_free(dev,uar);
        uprintf("UAR free was successful\n");
uar_free_second_uar:
	free(uar2, M_PD_VAL);
uar_free_uar:
	free(uar, M_PD_VAL);
uar_without_free:
        return ret_val;
}


/* Extended Reliable Connected Domain allocation test */
int xrcd_test(struct mlx4_dev *dev, char *log)
{
        u32 xrcdn;
	u32 xrcdn2;
        int err;
        int expected_rc = 0;
	int ret_val = FAIL;

        err = mlx4_xrcd_alloc(dev, &xrcdn);
        VL_CHECK_RC(err, expected_rc, goto xrcd_without_free , log, "failed to allocate XRCD");
        uprintf("XRCD was allocated successfuly\n");
        uprintf("XRCD number is:%u\n", xrcdn);

	err = mlx4_xrcd_alloc(dev, &xrcdn2);
	VL_CHECK_RC(err, expected_rc, goto xrcd_free_xrcd , log, "failed to allocate XRCD");
        uprintf("Second XRCD was allocated successfuly\n");
        uprintf("Second XRCD number is:%u\n", xrcdn2);

        VL_CHECK_GREATER(xrcdn2, xrcdn, goto xrcd_free_second_xrcd , log, "Fail - XRCD number should increase");
	uprintf("XRCD number is incrementing\n");
	ret_val = SUCCESS;
xrcd_free_second_xrcd:
        mlx4_xrcd_free(dev, xrcdn2);
        uprintf("Second XRCD free was successful\n");
xrcd_free_xrcd:
	mlx4_xrcd_free(dev, xrcdn);
        uprintf("XRCD free was successful\n");
xrcd_without_free:
	return ret_val;
}

/* Protection Domain allocation test  */
int pd_test(struct mlx4_dev *dev, char *log)
{
        u32 pdn;
	u32 pdn2;
        int err;
        int expected_rc = 0;
	int ret_val = FAIL;

        err = mlx4_pd_alloc(dev, &pdn);
        VL_CHECK_RC(err, expected_rc, goto pd_without_free , log, "failed to allocate PD");
        uprintf("PD was allocated successfuly\n");
        uprintf("PD number is:%u\n", pdn);

        err = mlx4_pd_alloc(dev, &pdn2);
	VL_CHECK_RC(err, expected_rc, goto pd_free_pd , log, "failed to allocate PD");
	uprintf("Second PD was allocated successfuly\n");
        uprintf("Second PD number is:%u\n", pdn2);

        VL_CHECK_GREATER(pdn2, pdn, goto pd_free_second_pd , log, "Fail - PD number should increase");
	uprintf("PD number is incrementing\n");
	ret_val = SUCCESS;

pd_free_second_pd:
        mlx4_pd_free(dev, pdn2);
        uprintf("PD free was successful\n");
pd_free_pd:
	mlx4_pd_free(dev, pdn);
        uprintf("Second PD free was successful\n");
pd_without_free:
        return ret_val;
}


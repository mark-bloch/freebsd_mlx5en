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
 * $Id: alloc_test.c 2013-05-14:53 Daria Zasipko $
 *
 */

#include "mlx4_core_tests.h"

MALLOC_DEFINE(M_ALLOC_VAL, "alloc buffer", "buffer for allocation tests");

/* Doorbell allocation test, allocating two doorbells to insure that db->index incrementing  */
int db_test(struct mlx4_dev *dev, char* log)
{
        struct mlx4_db *db;
        struct mlx4_db *db2;
        int expected_rc = 0;
	int ret_val = FAIL;	

	db = malloc(sizeof (struct mlx4_db), M_ALLOC_VAL, M_WAITOK);
        VL_CHECK_MALLOC(db, goto alloc_no_free, log);
        db2 = malloc(sizeof (struct mlx4_db), M_ALLOC_VAL, M_WAITOK);
        VL_CHECK_MALLOC(db2, goto alloc_free_db_malloc, log);

	int err = mlx4_db_alloc(dev, db, 1);
        VL_CHECK_RC(err, expected_rc, goto alloc_free_db2_malloc , log, "failed to allocate DB");
        uprintf( "DB was allocated successfuly\n");
        uprintf( "doorbell index=%d\n", db->index);

	//Second db allocation, index should be bigger.
	err = mlx4_db_alloc(dev, db2, 1);
        VL_CHECK_RC(err, expected_rc, goto alloc_db_free , log, "failed to allocate DB");
        uprintf( "DB was allocated successfuly\n");
        if (db2->index == 0)
        {
                uprintf("unexpected index value doorbell index=%d\n", db2->index);
                strcpy(log, "unexpected index value\n");
                goto alloc_db2_free;
        }
        uprintf( "doorbell index=%d\n", db2->index);
        if (!(db2->index > db->index))
        {
                uprintf("unexpected index value, should be larger than previous index. doorbell index=%d\n", db2->index);
                strcpy(log, "unexpected index value, should be larger than previous index\n");
                goto alloc_db2_free;
        }

        ret_val = SUCCESS;

alloc_db2_free:
	mlx4_db_free(dev, db2);
alloc_db_free:
	mlx4_db_free(dev, db);
alloc_free_db2_malloc:
        free (db2, M_ALLOC_VAL);
alloc_free_db_malloc:
        free (db, M_ALLOC_VAL);
alloc_no_free:
        return ret_val;
}

/* Doorbell and buf allocation test - alloc_hwq_res allocats buf and doorbell, free_hwq_res frees buf and doorbell */
int alloc_hwq_res_test(struct mlx4_dev *dev, char* log)
{
	struct mlx4_hwq_resources *wqres ;
        int expected_rc = 0;
	int ret_val = FAIL;

	wqres = malloc (sizeof (struct mlx4_hwq_resources), M_ALLOC_VAL, M_WAITOK);
        VL_CHECK_MALLOC(wqres, goto alloc_error_hwq, log);

	int err = mlx4_alloc_hwq_res(dev, wqres, 1024, 2 * PAGE_SIZE);
        VL_CHECK_RC(err, expected_rc, goto alloc_error_hwq_wqres , log, "failed to allocate hw res");
	uprintf( "hw res was allocated successfuly\n");
	uprintf( "doorbell index=%d\n", wqres->db.index);

	mlx4_free_hwq_res(dev, wqres, 1024);
	uprintf( "hw res was freed successfuly\n");
	ret_val = SUCCESS;

alloc_error_hwq_wqres:
	free(wqres, M_ALLOC_VAL);
alloc_error_hwq:
	return ret_val;
}


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
 * $Id: eq_test.c 2013-07-25 16:21 Daria Zasipko $
 *
 */

#include "mlx4_core_tests.h"

/* EQ assign and release test,
   Test that verifies accept of interrupts on all the irq vectors of the device */
int eq_test(struct mlx4_dev *dev, char* log) {

	int err;
	int expected_rc = 0;
	int ret_val = FAIL;
        int vector;
	char name[32];

	strncpy(name, "test_device", strlen(name));

	err = mlx4_assign_eq(dev, name, &vector);
	VL_CHECK_RC(err, expected_rc, goto out, log, "mlx4_assign_eq failed");
	uprintf("mlx4_assign_eq was successful\n");

	err = mlx4_test_interrupts(dev);
	VL_CHECK_RC(err, expected_rc, goto out, log, "mlx4_test_interrupts failed");
        uprintf("mlx4_test_interrupts was successful\n");

	mlx4_release_eq(dev, vector);
	uprintf("mlx4_release_eq was successful\n");

	ret_val = SUCCESS;

out:
        return ret_val;
}



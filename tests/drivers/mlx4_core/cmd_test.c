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
 * $Id: cmd_test.c 2013-05-23 15:29: Daria Zasipko $
 *
 */

#include <linux/mlx4/cmd.h>
#include "mlx4_core_tests.h"

int cmd_test (struct mlx4_dev *dev, char* log)
{
	signed long int expected_rc = 0;
	int ret_val = FAIL;
	struct mlx4_cmd_mailbox* mailbox;
	mailbox = mlx4_alloc_cmd_mailbox(dev);
	VL_CHECK_LONG_INT_VALUE(IS_ERR(mailbox), expected_rc, goto mailbox_return , log, "Mailbox allocation failed");
	uprintf( "Mailbox was allocated successfuly\n");
	mlx4_free_cmd_mailbox(dev, mailbox);
	uprintf( "Mailbox was freed successfuly\n");
	ret_val = SUCCESS;
mailbox_return:
	return ret_val;
}


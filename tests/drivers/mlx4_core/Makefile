# $FreeBSD$

.include <bsd.own.mk>

KMOD    = mlx4_core_test_module
SRCS    = device_if.h bus_if.h pci_if.h vnode_if.h
SRCS	+= mlx4_core_test_module.h mlx4_core_test_module.c mlx4_core_tests.h  alloc_test.c pd_test.c cmd_test.c
SRCS	+= qp_test.c mr_test.c srq_test.c fw_test.c port_test.c mcg_test.c eq_test.c cq_test.c

CFLAGS+= -I${.CURDIR}/../../../include
CFLAGS+= -I${.CURDIR}/../../../include/freebsd/include
CFLAGS+= -I${.CURDIR}/../../../drivers/net/ethernet/mellanox/mlx4

.include <bsd.kmod.mk>

CFLAGS+= -Wno-cast-qual -Wno-pointer-arith -fms-extensions





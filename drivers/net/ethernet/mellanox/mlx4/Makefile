# $FreeBSD$
.PATH:  ${.CURDIR}/../../../../../drivers/net/ethernet/mellanox/mlx4/ 
.PATH:  ${.CURDIR}/../../../../../include/linux
.PATH:  ${.CURDIR}/../../../../../include/freebsd/include/linux

.include <bsd.own.mk>

KMOD    = mlx4
SRCS    = device_if.h bus_if.h pci_if.h vnode_if.h opt_inet.h opt_inet6.h
SRCS+=  alloc.c catas.c cmd.c cq.c eq.c fw.c icm.c intf.c main.c mcg.c mr.c linux_compat.c linux_radix.c linux_idr.c
SRCS+=	pd.c port.c profile.c qp.c reset.c sense.c srq.c resource_tracker.c sys_tune.c

CFLAGS+= -I${.CURDIR}/../../../../../drivers/net/ethernet/mellanox/mlx4/ 
CFLAGS+= -I${.CURDIR}/../../../../../include/
CFLAGS+= -I${.CURDIR}/../../../../../include/freebsd/include

.if !defined(KERNBUILDDIR)
.if ${MK_INET_SUPPORT} != "no"
opt_inet.h:
	@echo "#define INET 1" > ${.TARGET}
.endif

.if ${MK_INET6_SUPPORT} != "no"
opt_inet6.h:
	@echo "#define INET6 1" > ${.TARGET}
.endif
.endif

.include <bsd.kmod.mk>

CFLAGS+= -Wno-cast-qual -Wno-pointer-arith -Wno-tautological-compare -fms-extensions

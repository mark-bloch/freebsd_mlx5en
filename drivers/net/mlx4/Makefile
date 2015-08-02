# $FreeBSD$
.PATH:  ${.CURDIR}/../../../drivers/net/mlx4

.include <bsd.own.mk>

.PATH:  ${.CURDIR}/../../../include/linux

KMOD=	mlx4
SRCS=	device_if.h bus_if.h pci_if.h vnode_if.h \
	opt_inet.h opt_inet6.h \
	alloc.c catas.c cmd.c cq.c eq.c \
	fw.c icm.c intf.c main.c mcg.c mr.c \
	pd.c port.c profile.c qp.c reset.c sense.c \
	srq.c resource_tracker.c sys_tune.c

OSVERSION!=	/sbin/sysctl -n kern.osreldate

.if ${OSVERSION} < 1100000
SRCS+=	linux_compat.c linux_radix.c linux_idr.c \
	linux_kmod.c linux_pci.c

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
.endif

CFLAGS+= -I${.CURDIR}/../../../drivers/net/mlx4
CFLAGS+= -I${.CURDIR}/../../../include

.if defined(CONFIG_RATELIMIT)
CFLAGS += -DCONFIG_RATELIMIT=1
CFLAGS += -DCONFIG_WQE_FORMAT_1=1
.endif


.include <bsd.kmod.mk>

CFLAGS+= -Wno-cast-qual -Wno-pointer-arith

CWARNFLAGS.mcg.c=	-Wno-unused

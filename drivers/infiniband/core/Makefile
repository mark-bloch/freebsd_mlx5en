# $FreeBSD$
.PATH:  ${.CURDIR}/../../../drivers/infiniband/core
.PATH:  ${.CURDIR}/../../../include/linux
.PATH:  ${.CURDIR}/../../../include/freebsd/include/linux

.include <bsd.own.mk>

KMOD    = ibcore
SRCS    = addr.c cm_msgs.h iwcm.c mad_rmpp.h sa_query.c ucma.c uverbs_cmd.c
SRCS+= agent.c    local_sa.c iwcm.h multicast.c smi.c ud_header.c uverbs_main.c
SRCS+= agent.h core_priv.h mad.c notice.c smi.h umem.c uverbs_marshall.c
SRCS+= cache.c device.c mad_priv.h packer.c sysfs.c user_mad.c verbs.c
SRCS+= cm.c fmr_pool.c mad_rmpp.c sa.h ucm.c uverbs.h cma.c
SRCS+= linux_compat.c linux_radix.c linux_idr.c
SRCS+= vnode_if.h device_if.h bus_if.h pci_if.h opt_inet.h opt_inet6.h

CFLAGS+= -I${.CURDIR}/../../../drivers/infiniband/core
CFLAGS+= -I${.CURDIR}/../../../include/
CFLAGS+= -I${.CURDIR}/../../../include/freebsd/include
CFLAGS+= -DINET6 -DINET -DOFED

.include <bsd.kmod.mk>

CFLAGS+= -Wno-cast-qual -Wno-pointer-arith ${GCC_MS_EXTENSIONS}

CWARNFLAGS.cm.c=	-Wno-unused-function
CWARNFLAGS+=		${CWARNFLAGS.${.IMPSRC:T}}

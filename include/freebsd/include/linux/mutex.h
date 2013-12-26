#ifndef	_FBSD_MUTEX_H_
#define	_FBSD_MUTEX_H_

#include <sys/param.h>
#include <sys/lock.h>
#include <sys/sx.h>

#include <linux/spinlock.h>

typedef struct mutex {
	struct sx sx;
} mutex_t;

#define	mutex_lock(_m)			sx_xlock(&(_m)->sx)
#define	mutex_lock_nested(_m, _s)	mutex_lock(_m)
#define	mutex_lock_interruptible(_m)	({ mutex_lock((_m)); 0; })
#define	mutex_unlock(_m)		sx_xunlock(&(_m)->sx)
#define	mutex_trylock(_m)		!!sx_try_xlock(&(_m)->sx)

#define DEFINE_MUTEX(lock)						\
	mutex_t lock;							\
	SX_SYSINIT_FLAGS(lock, &(lock).sx, "lnxmtx", SX_NOWITNESS)

static inline void
linux_mutex_init(mutex_t *m)
{

	memset(&m->sx, 0, sizeof(m->sx));
	sx_init_flags(&m->sx, "lnxmtx",  SX_NOWITNESS);
}

#define	mutex_init	linux_mutex_init

#endif	/* _FBSD_MUTEX_H_ */

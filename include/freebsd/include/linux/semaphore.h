#ifndef _FBSD_SEMAPHORE_H_
#define _FBSD_SEMAPHORE_H_

#include <sys/param.h>
#include <sys/lock.h>
#include <sys/sema.h>

/*
 * XXX BSD semaphores are disused and slow.  They also do not provide a
 * sema_wait_sig method.  This must be resolved eventually.
 */
struct semaphore {
	struct sema	sema;
};

#define	down(_sem)			sema_wait(&(_sem)->sema)
#define	down_interruptible(_sem)	sema_wait(&(_sem)->sema), 0
#define	down_trylock(_sem)		!sema_trywait(&(_sem)->sema)
#define	up(_sem)			sema_post(&(_sem)->sema)

static inline void
linux_sema_init(struct semaphore *sem, int val)
{

	memset(&sem->sema, 0, sizeof(sem->sema));
	sema_init(&sem->sema, val, "lnxsema");
}

static inline void
init_MUTEX(struct semaphore *sem)
{

	memset(&sem->sema, 0, sizeof(sem->sema));
	sema_init(&sem->sema, 1, "lnxsema");
}

#define	sema_init	linux_sema_init

#endif /* _FBSD_SEMAPHORE_H_ */

#ifndef	_FBSD_COMPLETION_H_
#define	_FBSD_COMPLETION_H_

#include <linux/errno.h>
//#include <linux/sched.h> /* XXX delete or prove needed */
//#include <linux/wait.h>  /* XXX delete or prove needed */      

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sleepqueue.h>
#include <sys/kernel.h>
#include <sys/proc.h>

struct completion {
	unsigned int done;
};

#define	INIT_COMPLETION(c)	((c).done = 0)
#define	init_completion(c)	((c)->done = 0)

static inline void
_complete_common(struct completion *c, int all)
{
	int wakeup_swapper;

	sleepq_lock(c);
	c->done++;
	if (all)
		wakeup_swapper = sleepq_broadcast(c, SLEEPQ_SLEEP, 0, 0);
	else
		wakeup_swapper = sleepq_signal(c, SLEEPQ_SLEEP, 0, 0);
	sleepq_release(c);
	if (wakeup_swapper)
		kick_proc0();
}

#define	complete(c)	_complete_common(c, 0)
#define	complete_all(c)	_complete_common(c, 1)

/*
 * Indefinite wait for done != 0 with or without signals.
 */
static inline long
_wait_for_common(struct completion *c, int flags)
{

	flags |= SLEEPQ_SLEEP;
	for (;;) {
		sleepq_lock(c);
		if (c->done)
			break;
		sleepq_add(c, NULL, "completion", flags, 0);
		if (flags & SLEEPQ_INTERRUPTIBLE) {
			if (sleepq_wait_sig(c, 0) != 0)
				return (-ERESTARTSYS);
		} else
			sleepq_wait(c, 0);
	}
	c->done--;
	sleepq_release(c);

	return (0);
}

#define	wait_for_completion(c)	_wait_for_common(c, 0)
#define	wait_for_completion_interuptible(c)				\
	_wait_for_common(c, SLEEPQ_INTERRUPTIBLE)

static inline long
_wait_for_timeout_common(struct completion *c, long timeout, int flags)
{
	long end;

	end = ticks + timeout;
	flags |= SLEEPQ_SLEEP;
	for (;;) {
		sleepq_lock(c);
		if (c->done)
			break;
		sleepq_add(c, NULL, "completion", flags, 0);
		sleepq_set_timeout(c, end - ticks);
		if (flags & SLEEPQ_INTERRUPTIBLE) {
			if (sleepq_timedwait_sig(c, 0) != 0)
				return (-ERESTARTSYS);
		} else
			sleepq_timedwait(c, 0);
	}
	c->done--;
	sleepq_release(c);
	timeout = end - ticks;

	return (timeout > 0 ? timeout : 1);
}

#define	wait_for_completion_timeout(c, timeout)				\
	_wait_for_timeout_common(c, timeout, 0)
#define	wait_for_completion_interruptible_timeout(c, timeout)		\
	_wait_for_timeout_common(c, timeout, SLEEPQ_INTERRUPTIBLE)

static inline int
try_wait_for_completion(struct completion *c)
{
	int isdone;

	isdone = 1;
	sleepq_lock(c);
	if (c->done)
		c->done--;
	else
		isdone = 0;
	sleepq_release(c);
	return (isdone);
}

static inline int
completion_done(struct completion *c)
{
	int isdone;

	isdone = 1;
	sleepq_lock(c);
	if (c->done == 0)
		isdone = 0;
	sleepq_release(c);
	return (isdone);
}
#endif	/* _FBSD_COMPLETION_H_ */

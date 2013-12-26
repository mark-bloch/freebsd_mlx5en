#ifndef _FBSD_TIMER_H_
#define _FBSD_TIMER_H_

#include <linux/types.h>

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/callout.h>

struct timer_list {
	struct callout	timer_callout;
	void		(*function)(unsigned long);
	unsigned long	data;
	unsigned long	expires;
};

static inline void
_timer_fn(void *context)
{
	struct timer_list *timer;

	timer = context;
	timer->function(timer->data);
}

#define	setup_timer(timer, func, dat)					\
do {									\
	(timer)->function = (func);					\
	(timer)->data = (dat);						\
	callout_init(&(timer)->timer_callout, CALLOUT_MPSAFE);		\
} while (0)

#define	init_timer(timer)						\
do {									\
	(timer)->function = NULL;					\
	(timer)->data = 0;						\
	callout_init(&(timer)->timer_callout, CALLOUT_MPSAFE);		\
} while (0)

#define	mod_timer(timer, exp)						\
do {									\
	(timer)->expires = (exp);					\
	callout_reset(&(timer)->timer_callout, (exp) - jiffies,		\
	    _timer_fn, (timer));					\
} while (0)

#define	add_timer(timer)						\
	callout_reset(&(timer)->timer_callout,				\
	    (timer)->expires - jiffies, _timer_fn, (timer))

#define	del_timer(timer)	callout_stop(&(timer)->timer_callout)
#define	del_timer_sync(timer)	callout_drain(&(timer)->timer_callout)

#define	timer_pending(timer)	callout_pending(&(timer)->timer_callout)

static inline unsigned long
round_jiffies(unsigned long j)
{
	return roundup(j, hz);
}

#endif /* _FBSD_TIMER_H_ */

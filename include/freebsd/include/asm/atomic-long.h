#ifndef	_ATOMIC_LONG_H_
#define	_ATOMIC_LONG_H_

#include <sys/cdefs.h>
#include <sys/types.h>
#include <machine/atomic.h>

typedef struct {
	volatile u_long counter;
} atomic_long_t;

#define	atomic_long_add(i, v)		atomic_long_add_return((i), (v))
#define	atomic_long_inc_return(v)	atomic_long_add_return(1, (v))

static inline long
atomic_long_add_return(long i, atomic_long_t *v)
{
	return i + atomic_fetchadd_long(&v->counter, i);
}

static inline void
atomic_long_set(atomic_long_t *v, long i)
{
	atomic_store_rel_long(&v->counter, i);
}

static inline long
atomic_long_read(atomic_long_t *v)
{
	return atomic_load_acq_long(&v->counter);
}

static inline long
atomic_long_inc(atomic_long_t *v)
{
	return atomic_fetchadd_long(&v->counter, 1) + 1;
}

static inline long
atomic_long_dec(atomic_long_t *v)
{
	return atomic_fetchadd_long(&v->counter, -1) - 1;
}

static inline long
atomic_long_dec_and_test(atomic_long_t *v)
{
	long i = atomic_long_add(-1, v);
	return i == 0 ;
}

#endif	/* _ATOMIC_LONG_H_ */

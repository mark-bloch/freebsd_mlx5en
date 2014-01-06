#ifndef	_FBSD_MODULE_H_
#define	_FBSD_MODULE_H_

#include <linux/list.h>
#include <linux/compiler.h>
#include <linux/kobject.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>

#define MODULE_AUTHOR(name)
#define MODULE_DESCRIPTION(name)
#define MODULE_LICENSE(name)
#undef MODULE_VERSION
#define MODULE_VERSION(name)

#define	THIS_MODULE	((struct module *)0)

#define	EXPORT_SYMBOL(name)
#define	EXPORT_SYMBOL_GPL(name)

#include <sys/linker.h>

static inline void
_module_run(void *arg)
{
	void (*fn)(void);
#ifdef OFED_DEBUG_INIT
	char name[1024];
	caddr_t pc;
	long offset;

	pc = (caddr_t)arg;
	if (linker_search_symbol_name(pc, name, sizeof(name), &offset) != 0)
		printf("Running ??? (%p)\n", pc);
	else
		printf("Running %s (%p)\n", name, pc);
#endif
	fn = arg;
	DROP_GIANT();
	fn();
	PICKUP_GIANT();
}

#define	module_init(fn)							\
	SYSINIT(fn, SI_SUB_LAST, SI_ORDER_FIRST, _module_run, (fn))

/*
 * XXX This is a freebsdism designed to work around not having a module
 * load order resolver built in.
 */
#define	module_init_order(fn, order)					\
	SYSINIT(fn, SI_SUB_LAST, (order), _module_run, (fn))

#define	module_exit(fn)						\
	SYSUNINIT(fn, SI_SUB_LAST, SI_ORDER_FIRST, _module_run, (fn))

#define	module_get(module)
#define	module_put(module)
#define	try_module_get(module)	1

#endif	/* _FBSD_MODULE_H_ */

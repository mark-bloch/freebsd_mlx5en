#ifndef _COMPAT_LINUX_EXPORT_H
#define _COMPAT_LINUX_EXPORT_H 1

#ifdef __linux__
#include <linux/version.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0))
#include_next <linux/export.h>
#else 
#include <linux/module.h>
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0)) */

#endif /* __linux__ */

#ifdef __FreeBSD__ 
#include <linux/module.h>
#endif /* __FreeBSD__ */

#endif	/* _COMPAT_LINUX_EXPORT_H */

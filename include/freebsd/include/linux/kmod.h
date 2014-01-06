#ifndef	_FBSD_KMOD_H_
#define	_FBSD_KMOD_H_

#include <sys/types.h>
#include <sys/syscallsubr.h>
#include <sys/refcount.h>
#include <sys/sbuf.h>
#include <machine/stdarg.h>
#include <sys/proc.h>


static inline int request_module(const char *fmt, ...)
{
        va_list ap;
        char modname[128];
        int fileid;

        va_start(ap, fmt);
        vsnprintf(modname, sizeof(modname), fmt, ap);
        va_end(ap);

        return kern_kldload(curthread, modname, &fileid);
}

#define request_module_nowait request_module




#endif /* _FBSD_KMOD_H_ */

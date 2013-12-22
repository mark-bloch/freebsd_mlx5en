#ifndef LINUX_3_12_COMPAT_H
#define LINUX_3_12_COMPAT_H

#include <linux/version.h>

#ifndef IFF_EIPOIB_PIF
#define IFF_EIPOIB_PIF  0x100000       /* IPoIB PIF intf(eg ib0, ib1 etc.)*/
#endif
#ifndef IFF_EIPOIB_VIF
#define IFF_EIPOIB_VIF  0x200000       /* IPoIB VIF intf(eg ib0.x, ib1.x etc.)*/
#endif

/* Added IFF_SLAVE_NEEDARP for SLES11SP1 Errata kernels where this was replaced
 * by IFF_MASTER_NEEDARP
 */
#ifndef IFF_SLAVE_NEEDARP
#define IFF_SLAVE_NEEDARP 0x40          /* need ARPs for validation     */
#endif

#endif /* LINUX_3_12_COMPAT_H */

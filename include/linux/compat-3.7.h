#ifndef LINUX_3_7_COMPAT_H
#define LINUX_3_7_COMPAT_H

#include <linux/version.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0))

#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/pci.h>
#include <linux/pci_regs.h>
#include <linux/mm.h>
#include <linux/user_namespace.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/seq_file.h>

#define VM_DONTDUMP    VM_NODUMP

#ifdef CONFIG_USER_NS

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,38))
static inline struct user_namespace *seq_user_ns(struct seq_file *seq)
{
	struct file *f = container_of((void *) seq, struct file, private_data);

	return f->f_cred->user_ns;
}
#else
static inline struct user_namespace *seq_user_ns(struct seq_file *seq)
{
	return current_user_ns();
}
#endif /* (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,38)) */

#else
static inline struct user_namespace *seq_user_ns(struct seq_file *seq)
{
	extern struct user_namespace init_user_ns;
	return &init_user_ns;
}
#endif /* CONFIG_USER_NS */

#define netlink_notify_portid(__notify) (__notify->pid)
#define genl_info_snd_portid(__genl_info) (__genl_info->snd_pid)
#define NETLINK_CB_PORTID(__skb) NETLINK_CB(cb->skb).pid

#define mod_delayed_work LINUX_BACKPORT(mod_delayed_work)
bool mod_delayed_work(struct workqueue_struct *wq, struct delayed_work *dwork,
		      unsigned long delay);

/* Backports tty_lock: Localise the lock */
#define tty_lock(__tty) tty_lock()
#define tty_unlock(__tty) tty_unlock()

#define tty_port_register_device(port, driver, index, device) \
	tty_register_device(driver, index, device)

#define pcie_capability_read_word LINUX_BACKPORT(pcie_capability_read_word)
int pcie_capability_read_word(struct pci_dev *dev, int pos, u16 *val);
#define pcie_capability_read_dword LINUX_BACKPORT(pcie_capability_read_dword)
int pcie_capability_read_dword(struct pci_dev *dev, int pos, u32 *val);
#define pcie_capability_write_word LINUX_BACKPORT(pcie_capability_write_word)
int pcie_capability_write_word(struct pci_dev *dev, int pos, u16 val);
#define pcie_capability_write_dword LINUX_BACKPORT(pcie_capability_write_dword)
int pcie_capability_write_dword(struct pci_dev *dev, int pos, u32 val);
#define pcie_capability_clear_and_set_word LINUX_BACKPORT(pcie_capability_clear_and_set_word)
int pcie_capability_clear_and_set_word(struct pci_dev *dev, int pos,
				       u16 clear, u16 set);
#define pcie_capability_clear_and_set_dword LINUX_BACKPORT(pcie_capability_clear_and_set_dword)
int pcie_capability_clear_and_set_dword(struct pci_dev *dev, int pos,
					u32 clear, u32 set);
#define pcie_capability_set_word LINUX_BACKPORT(pcie_capability_set_word)
static inline int pcie_capability_set_word(struct pci_dev *dev, int pos,
					   u16 set)
{
	return pcie_capability_clear_and_set_word(dev, pos, 0, set);
}

#define pcie_capability_set_dword LINUX_BACKPORT(pcie_capability_set_dword)
static inline int pcie_capability_set_dword(struct pci_dev *dev, int pos,
					    u32 set)
{
	return pcie_capability_clear_and_set_dword(dev, pos, 0, set);
}

#define pcie_capability_clear_word LINUX_BACKPORT(pcie_capability_clear_word)
static inline int pcie_capability_clear_word(struct pci_dev *dev, int pos,
					     u16 clear)
{
	return pcie_capability_clear_and_set_word(dev, pos, clear, 0);
}

#define pcie_capability_clear_dword LINUX_BACKPORT(pcie_capability_clear_dword)
static inline int pcie_capability_clear_dword(struct pci_dev *dev, int pos,
					      u32 clear)
{
	return pcie_capability_clear_and_set_dword(dev, pos, clear, 0);
}

#define PCI_EXP_LNKSTA2			50      /* Link Status 2 */

#define MAX_IDR_SHIFT (sizeof(int)*8 - 1)
#define MAX_IDR_BIT (1U << MAX_IDR_SHIFT)
#define MAX_IDR_MASK (MAX_IDR_BIT - 1)

/* IPoIB section */
#ifndef IFLA_IPOIB_MAX
enum {
	IFLA_IPOIB_UNSPEC,
	IFLA_IPOIB_PKEY,
	IFLA_IPOIB_MODE,
	IFLA_IPOIB_UMCAST,
	__IFLA_IPOIB_MAX
};

enum {
	IPOIB_MODE_DATAGRAM  = 0, /* using unreliable datagram QPs */
	IPOIB_MODE_CONNECTED = 1, /* using connected QPs */
};

#define IFLA_IPOIB_MAX (__IFLA_IPOIB_MAX - 1)
#endif

#define FMODE_PATH		((__force fmode_t)0x4000)

#define fget_light LINUX_BACKPORT(fget_light)
extern struct file *fget_light(unsigned int fd, int *fput_needed);

#else /* (LINUX_VERSION_CODE > KERNEL_VERSION(3,7,0)) */
#define netlink_notify_portid(__notify) (__notify->portid)
#define genl_info_snd_portid(__genl_info) (__genl_info->snd_portid)
#define NETLINK_CB_PORTID(__skb) NETLINK_CB(cb->skb).portid
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)) */

#endif /* LINUX_3_7_COMPAT_H */

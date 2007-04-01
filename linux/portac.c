#include <linux/capability.h>
#include <linux/module.h>
#include <linux/security.h>
#include <../security/dummy.c>

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/proc_fs.h>
#include <linux/socket.h>

#include <net/inet_sock.h>

#include "portac.h"

#define PORTAC_VER "1.0"
#define PORTAC_MAX_RULES 16384

#define PORTAC_DEBUG 0
#if PORTAC_DEBUG
# define dprintk(x, args...) do { printk(KERN_DEBUG "portac: " x , ## args); } while(0)
#else
# define dprintk(x, args...)
#endif

MODULE_DESCRIPTION("TCP/UDP port access control");
MODULE_AUTHOR("Simon Arlott <portac@fire.lp0.eu>");
MODULE_LICENSE("GPL");
MODULE_VERSION(PORTAC_VER);

static u32 default_deny_ports = PROT_SOCK - 1;
module_param(default_deny_ports, uint, 0);
MODULE_PARM_DESC(default_deny_ports, "Initial number of ports protected by CAP_NET_BIND_SERVICE (0-65535, standard: 1023)");

static int default_deny_listen = 0;
module_param(default_deny_listen, bool, 0);
MODULE_PARM_DESC(default_deny_listen, "Initial setting for requiring CAP_NET_BIND_SERVICE to listen on port 0 (default: false)");

static int secondary_allow = 1;
module_param(secondary_allow, bool, 0);
MODULE_PARM_DESC(secondary_allow, "Allow a secondary module to be loaded (default: true)");

static int secondary_call_bind = 0;
module_param(secondary_call_bind, bool, 0);
MODULE_PARM_DESC(secondary_call_bind, "Call secondary module for socket_bind if result is ALLOW (default: false)");

static int secondary_call_listen = 1;
module_param(secondary_call_listen, bool, 0);
MODULE_PARM_DESC(secondary_call_listen, "Call secondary module for socket_listen if result is ALLOW (default: true)");

int portac_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen);
int portac_socket_listen(struct socket *sock, int backlog);
int portac_register_security(const char *name, struct security_operations *ops);
int portac_unregister_security(const char *name, struct security_operations *ops);

struct security_operations portac_ops = {
	/* Why do security/capabilities and security/root_plug
	 * use these to load themselves but don't implement them
	 * to let other modules do the same?
	 */
	.register_security = portac_register_security,
	.unregister_security = portac_unregister_security,

	.socket_bind = portac_socket_bind,
	.socket_listen = portac_socket_listen
};

int portac_proc_open(struct inode *inode, struct file *file);
int portac_proc_write(struct file *file, const char __user *user, size_t size, loff_t *offset);
int portac_proc_commit(struct inode *inode, struct file *file);

struct file_operations portac_proc_fops = {
	.owner   = THIS_MODULE,
	.open    = portac_proc_open,
	.write   = portac_proc_write,
	.release = portac_proc_commit
};

DEFINE_MUTEX(portac_acl);
DEFINE_MUTEX(portac_config);
DEFINE_MUTEX(secondary_mod);
int secondary = 0;
int in_config = 0;
struct security_operations primary_ops;
struct security_operations *secondary_ops = NULL;

/* Array of bits laid out in the most confusing way possible.
 * (Also using u8 means it never needs endian conversion).
 *
 * For port 42424, which is 10100101 10111000, remove the smallest 3 bits (>> 3).
 *     10100101 10111 = 2651
 *
 *     Use the 3 bits that were discarded to get the default_action bit.
 *     000 = 0
 *
 *     default_action[2651] & (1 << 0)
 */
u8 default_action[8192];
inline int get_require_cap_net_bind_service(u16 port) {
	dprintk(" (require_cap_net_bind_service) %u=%s\n", port,
			(default_action[port >> 3] & (1 << (port & 0x07))) ? "YES" : "NO");
	return (default_action[port >> 3] & (1 << (port & 0x07))) != 0;
}
inline void set_require_cap_net_bind_service(u16 port, int yes) {
	if (yes)
		default_action[port >> 3] |= (1 << (port & 0x07));
	else
		default_action[port >> 3] &= ~(1 << (port & 0x07));
}
struct portac_entry *portac_entries = NULL;

int portac_check(u16 snum, unsigned short family, unsigned char protocol) {
	struct portac_entry *tmp = portac_entries;
	int log = 0;

	mutex_lock(&portac_acl);
	dprintk("(check) port=%u uid=%u family=%u protocol=%u {\n",
			snum, current->euid, family, protocol);

	while (tmp != NULL) {
		struct portac_entry *entry = tmp;
		tmp = tmp->next;

		dprintk(" > user flags=%s%s%s%s%s%s%s%s(uid=%u grp=%u sport=%u eport=%u)\n",
				PORTAC_FLAG(entry, PORTAC_TCP4) ? "tcp4 " : "",
				PORTAC_FLAG(entry, PORTAC_UDP4) ? "udp4 " : "",
				PORTAC_FLAG(entry, PORTAC_TCP6) ? "tcp6 " : "",
				PORTAC_FLAG(entry, PORTAC_UDP6) ? "udp6 " : "",
				PORTAC_FLAG(entry, PORTAC_UID) ? "uid " : "",
				PORTAC_FLAG(entry, PORTAC_GRP) ? "grp " : "",
				PORTAC_FLAG(entry, PORTAC_LOG) ? "log " : "",
				PORTAC_FLAG(entry, PORTAC_TCP4|PORTAC_UDP4|PORTAC_TCP6|PORTAC_UDP6
					|PORTAC_UID|PORTAC_GRP|PORTAC_LOG) ? "" : " ",
				entry->uid, entry->grp,
				entry->sport, entry->eport);

		if (PORTAC_FLAG(entry, PORTAC_UID) && current->euid != entry->uid) {
			dprintk(" : uid does not match\n");
			continue;
		}

		if (PORTAC_FLAG(entry, PORTAC_GRP) && !in_egroup_p(entry->grp)) {
			dprintk(" : grp does not match\n");
			continue;
		}

		if (!(
				(PORTAC_FLAG(entry, PORTAC_TCP4|PORTAC_UDP4) && family == PF_INET)
					|| (PORTAC_FLAG(entry, PORTAC_TCP6|PORTAC_UDP6) && family == PF_INET6))
				) {
			dprintk(" : family does not match\n");
			continue;
		}

		if (!(
				(PORTAC_FLAG(entry, PORTAC_TCP4|PORTAC_TCP6) && protocol == IPPROTO_TCP)
					|| (PORTAC_FLAG(entry, PORTAC_UDP4|PORTAC_UDP6) && protocol == IPPROTO_UDP))
				) {
			dprintk(" : protocol does not match\n");
			continue;
		}

		if (snum < entry->sport || snum > entry->eport) {
			dprintk(" : port does not match\n");
			continue;
		}

		if (PORTAC_FLAG(entry, PORTAC_DENY)) {
			dprintk(" : DENY\n");
			dprintk("}\n");
			if (log)
				printk("portac: DENY uid=%u family=%s proto=%s port=%u\n",
					current->uid, family == PF_INET ? "INET" : "INET6",
					protocol == IPPROTO_TCP ? "TCP" : "UDP", snum);
			mutex_unlock(&portac_acl);
			return -EACCES;
		} else if (PORTAC_FLAG(entry, PORTAC_LOG)) {
			dprintk(" : LOG\n");
			log = 1;
		} else {
			dprintk(" : ALLOW\n");
			dprintk("}\n");
			if (log)
				printk("portac: ALLOW uid=%u family=%s proto=%s port=%u\n",
					current->uid, family == PF_INET ? "INET" : "INET6",
					protocol == IPPROTO_TCP ? "TCP" : "UDP", snum);
			mutex_unlock(&portac_acl);
			return 0;
		}
	}

	if (get_require_cap_net_bind_service(snum)) {
		if (!capable(CAP_NET_BIND_SERVICE)) {
			dprintk(" : DENY\n");
			dprintk("}\n");
			if (log)
				printk("portac: DENY uid=%u family=%s proto=%s port=%u\n",
					current->uid, family == PF_INET ? "INET" : "INET6",
					protocol == IPPROTO_TCP ? "TCP" : "UDP", snum);
			mutex_unlock(&portac_acl);
			return -EACCES;
		} else {
			dprintk(" : ALLOW\n");
			dprintk("}\n");
			if (log)
				printk("portac: ALLOW uid=%u family=%s proto=%s port=%u\n",
					current->uid, family == PF_INET ? "INET" : "INET6",
					protocol == IPPROTO_TCP ? "TCP" : "UDP", snum);
		}
	} else {
		dprintk(" (default)\n");
		dprintk(" : ALLOW\n");
		dprintk("}\n");
		if (log)
			printk("portac: ALLOW uid=%u family=%s proto=%s port=%u\n",
				current->uid, family == PF_INET ? "INET" : "INET6",
				protocol == IPPROTO_TCP ? "TCP" : "UDP", snum);
	}
	mutex_unlock(&portac_acl);
	return 0;
}

int portac_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
{
	int ret = 0; /* only used in secondary case so the mutex can be unlocked */
	u16 snum = 0;

	switch (address->sa_family) {
#ifdef CONFIG_INET
	case PF_INET: {
			struct sockaddr_in *addr = (struct sockaddr_in *)address;
			snum = ntohs(addr->sin_port);
			break;
		}
	case PF_INET6: {
			struct sockaddr_in6 *addr = (struct sockaddr_in6 *)address;
			snum = ntohs(addr->sin6_port);
			break;
		}
#endif
	default:
		goto secondary;
	}
	
	if (snum) {
		ret = portac_check(snum, sock->sk->sk_family, sock->sk->sk_protocol);
		if (ret)
			return ret;
	}

secondary:
	/* If there is a secondary module,
	 * run its socket_bind function.
	 */
	if (secondary_call_bind) {
		mutex_lock(&secondary_mod);
		if (secondary_ops != NULL
				&& secondary_ops->socket_bind != NULL) {

			dprintk("(call) socket_bind {\n");
			ret = secondary_ops->socket_bind(sock, address, addrlen);
			dprintk(" : %s\n", ret == 0 ? "ALLOW" : "DENY");
			dprintk("}\n");
		}
		mutex_unlock(&secondary_mod);
	}
	return ret;
}

int portac_socket_listen(struct socket *sock, int backlog)
{
	int ret = 0; /* only used in secondary case so the mutex can be unlocked */
	u16 snum = -1;

	switch (sock->sk->sk_family) {
#ifdef CONFIG_INET
	case PF_INET:
	case PF_INET6: {
			struct inet_sock *inet = inet_sk(sock->sk);
			snum = inet->sport;
			break;
		}
#endif
	default:
		goto secondary;
	}
	
	if (!snum) { /* port 0 */
		ret = portac_check(snum, sock->sk->sk_family, sock->sk->sk_protocol);
		if (ret)
			return ret;
	}

secondary:
	/* If there is a secondary module,
	 * run its socket_bind function.
	 */
	if (secondary_call_listen) {
		mutex_lock(&secondary_mod);
		if (secondary_ops != NULL
				&& secondary_ops->socket_listen != NULL) {

			dprintk("(call) socket_listen {\n");
			ret = secondary_ops->socket_listen(sock, backlog);
			dprintk(" : %s\n", ret == 0 ? "ALLOW" : "DENY");
			dprintk("}\n");
		}
		mutex_unlock(&secondary_mod);
	}
	return ret;
}

int portac_register_security(const char *name, struct security_operations *ops)
{
	struct security_operations tmp;

	if (ops == NULL)
		return -EINVAL;

	if (!secondary_allow)
		return -EACCES;

	mutex_lock(&secondary_mod);
	if (secondary_ops != NULL) {
		mutex_unlock(&secondary_mod);
		return -EPERM;
	}
	if (!try_module_get(THIS_MODULE)) {
		mutex_unlock(&secondary_mod);
		return -EAGAIN;
	}

	/* Copy our current ops because they have
	 * been fixed with dummy functions.
	 *
	 * Keep a reference to the secondary ops
	 * for later use.
	 */
	primary_ops = portac_ops;
	secondary_ops = ops;

	/* Copy the secondary ops, override the
	 * functions we use and call security_fixup_ops
	 * to add missing dummy functions.
	 *
	 * Replace our current ops with these ops.
	 */
	tmp = *ops;
	tmp.socket_bind = portac_socket_bind;
	tmp.socket_listen = portac_socket_listen;
	tmp.unregister_security = portac_unregister_security;
	security_fixup_ops(&tmp); /* from security/dummy.c */
	portac_ops = tmp;
	mutex_unlock(&secondary_mod);

	return 0;
}

int portac_unregister_security(const char *name, struct security_operations *ops)
{
	if (ops == NULL)
		return -EINVAL;

	if (!secondary_allow)
		return -EACCES;

	mutex_lock(&secondary_mod);
	if (ops != secondary_ops) {
		/* The ops being unloaded are not the
		 * same as the secondary ops, so the
		 * secondary module must have loaded
		 * a secondary of its own, or some other
		 * module is doing something stupid.
		 *
		 * If there is a secondary module,
		 * run its unregister_security function.
		 */
		int ret = -EINVAL;
		if (secondary_ops != NULL
				&& secondary_ops->unregister_security != NULL)
			ret = secondary_ops->unregister_security(name, ops);
		mutex_unlock(&secondary_mod);
		return ret;
	}

	/* Copy our previous ops back. */
	portac_ops = primary_ops;
	secondary_ops = NULL;
	mutex_unlock(&secondary_mod);

	module_put(THIS_MODULE);
	return 0;
}

int portac_proc_open(struct inode *inode, struct file *file) {
	struct portac_proc_file *portac_file;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (mutex_lock_interruptible(&portac_config))
		return -ERESTARTSYS;

	if (in_config) {
		mutex_unlock(&portac_config);
		return -EBUSY;
	}

	portac_file = kzalloc(sizeof(struct portac_proc_file), GFP_KERNEL);
	if (portac_file == NULL) {
		mutex_unlock(&portac_config);
		return -ENOMEM;
	}

	portac_file->size = 0;
	portac_file->data = NULL;
	file->private_data = portac_file;
		
	in_config = 1;		
	mutex_unlock(&portac_config);
	return 0;
}

int portac_proc_write(struct file *file, const char __user *data, size_t size, loff_t *offset) {
	struct portac_proc_file *portac_file = file->private_data;
	char *tmp = portac_file->data;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (mutex_lock_interruptible(&portac_config))
		return -ERESTARTSYS;

	BUG_ON(!in_config);

	if (portac_file->size + size > (4 + sizeof(default_action) + 13 * (PORTAC_MAX_RULES+1))) {
		portac_file->size = 0;
		if (portac_file->data != NULL) {
			kfree(portac_file->data);
			portac_file->data = NULL;
		}
		mutex_unlock(&portac_config);
		return -ENOMEM;
	}

	portac_file->data = kzalloc(portac_file->size + size, GFP_KERNEL);
	if (portac_file->data == NULL) {
		if (tmp != NULL)
			kfree(tmp);
		portac_file->size = 0;
		return -ENOMEM;
	}

	if (tmp != NULL) {
		memcpy(portac_file->data, tmp, portac_file->size);
		kfree(tmp);
	}
	portac_file->size += size;

	memcpy(&portac_file->data[*offset], data, size);
	*offset += size;

	mutex_unlock(&portac_config);
	return size;
}

int portac_proc_commit(struct inode *inode, struct file *file) {
	struct portac_proc_file *portac_file = file->private_data;
	int ret = -EPERM;

	if (mutex_lock_interruptible(&portac_config))
		return -ERESTARTSYS;

	BUG_ON(!in_config);

	if (capable(CAP_NET_ADMIN)) {
		unsigned int records = (portac_file->size - (4 + sizeof(default_action))) / 13;
		u16 count;
		ret = 0;
	
		if (portac_file->size < 4
				|| portac_file->data[0] != 0
				|| portac_file->data[1] != PORTAC_IFVER
				|| portac_file->size < 4 + sizeof(default_action)) {
			ret = -EINVAL;
			printk(KERN_INFO "portac: Invalid ACL format\n");
		}

		if ((portac_file->size - (4 + sizeof(default_action))) % 13 != 0) {
			ret = -EINVAL;
			printk(KERN_INFO "portac: ACL does not contain whole records\n");
		}

		if (!ret) {
			memcpy(&count, &portac_file->data[2], sizeof(u16));
			count = ntohs(count);
			if (count != records) {
				ret = -EINVAL;
				printk(KERN_INFO "portac: ACL header record count mismatch %u != %u\n", count, records);
			}
		}
		
		if (!ret) {
			struct portac_entry *entries = NULL;
			struct portac_entry *last = NULL;
			struct portac_entry *tmp;
			size_t pos = 4 + sizeof(default_action);

			mutex_lock(&portac_acl);
			printk(KERN_INFO "portac: Reloading ACL (%u records)\n", records);

			while (records > 0) {
				u16 sp, ep;
				u32 uid, grp;

				tmp = kzalloc(sizeof(struct portac_entry), GFP_KERNEL);
				if (tmp == NULL) {
					ret = -ENOMEM;
					printk(KERN_ALERT "portac: Failed to load new ACL\n");

					while (entries != NULL) {
						tmp = entries->next;
						kfree(entries);
						entries = tmp;
					}

					goto failed;
				}

				memcpy(&sp, &portac_file->data[pos], sizeof(u16));
				memcpy(&ep, &portac_file->data[pos+2], sizeof(u16));
				memcpy(&tmp->flags, &portac_file->data[pos+4], sizeof(u8));
				memcpy(&uid, &portac_file->data[pos+5], sizeof(u32));
				memcpy(&grp, &portac_file->data[pos+9], sizeof(u32));
				tmp->sport = ntohs(sp);
				tmp->eport = ntohs(ep);
				tmp->uid = ntohl(uid);
				tmp->grp = ntohl(grp);
				tmp->next = NULL;
				dprintk("add: sport=%u eport=%u flags=%08x uid=%u grp=%u\n",
					tmp->sport, tmp->eport, tmp->flags, tmp->uid, tmp->grp);

				if (last != NULL)
					last->next = tmp;
				else
					entries = tmp;
				last = tmp;

				pos += 13;
				records--;
			}

			while (portac_entries != NULL) {
				tmp = portac_entries->next;
				kfree(portac_entries);
				portac_entries = tmp;
			}
			portac_entries = entries;
			
			memcpy(default_action, &portac_file->data[2], sizeof(default_action));
			printk(KERN_INFO "portac: Reload complete\n");
failed:
			mutex_unlock(&portac_acl);
		}
	}
	
	if (portac_file->data != NULL)
		kfree(portac_file->data);
	kfree(portac_file);
	file->private_data = NULL;

	in_config = 0;
	mutex_unlock(&portac_config);	
	return ret;
}

static int __init portac_init_module(void)
{
	struct proc_dir_entry *proc_file;

	/* clear arrays */
	memset(default_action, 0, sizeof(default_action));

	/* initialise default_action based on default_deny_ports */
	if (default_deny_ports < 0 || default_deny_ports > 65535) {
		printk(KERN_INFO "portac: default_deny_ports must be 0-65535\n");
		return -EINVAL;
	} else if (default_deny_ports > 0) {
		default_deny_ports++;
		memset(default_action, ~0, sizeof(default_action[0]) * (default_deny_ports >> 5));
		if (default_deny_ports & 0x1F)
			default_action[default_deny_ports >> 5] = default_deny_ports & 0x1F;
		default_deny_ports--;
	}

	set_require_cap_net_bind_service(0, default_deny_listen);

	proc_file = create_proc_entry(KBUILD_MODNAME, S_IWUSR, proc_net);
	if (proc_file == NULL) {
		printk(KERN_INFO "Failure creating /proc/%s.\n", KBUILD_MODNAME);
		return -ENOMEM;
	}
	proc_file->proc_fops = &portac_proc_fops;
	
	/* register ourselves with the security framework */
	if (register_security(&portac_ops)) {
		/* try registering with primary module */
		if (mod_reg_security(KBUILD_MODNAME, &portac_ops)) {
			printk(KERN_INFO "Failure registering portac "
					"with primary security module.\n");
			return -EINVAL;
		}
		secondary = 1;
	}

	printk(KERN_INFO "TCP/UDP port access control v"
			PORTAC_VER " LSM initialised%s\n",
			secondary ? " as secondary" : "");
	return 0;
}

static void __exit portac_exit_module(void)
{
	/* If rmmod --force is used, secondary_ops
	 * is probably not NULL, but this won't matter.
	 */

	remove_proc_entry(KBUILD_MODNAME, proc_net);
	
	/* remove ourselves from the security framework */
	if (secondary) {
		if (mod_unreg_security(KBUILD_MODNAME, &portac_ops))
			printk(KERN_INFO "Failure unregistering portac "
					"with primary module.\n");
		return;
	}

	if (unregister_security(&portac_ops)) {
		printk(KERN_INFO
			"Failure unregistering portac with the kernel\n");
	}
}

security_initcall(portac_init_module);
module_exit(portac_exit_module);

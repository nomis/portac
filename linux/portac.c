#include <linux/capability.h>
#include <linux/module.h>
#include <linux/security.h>
#include <../security/dummy.c>

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/rwsem.h>
#include <linux/socket.h>

#include <net/inet_sock.h>
#include <net/netlink.h>
#include <net/genetlink.h>

#include "portac.h"

#define PORTAC_VER "2.0"

#define PORTAC_DEBUG 1
#if PORTAC_DEBUG
# define dprintk(x, args...) do { \
	printk(KERN_DEBUG "portac: " x , ## args); } while(0)
#else
# define dprintk(x, args...)
#endif

MODULE_DESCRIPTION("TCP/UDP port access control");
MODULE_AUTHOR("Simon Arlott <portac@fire.lp0.eu>");
MODULE_LICENSE("GPL");
MODULE_VERSION(PORTAC_VER);

static int default_action = PORTAC_REQUIRE_CAP;
module_param(default_action, int, 0);
MODULE_PARM_DESC(default_action,
	"Default action, 0:ALLOW 1:DENY 2:REQUIRE_CAP 3:LOG (default: 2)");

static int default_flags;
module_param(default_flags, int, 0);
MODULE_PARM_DESC(default_flags, "Default flags, 0:NONE 1:LOG (default: 0)");

static int secondary_allow = 1;
module_param(secondary_allow, bool, 0);
MODULE_PARM_DESC(secondary_allow,
	"Allow a secondary module to be loaded (default: true)");

static int secondary_call_bind;
module_param(secondary_call_bind, bool, 0);
MODULE_PARM_DESC(secondary_call_bind,
	"Call secondary module for socket_bind if result is ALLOW"\
	" (default: false)");

static int secondary_call_listen = 1;
module_param(secondary_call_listen, bool, 0);
MODULE_PARM_DESC(secondary_call_listen,
	"Call secondary module for socket_listen if result is ALLOW"\
	" (default: true)");

static int portac_socket_bind(struct socket *sock, struct sockaddr *sa, int len);
static int portac_socket_listen(struct socket *sock, int backlog);
static int portac_register_security(const char *name, struct security_operations *ops);
static int portac_unregister_security(const char *name, struct security_operations *ops);

static struct security_operations portac_ops = {
	/* Why do security/capabilities and security/root_plug
	 * use these to load themselves but don't implement them
	 * to let other modules do the same?
	 */
	.register_security = portac_register_security,
	.unregister_security = portac_unregister_security,

	.socket_bind = portac_socket_bind,
	.socket_listen = portac_socket_listen
};

static int portac_nl_modify(struct sk_buff *skb, struct genl_info *info);
static int portac_nl_replace(struct sk_buff *skb, struct genl_info *info);
static int portac_nl_list(struct sk_buff *skb, struct netlink_callback *cb);
static int portac_nl_get_default(struct sk_buff *skb, struct netlink_callback *cb);
static int portac_nl_set_default(struct sk_buff *skb, struct genl_info *info);

static struct genl_family portac_nl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = "portac",
	.version = PORTAC_NL_VERSION
};

static const __read_mostly
struct nla_policy portac_nl_attr_policy[PORTAC_NL_A_MAX + 1] = {
	[PORTAC_NL_A_LIST] = { .type = NLA_NESTED }
};

static const __read_mostly
struct nla_policy portac_nl_list_policy[PORTAC_NL_L_MAX + 1] = {
	[PORTAC_NL_L_OP] = { .type = NLA_U8 },
	[PORTAC_NL_L_RULE] = { .type = NLA_NESTED }
};

static const __read_mostly
struct nla_policy portac_nl_rule_policy[PORTAC_NL_R_MAX + 1] = {
	[PORTAC_NL_R_ACTION] = { .type = NLA_U16 },
	[PORTAC_NL_R_MATCH] = { .type = NLA_U32 },
	[PORTAC_NL_R_FLAGS] = { .type = NLA_U32 },
	[PORTAC_NL_R_DATA_SPORT] = { .type = NLA_U16 },
	[PORTAC_NL_R_DATA_EPORT] = { .type = NLA_U16 },
	[PORTAC_NL_R_DATA_UID] = { .type = NLA_U64 },
	[PORTAC_NL_R_DATA_GRP] = { .type = NLA_U64 },
	[PORTAC_NL_R_DATA_IP4] = {
		.type = NLA_UNSPEC, .len = sizeof(struct in_addr) },
	[PORTAC_NL_R_DATA_IP6] = {
		.type = NLA_UNSPEC, .len = sizeof(struct in6_addr) }
};

static const __read_mostly
struct nla_policy portac_nl_default_policy[PORTAC_NL_D_MAX + 1] = {
	[PORTAC_NL_D_ACTION] = { .type = NLA_U16 },
	[PORTAC_NL_D_FLAGS] = { .type = NLA_U32 }
};

static struct genl_ops portac_nl_ops[] = {
	{
		.cmd = PORTAC_NL_C_MODIFY,
		.flags = 0/*|GENL_ADMIN_PERM*/,
		.policy = portac_nl_attr_policy,
		.doit = portac_nl_modify
	},
	{
		.cmd = PORTAC_NL_C_REPLACE,
		.flags = 0/*|GENL_ADMIN_PERM*/,
		.policy = portac_nl_attr_policy,
		.doit = portac_nl_replace
	},
	{
		.cmd = PORTAC_NL_C_LIST,
		.flags = 0/*|GENL_ADMIN_PERM*/,
		.policy = portac_nl_attr_policy,
		.dumpit = portac_nl_list
	},
	{
		.cmd = PORTAC_NL_C_DEFAULT,
		.flags = 0/*|GENL_ADMIN_PERM*/,
		.policy = portac_nl_default_policy,
		.doit = portac_nl_set_default,
		.dumpit = portac_nl_get_default
	}
};

static DECLARE_RWSEM(portac_acl);
static DEFINE_MUTEX(secondary_mod);
static int secondary;
static struct security_operations primary_ops;
static struct security_operations *secondary_ops;
static struct portac_entry *portac_entries_head;
static struct portac_entry *portac_entries_tail;

static
void portac_log(const char *event, u16 snum, void *host,
	unsigned short family, unsigned char protocol)
{
	if (!printk_ratelimit())
		return;

	if (family == PF_INET) {
		struct in_addr *host4 = host;
		printk(KERN_INFO "portac: %s pid=%u uid=%u euid=%u"
			" host=%d.%d.%d.%d port=%u family=INET protocol=%s\n",
			event, current->pid, current->uid, current->euid,
			(host4->s_addr & 0xFF000000) >> 24,
			(host4->s_addr & 0x00FF0000) >> 16,
			(host4->s_addr & 0x0000FF00) >> 8,
			(host4->s_addr & 0x000000FF), snum,
			protocol == IPPROTO_TCP ? "TCP"
			: protocol == IPPROTO_UDP ? "UDP" : "UDPLITE");
	} else {
		struct in6_addr *host6 = host;
		printk(KERN_INFO "portac: %s pid=%u uid=%u euid=%u host="
			"%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
			"%02x%02x:%02x%02x:%02x%02x:%02x%02x"
			" port=%u family=INET6 protocol=%s\n",
			event, current->pid, current->uid, current->euid,
			host6->s6_addr[0], host6->s6_addr[1],
			host6->s6_addr[2], host6->s6_addr[3],
			host6->s6_addr[4], host6->s6_addr[5],
			host6->s6_addr[6], host6->s6_addr[7],
			host6->s6_addr[8], host6->s6_addr[9],
			host6->s6_addr[10], host6->s6_addr[11],
			host6->s6_addr[12], host6->s6_addr[13],
			host6->s6_addr[14], host6->s6_addr[15],
			snum, protocol == IPPROTO_TCP ? "TCP"
			: protocol == IPPROTO_UDP ? "UDP" : "UDPLITE");
	}
}

static
int portac_check(u16 snum, void *host, unsigned short family,
	unsigned char proto)
{
	struct portac_entry *tmp;
	int log = 0;

	down_read(&portac_acl);
	tmp = portac_entries_head;
	if (family == PF_INET) {
		struct in_addr *host4 = host;
		dprintk("(check) pid=%u uid=%u euid=%u host=%d.%d.%d.%d"
			" port=%u family=%u protocol=%u {\n",
			current->pid, current->uid, current->euid,
			(host4->s_addr & 0xFF000000) >> 24,
			(host4->s_addr & 0x00FF0000) >> 16,
			(host4->s_addr & 0x0000FF00) >> 8,
			(host4->s_addr & 0x000000FF),
			snum, family, proto);
	} else {
		struct in6_addr *host6 = host;
		dprintk("(check) pid=%u uid=%u euid=%u host=%02x%02x:%02x%02x:"
			"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
			"%02x%02x port=%u family=%u protocol=%u {\n",
			current->pid, current->uid, current->euid,
			host6->s6_addr[0], host6->s6_addr[1],
			host6->s6_addr[2], host6->s6_addr[3],
			host6->s6_addr[4], host6->s6_addr[5],
			host6->s6_addr[6], host6->s6_addr[7],
			host6->s6_addr[8], host6->s6_addr[9],
			host6->s6_addr[10], host6->s6_addr[11],
			host6->s6_addr[12], host6->s6_addr[13],
			host6->s6_addr[14], host6->s6_addr[15],
			snum, family, proto);
	}

	while (tmp) {
		struct portac_entry *entry = tmp;
		tmp = tmp->next;

		dprintk(" : match=%#x flags=%#x"
			" uid=%u grp=%u sport=%u eport=%u\n",
			entry->match, entry->flags,
			entry->uid, entry->grp,
			entry->sport, entry->eport);

		if (PORTAC_MATCH_ISSET(entry, PORTAC_MATCH_UID)
				&& current->uid != entry->uid
				&& current->euid != entry->uid) {
			dprintk(" > uid does not match\n");
			continue;
		}

		if (PORTAC_MATCH_ISSET(entry, PORTAC_MATCH_GRP)
				&& !in_egroup_p(entry->grp)) {
			dprintk(" > grp does not match\n");
			continue;
		}

		if (!(PORTAC_MATCH_ISSET(entry, PORTAC_MATCH_IP4)
				&& family == PF_INET)
			&& !(PORTAC_MATCH_ISSET(entry, PORTAC_MATCH_IP6)
				&& family == PF_INET6)) {
			dprintk(" > family does not match\n");
			continue;
		}

		if (!(PORTAC_MATCH_ISSET(entry, PORTAC_MATCH_TCP)
				&& proto == IPPROTO_TCP)
			&& !(PORTAC_MATCH_ISSET(entry, PORTAC_MATCH_UDP)
				&& proto == IPPROTO_UDP)
			&& !(PORTAC_MATCH_ISSET(entry, PORTAC_MATCH_UDP)
				&& proto == IPPROTO_UDPLITE)) {
			dprintk(" > protocol does not match\n");
			continue;
		}

		if (snum < entry->sport || snum > entry->eport) {
			dprintk(" > port does not match\n");
			continue;
		}

		if (entry->host && host) {
			struct in_addr *host4 = host;
			struct in6_addr *host6 = host;
			switch (family) {
			case PF_INET:
				if (entry->ip4->s_addr != host4->s_addr) {
					dprintk(" > host does not match\n");
					continue;
				}
				break;
			case PF_INET6:
				if (entry->ip6->s6_addr32[0] != host6->s6_addr32[0]
						&& entry->ip6->s6_addr32[1] != host6->s6_addr32[1]
						&& entry->ip6->s6_addr32[2] != host6->s6_addr32[2]
						&& entry->ip6->s6_addr32[3] != host6->s6_addr32[3]) {
					dprintk(" > host does not match\n");
					continue;
				}
				break;
			default:
				dprintk(" > host does not match\n");
				continue;
			}
		}

		/* this rule matches, so enable logging if set */
		if (PORTAC_FLAG_ISSET(entry, PORTAC_FLAG_LOG))
			log = 1;

		switch (entry->action) {
		case PORTAC_ALLOW:
			dprintk(" > ALLOW\n");
			dprintk("}\n");
			if (log)
				portac_log("ALLOW", snum, host, family, proto);
			up_read(&portac_acl);
			return 0;
		case PORTAC_DENY:
			dprintk(" > DENY\n");
			dprintk("}\n");
			if (log)
				portac_log("DENY", snum, host, family, proto);
			up_read(&portac_acl);
			return -EACCES;
		case PORTAC_LOG:
			dprintk(" > LOG\n");
			log = 1;
			break;
		case PORTAC_REQUIRE_CAP:
		default:
			if (!capable(CAP_NET_BIND_SERVICE)) {
				dprintk(" > CAP,DENY\n");
				dprintk("}\n");
				if (log)
					portac_log("DENY", snum, host,
						family, proto);
				up_read(&portac_acl);
				return -EACCES;
			} else {
				dprintk(" > CAP,ALLOW\n");
				dprintk("}\n");
				if (log)
					portac_log("ALLOW", snum, host,
						family, proto);
			}
			break;
		}
	}

	dprintk(" (default)\n");
	switch (default_action) {
	case PORTAC_ALLOW:
		dprintk(" > ALLOW\n");
		dprintk("}\n");
		if (log || (default_flags & PORTAC_FLAG_LOG))
			portac_log("ALLOW", snum, host, family, proto);
		break;
	case PORTAC_DENY:
		dprintk(" > DENY\n");
		dprintk("}\n");
		if (log || (default_flags & PORTAC_FLAG_LOG))
			portac_log("DENY", snum, host, family, proto);
		up_read(&portac_acl);
		return -EACCES;
	case PORTAC_LOG:
		log = 1;
	case PORTAC_REQUIRE_CAP:
	default:
		if (snum > 0 && snum < PROT_SOCK
				&& !capable(CAP_NET_BIND_SERVICE)) {
			dprintk(" > CAP,DENY\n");
			dprintk("}\n");
			if (log || (default_flags & PORTAC_FLAG_LOG))
				portac_log("DENY", snum, host, family, proto);
			up_read(&portac_acl);
			return -EACCES;
		} else {
			dprintk(" > CAP,ALLOW\n");
			dprintk("}\n");
			if (log || (default_flags & PORTAC_FLAG_LOG))
				portac_log("ALLOW", snum, host, family, proto);
		}
	}
	up_read(&portac_acl);
	return 0;
}

static
int portac_match(const struct portac_entry *a, const struct portac_entry *b)
{
	/* two rules are not identical if any of the following are inequal */
	if (a->action != b->action
			|| a->match != b->match
			|| a->flags != b->flags
			|| a->sport != b->sport
			|| a->eport != b->eport
			|| a->uid != b->uid
			|| a->grp != b->grp)
		return 0;

	/* two rules which have no host restriction are equal */
	if (!a->host && !b->host)
		return 1;

	/* two rules which don't both have a host restriction are inequal */
	if (!(a->host && b->host))
		return 0;

	/* two rules with the same host restriction are equal */
	if (PORTAC_MATCH_ISSET(a, PORTAC_MATCH_IP4)) {
		return !memcmp(a->ip4, b->ip4, sizeof(*a->ip4));
	} else if (PORTAC_MATCH_ISSET(a, PORTAC_MATCH_IP6)) {
		return !memcmp(a->ip6, b->ip6, sizeof(*a->ip6));
	}

	BUG();
}

static
struct portac_entry *portac_create(struct nlattr *rule[], int pos)
{
	struct portac_entry *entry = kzalloc(sizeof(struct portac_entry),
							GFP_KERNEL);
	int ret;

	if (!entry)
		return ERR_PTR(-ENOMEM);

	if (rule[PORTAC_NL_R_ACTION]) {
		u16 action = nla_get_u16(rule[PORTAC_NL_R_ACTION]);

		switch (action) {
		case PORTAC_ALLOW:
		case PORTAC_DENY:
		case PORTAC_LOG:
		case PORTAC_REQUIRE_CAP:
			entry->action = action;
			break;
		default:
			if (pos >= 0)
				printk(KERN_DEBUG "portac: invalid action %#x"
						" for rule %u\n", action, pos);
			ret = -EINVAL;
			goto failure;
		}
	} else {
		if (pos >= 0)
			printk(KERN_DEBUG "portac: missing action"
					" for rule %u\n", pos);
		ret = -EINVAL;
		goto failure;
	}

	if (rule[PORTAC_NL_R_MATCH]) {
		u32 match = nla_get_u32(rule[PORTAC_NL_R_MATCH]);

		if ((match & PORTAC_MATCH_INVALID) != 0
			|| (match & (PORTAC_MATCH_TCP|PORTAC_MATCH_UDP)) == 0
			|| (match & (PORTAC_MATCH_IP4|PORTAC_MATCH_IP6)) == 0) {

			if (pos >= 0)
				printk(KERN_DEBUG "portac: invalid match"
					" attr %#x for rule %u\n", match, pos);
			ret = -EINVAL;
			goto failure;
		}

		entry->match = match;
	} else {
		if (pos >= 0)
			printk(KERN_DEBUG "portac: missing match attr"
					" for rule %u\n", pos);
		ret = -EINVAL;
		goto failure;
	}

	if (rule[PORTAC_NL_R_FLAGS]) {
		u32 flags = nla_get_u32(rule[PORTAC_NL_R_FLAGS]);

		if ((flags & PORTAC_FLAG_INVALID) != 0) {
			if (pos >= 0)
				printk(KERN_DEBUG "portac: invalid flags %#x"
					" for rule %u\n", flags, pos);
			ret = -EINVAL;
			goto failure;
		}

		entry->flags = flags;
	} else {
		if (pos >= 0)
			printk(KERN_DEBUG "portac: missing flags attr"
					" for rule %u\n", pos);
		ret = -EINVAL;
		goto failure;
	}

	if (rule[PORTAC_NL_R_DATA_SPORT]) {
		entry->sport = nla_get_u16(rule[PORTAC_NL_R_DATA_SPORT]);
	} else {
		if (pos >= 0)
			printk(KERN_DEBUG "portac: missing start port"
					" for rule %u\n", pos);
		ret = -EINVAL;
		goto failure;
	}

	if (rule[PORTAC_NL_R_DATA_EPORT]) {
		entry->eport = nla_get_u16(rule[PORTAC_NL_R_DATA_EPORT]);
	} else {
		if (pos >= 0)
			printk(KERN_DEBUG "portac: missing end port"
					" for rule %u\n", pos);
		ret = -EINVAL;
		goto failure;
	}

	if (PORTAC_MATCH_ISSET(entry, PORTAC_MATCH_UID)) {
		if (rule[PORTAC_NL_R_DATA_UID]) {
			u64 uid = nla_get_u64(rule[PORTAC_NL_R_DATA_UID]);
#ifdef CONFIG_UID16
			if (uid > 0xFFFF) {
#else
			if (uid > 0xFFFFFFFF) {
#endif
				if (pos >= 0)
					printk(KERN_DEBUG "portac: invalid uid"
						" value for rule %u\n", pos);
				ret = -EINVAL;
				goto failure;
			}

			entry->uid = uid;
		} else {
			if (pos >= 0)
				printk(KERN_DEBUG "portac: missing uid value"
						" for rule %u\n", pos);
			ret = -EINVAL;
			goto failure;
		}
	} else if (rule[PORTAC_NL_R_DATA_UID]) {
		if (pos >= 0)
			printk(KERN_DEBUG "portac: uid value set"
				" but uid matching not enabled"
				" for rule %u\n", pos);
		ret = -EINVAL;
		goto failure;
	}

	if (PORTAC_MATCH_ISSET(entry, PORTAC_MATCH_GRP)) {
		if (rule[PORTAC_NL_R_DATA_GRP]) {
			u64 gid = nla_get_u64(rule[PORTAC_NL_R_DATA_GRP]);
#ifdef CONFIG_UID16
			if (gid > 0xFFFF) {
#else
			if (gid > 0xFFFFFFFF) {
#endif
				if (pos >= 0)
					printk(KERN_DEBUG "portac:"
						" invalid group value"
						" for rule %u\n", pos);
				ret = -EINVAL;
				goto failure;
			}

			entry->grp = gid;
		} else {
			if (pos >= 0)
				printk(KERN_DEBUG "portac: missing group value"
						" for rule %u\n", pos);
			ret = -EINVAL;
			goto failure;
		}
	} else if (rule[PORTAC_NL_R_DATA_GRP]) {
		if (pos >= 0)
			printk(KERN_DEBUG "portac: group value set"
					" but group matching not enabled"
					" for rule %u\n", pos);
		ret = -EINVAL;
		goto failure;
	}

	if (rule[PORTAC_NL_R_DATA_IP4]) {
		if (PORTAC_MATCH_ISSET(entry, PORTAC_MATCH_IP4)
			&& !PORTAC_MATCH_ISSET(entry, PORTAC_MATCH_IP6)) {

			struct in_addr *host = kmalloc(sizeof(struct in_addr),
								GFP_KERNEL);
			if (!host) {
				ret = -ENOMEM;
				goto failure;
			}
			nla_memcpy(host, rule[PORTAC_NL_R_DATA_IP4],
				sizeof(struct in_addr));
			entry->ip4 = host;
		} else if (rule[PORTAC_NL_R_DATA_IP4]) {
			if (pos >= 0)
				printk(KERN_DEBUG "portac: IPv4 host set"
					" but matching not set to IPv4 only"
					" for rule %u\n", pos);
			ret = -EINVAL;
			goto failure;
		}
	}

	if (rule[PORTAC_NL_R_DATA_IP6]) {
		if (PORTAC_MATCH_ISSET(entry, PORTAC_MATCH_IP6)
			&& !PORTAC_MATCH_ISSET(entry, PORTAC_MATCH_IP4)) {

			struct in6_addr *host = kmalloc(sizeof(struct in6_addr),
								GFP_KERNEL);
			if (!host) {
				ret = -ENOMEM;
				goto failure;
			}
			nla_memcpy(host, rule[PORTAC_NL_R_DATA_IP6],
				sizeof(struct in_addr));
			entry->ip6 = host;
		} else if (rule[PORTAC_NL_R_DATA_IP6]) {
			if (pos >= 0)
				printk(KERN_DEBUG "portac: IPv6 host set"
					" but matching not set to IPv6 only"
					" for rule %u\n", pos);
			ret = -EINVAL;
			goto failure;
		}
	}

	return entry;

failure:
	kfree(entry->host);
	kfree(entry);
	return ERR_PTR(ret);
}

static inline
void portac_list_del(struct portac_entry **head, struct portac_entry **tail,
	struct portac_entry *del, int *count_all, int *count_del)
{
	struct portac_entry *tmp = *head;
	struct portac_entry *prev = NULL;

	while (tmp) {
		while (del) {
			if (likely(!portac_match(tmp, del))) {
				del = del->next;
			} else {
				struct portac_entry *next = tmp->next;

				if (*head == tmp)
					*head = next;
				else
					prev->next = next;

				if (*tail == tmp)
					*tail = prev;

				kfree(tmp->host);
				kfree(tmp);

				tmp = next;
				if (count_del)
					(*count_del)++;
				goto deleted_current;
			}
		}

		prev = tmp;
		tmp = tmp->next;
		if (count_all)
			(*count_all)++;
deleted_current:;
	}
}

static
int portac_config(struct sk_buff *skb, struct genl_info *info, int replace)
{
	enum portac_op op = PORTAC_NONE;
	struct nlattr *nla;
	int ret = 0;
	unsigned int nla_rem, pos = 0;
	struct portac_entry *config_add_head = NULL;
	struct portac_entry *config_add_tail = NULL;
	struct portac_entry *config_del = NULL;
	int count_add = 0, count_del = 0, count_all = 0;

	if (!info->attrs
			|| !info->attrs[PORTAC_NL_A_LIST]
			|| nla_validate_nested(info->attrs[PORTAC_NL_A_LIST],
			PORTAC_NL_L_MAX, portac_nl_list_policy))
		return -EINVAL;

	nla_for_each_nested(nla, info->attrs[PORTAC_NL_A_LIST], nla_rem) {
		struct nlattr *rule[PORTAC_NL_R_MAX + 1];
		struct portac_entry *config_new;

		if (nla->nla_type == PORTAC_NL_L_OP) {
			op = nla_get_u8(nla);
			if (op <= PORTAC_NONE || op > PORTAC_OP_MAX) {
				printk(KERN_DEBUG "portac: invalid op %#x"
						" for rule %u\n", op, pos);
				goto finish;
			}
			continue;
		}

		if (nla_parse_nested(rule, PORTAC_NL_R_MAX,
				nla, portac_nl_rule_policy)) {
			ret = -EINVAL;
			goto finish;
		}

		config_new = portac_create(rule, pos);
		if (IS_ERR(config_new)) {
			if (PTR_ERR(config_new) != -EINVAL)
				ret = PTR_ERR(config_new);
			goto finish;
		}

		switch (op) {
		case PORTAC_ADD:
			if (config_add_tail) {
				config_add_tail->next = config_new;
				config_add_tail = config_new;
			} else {
				config_add_head = config_new;
				config_add_tail = config_new;
			}
			count_add++;
			break;
		case PORTAC_DEL:
			if (config_add_head) {
				int count_tmp = 0;
				portac_list_del(&config_add_head,
					&config_add_tail,
					config_new, NULL, &count_tmp);
				count_add -= count_tmp;
			}

			if (!replace) {
				config_new->next = config_del;
				config_del = config_new;
			} else {
				kfree(config_new->host);
				kfree(config_new);
			}
			break;
		default:
			printk(KERN_DEBUG "portac: invalid op %#x"
					" for rule %u\n", op, pos);
			kfree(config_new->host);
			kfree(config_new);
			goto finish;
		}

		pos++;
		if (pos < 0) {
			ret = -E2BIG;
			goto finish;
		}
	}

	down_write(&portac_acl);
	if (portac_entries_head == NULL)
		replace = 1;

	if (!replace)
		portac_list_del(&portac_entries_head, &portac_entries_tail,
			config_del, &count_all, &count_del);

	if (replace || !portac_entries_head) {
		while (portac_entries_head) {
			struct portac_entry *tmp = portac_entries_head->next;
			kfree(portac_entries_head->host);
			kfree(portac_entries_head);
			portac_entries_head = tmp;
		}
		portac_entries_head = config_add_head;
		portac_entries_tail = config_add_tail;
	} else {
		portac_entries_tail->next = config_add_head;
		if (config_add_tail)
			portac_entries_tail = config_add_tail;
	}

	downgrade_write(&portac_acl);
	if (replace) {
		printk(KERN_NOTICE "portac: Set ACL (%u rule%s)\n",
			count_add, count_add != 1 ? "s" : "");
	} else {
		printk(KERN_NOTICE "portac: Updated ACL (%u rule%s added,"
			" %u rule%s removed, %u rule%s total)\n",
			count_add, count_add != 1 ? "s" : "",
			count_del, count_del != 1 ? "s" : "",
			count_all, count_all != 1 ? "s" : "");
	}

	up_read(&portac_acl);
	config_add_head = NULL;

finish:
	config_add_tail = NULL;
	while (config_add_head) {
		struct portac_entry *tmp = config_add_head->next;
		kfree(config_add_head);
		config_add_head = tmp;
	}
	while (config_del) {
		struct portac_entry *tmp = config_del->next;
		kfree(config_del);
		config_del = tmp;
	}
	if (ret)
		return ret;
	else
		return pos;
}

static
int portac_socket_bind(struct socket *sock, struct sockaddr *sa, int len)
{
	int ret = 0;
	void *host;
	u16 snum = 0;

	switch (sa->sa_family) {
#ifdef CONFIG_INET
	case PF_INET: {
			struct sockaddr_in *addr = (struct sockaddr_in *)sa;
			host = &addr->sin_addr;
			snum = ntohs(addr->sin_port);
			break;
		}
	case PF_INET6: {
			struct sockaddr_in6 *addr = (struct sockaddr_in6 *)sa;
			host = &addr->sin6_addr;
			snum = ntohs(addr->sin6_port);
			break;
		}
#endif
	default:
		goto secondary;
	}

	if (snum) { /* not port 0 */
		ret = portac_check(snum, host,
			sock->sk->sk_family, sock->sk->sk_protocol);
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

			if (snum) {
				dprintk("(call) socket_bind {\n");
				ret = secondary_ops->socket_bind(sock, sa, len);
				dprintk(" > %s\n", ret == 0 ? "ALLOW" : "DENY");
				dprintk("}\n");
			}
		}
		mutex_unlock(&secondary_mod);
	}
	return ret;
}

static
int portac_socket_listen(struct socket *sock, int backlog)
{
	int ret = 0;
	void *host;
	u16 snum = -1;

	switch (sock->sk->sk_family) {
#ifdef CONFIG_INET
	case PF_INET: {
			struct inet_sock *inet = inet_sk(sock->sk);
			host = &inet->saddr;
			snum = inet->sport;
		}
		break;
	case PF_INET6: {
			struct inet_sock *inet = inet_sk(sock->sk);
			host = &inet->pinet6->saddr;
			snum = inet->sport;
		}
		break;
#endif
	default:
		goto secondary;
	}

	if (!snum) { /* port 0 */
		ret = portac_check(snum, host,
			sock->sk->sk_family, sock->sk->sk_protocol);
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

			if (!snum) {
				dprintk("(call) socket_listen {\n");
				ret = secondary_ops->socket_listen(sock,
								backlog);
				dprintk(" > %s\n", ret == 0 ? "ALLOW" : "DENY");
				dprintk("}\n");
			}
		}
		mutex_unlock(&secondary_mod);
	}
	return ret;
}

static
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

static
int portac_unregister_security(const char *name,
	struct security_operations *ops)
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

static
int portac_nl_modify(struct sk_buff *skb, struct genl_info *info)
{
	return portac_config(skb, info, 0);
}

static
int portac_nl_replace(struct sk_buff *skb, struct genl_info *info)
{
	return portac_config(skb, info, 1);
}

static
int portac_nl_list(struct sk_buff *skb, struct netlink_callback *cb)
{
	void *data;
	int ret;

	printk(KERN_DEBUG "portac_nl_list %lu\n", cb->args[0]);

	if (cb->args[0] > 10)
		return 0;

	data = genlmsg_put(skb, NETLINK_CB(skb).pid, cb->nlh->nlmsg_seq,
		&portac_nl_family, NLM_F_MULTI, PORTAC_NL_C_LIST);
	if (!data)
		return -ENODATA;

	down_read(&portac_acl);
	ret = nla_put_u32(skb, PORTAC_NL_D_ACTION, default_action);
	if (ret)
		goto failure;

	ret = nla_put_u32(skb, PORTAC_NL_D_ACTION, default_action);
	if (ret)
		goto failure;
	up_read(&portac_acl);

	cb->args[0]++;

	return genlmsg_end(skb, data);

failure:
	genlmsg_cancel(skb, data);
	return ret;

//	down_read(&portac_acl);
//	up_read(&portac_acl);
//	return -ENOSYS;
}

static
int portac_nl_get_default(struct sk_buff *skb, struct netlink_callback *cb)
{
	void *data;
	int ret;

	/* use arg 0 to indicate completion */
	if (cb->args[0])
		return 0;

	data = genlmsg_put(skb, NETLINK_CB(skb).pid, cb->nlh->nlmsg_seq,
		&portac_nl_family, NLM_F_ACK, PORTAC_NL_C_DEFAULT);
	if (!data)
		return -ENODATA;

	down_read(&portac_acl);
	ret = nla_put_u32(skb, PORTAC_NL_D_ACTION, default_action);
	if (ret)
		goto failure;

	ret = nla_put_u32(skb, PORTAC_NL_D_ACTION, default_action);
	if (ret)
		goto failure;
	up_read(&portac_acl);

	/* mark this dump as complete */
	cb->args[0] = 1;

	return genlmsg_end(skb, data);

failure:
	genlmsg_cancel(skb, data);
	return ret;
}

static
int portac_nl_set_default(struct sk_buff *skb, struct genl_info *info)
{
	u32 action, flags;
	if (!info->attrs
			|| !info->attrs[PORTAC_NL_D_ACTION]
			|| !info->attrs[PORTAC_NL_D_FLAGS])
		return -EINVAL;

	action = nla_get_u32(info->attrs[PORTAC_NL_D_ACTION]);
	switch (action) {
	case PORTAC_ALLOW:
	case PORTAC_DENY:
	case PORTAC_REQUIRE_CAP:
		break;
	default:
		printk(KERN_DEBUG "portac: invalid default action %#x\n",
								action);
		return -EINVAL;
	}

	flags = nla_get_u32(info->attrs[PORTAC_NL_D_FLAGS]);
	if ((flags & PORTAC_FLAG_INVALID) != 0) {
		printk(KERN_DEBUG "portac: invalid default flags %#x\n", flags);
		return -EINVAL;
	}

	down_write(&portac_acl);
	default_action = action;
	default_flags = flags;

	up_read(&portac_acl);
	return 0;
}

static __init
int portac_init_module(void)
{
	int ret, i;

	/* register ourselves with the security framework */
	ret = register_security(&portac_ops);
	if (ret == -EAGAIN) {
		/* try registering with primary module */
		ret = mod_reg_security(KBUILD_MODNAME, &portac_ops);
		if (ret) {
			printk(KERN_NOTICE "Failure registering portac"
					" with primary security module.\n");
			goto failure;
		}
		secondary = 1;
	} else if (ret) {
		printk(KERN_NOTICE "Failure registering portac"
				" with the kernel.\n");
	}

	portac_nl_family.maxattr = max(PORTAC_NL_A_MAX, PORTAC_NL_L_MAX);
	portac_nl_family.maxattr = max_t(int, portac_nl_family.maxattr,
							PORTAC_NL_R_MAX);
	portac_nl_family.maxattr = max_t(int, portac_nl_family.maxattr,
							PORTAC_NL_D_MAX);

	ret = genl_register_family(&portac_nl_family);
	if (ret) {
		printk(KERN_ERR "portac: genl_register_family: %d\n", ret);
		goto failure_family;
	}

	for (i = 0; i < ARRAY_SIZE(portac_nl_ops); i++) {
		ret = genl_register_ops(&portac_nl_family, &portac_nl_ops[i]);
		if (ret) {
			printk(KERN_ERR "portac: genl_register_ops[%d]: %d\n",
									i, ret);
			goto failure_ops;
		}
	}

	printk(KERN_INFO "TCP/UDP port access control v"
			PORTAC_VER " LSM initialised%s\n",
			secondary ? " as secondary" : "");
	return 0;

failure_ops:
	for (i--; i > 0; i--) {
		ret = genl_unregister_ops(&portac_nl_family, &portac_nl_ops[i]);
		if (ret != 0)
			printk(KERN_ERR "portac: genl_unregister_ops[%d]: %d\n",
									i, ret);
	}

	ret = genl_unregister_family(&portac_nl_family);
	if (ret)
		printk(KERN_ERR "genl_unregister_family: %d\n", ret);

failure_family:
	/* remove ourselves from the security framework */
	if (secondary) {
		if (mod_unreg_security(KBUILD_MODNAME, &portac_ops))
			printk(KERN_NOTICE "Failure unregistering portac"
					" from primary module.\n");
	} else if (unregister_security(&portac_ops)) {
		printk(KERN_NOTICE
			"Failure unregistering portac from the kernel\n");
	}

failure:
	return -EINVAL;
}

static __exit
void portac_exit_module(void)
{
	int ret, i;

	/* If rmmod --force is used, secondary_ops
	 * is probably not NULL, but this won't matter.
	 */

	/* remove ourselves from the security framework */
	if (secondary) {
		ret = mod_unreg_security(KBUILD_MODNAME, &portac_ops);
		if (ret)
			printk(KERN_NOTICE "Failure unregistering portac"
					" from primary module.\n");
	} else {
		ret = unregister_security(&portac_ops);
		if (ret)
			printk(KERN_NOTICE "Failure unregistering portac"
					" from the kernel\n");
	}

	for (i = 0; i < ARRAY_SIZE(portac_nl_ops); i++) {
		ret = genl_unregister_ops(&portac_nl_family, &portac_nl_ops[i]);
		if (ret != 0)
			printk(KERN_ERR "portac: genl_unregister_ops[%d]: %d\n",
									i, ret);
	}

	ret = genl_unregister_family(&portac_nl_family);
	if (ret != 0)
		printk(KERN_ERR "portac: genl_unregister_family: %d\n", ret);

	down_write(&portac_acl);
	portac_entries_tail = NULL;
	while (portac_entries_head != NULL) {
		struct portac_entry *tmp = portac_entries_head->next;
		kfree(portac_entries_head->host);
		kfree(portac_entries_head);
		portac_entries_head = tmp;
	}
	up_write(&portac_acl);
}

security_initcall(portac_init_module);
module_exit(portac_exit_module);

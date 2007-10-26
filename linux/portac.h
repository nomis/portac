#ifdef __KERNEL__
# include <linux/types.h>
#else
# include <stdint.h>
#endif

#define PORTAC_IFVER                   0x02

#define PORTAC_MATCH_TCP               0x01
#define PORTAC_MATCH_UDP               0x02
#define PORTAC_MATCH_IP4               0x04
#define PORTAC_MATCH_IP6               0x08
#define PORTAC_MATCH_UID               0x10
#define PORTAC_MATCH_GRP               0x20
#define PORTAC_MATCH_ANY_HOST          0x40

#define PORTAC_FLAG_LOG                0x01

enum portac_action {
	PORTAC_ALLOW = 0,
	PORTAC_DENY,
	PORTAC_LOG,
	PORTAC_KILL
};

#define PORTAC_MATCH_ISSET(entry, mask) ((entry)->match & (mask))
#define PORTAC_MATCH_SET(entry, mask)   do { (entry)->match |= (mask); } while(0)
#define PORTAC_MATCH_CLEAR(entry, mask) do { (entry)->match ^= (mask); } while(0)

#define PORTAC_FLAG_ISSET(entry, mask)   ((entry)->flags & (mask))
#define PORTAC_FLAG_SET(entry, mask)     do { (entry)->flags |= (mask); } while(0)
#define PORTAC_FLAG_CLEAR(entry, mask)   do { (entry)->flags ^= (mask); } while(0)

struct portac_entry {
	/* data */
	union host {
		struct sockaddr_in ip4;
		struct sockaddr_in6 ip6;
	};
	uid_t uid;
	gid_t grp;
	uint16_t sport;
	uint16_t eport;

	/* options */
	enum portac_action action;
	uint8_t match;
	uint8_t flags;
	struct portac_entry *next;
};

#ifdef __KERNEL__
struct portac_proc_file {
	size_t size;
	char *data;
};
#endif

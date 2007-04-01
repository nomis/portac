#ifdef __KERNEL__
# include <linux/types.h>
#else
# include <stdint.h>
#endif

#define PORTAC_IFVER 0x01

#define PORTAC_DENY  0x01
#define PORTAC_TCP4  0x02
#define PORTAC_UDP4  0x04
#define PORTAC_TCP6  0x08
#define PORTAC_UDP6  0x10
#define PORTAC_UID   0x20
#define PORTAC_GRP   0x40
#define PORTAC_LOG   0x80

#define PORTAC_FLAG(entry, flag)  ((entry)->flags & (flag))
#define PORTAC_SET(entry, flag)   do { (entry)->flags |= (flag); } while(0)
#define PORTAC_CLEAR(entry, flag) do { (entry)->flags ^= (flag); } while(0)

struct portac_entry {
	uint16_t sport;
	uint16_t eport;
	uint8_t flags;
#ifdef __KERNEL__
	uid_t uid;
	gid_t grp;
#else
	uint32_t uid;
	uint32_t grp;
#endif
	struct portac_entry *next;
};

#ifdef __KERNEL__
struct portac_proc_file {
	size_t size;
	char *data;
};
#endif

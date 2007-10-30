#ifdef __KERNEL__
# include <linux/types.h>
# include <linux/in.h>
# include <linux/in6.h>
#else
# include <stdint.h>
#endif

/* uint8_t match */
#define PORTAC_MATCH_TCP               0x00000001
#define PORTAC_MATCH_UDP               0x00000002
#define PORTAC_MATCH_IP4               0x00000004
#define PORTAC_MATCH_IP6               0x00000008
#define PORTAC_MATCH_UID               0x00000010
#define PORTAC_MATCH_GRP               0x00000020
#define PORTAC_MATCH_INVALID           0xFFFFFFC0

/* uint8_t flag */
#define PORTAC_FLAG_LOG                0x00000001
#define PORTAC_FLAG_INVALID            0xFFFFFFFE

enum portac_action {
	PORTAC_ALLOW,
	PORTAC_DENY,
	PORTAC_REQUIRE_CAP,
	PORTAC_LOG
};

enum portac_op {
	PORTAC_NONE,
	PORTAC_ADD,
	PORTAC_DEL,
	__PORTAC_OP_MAX
};
#define PORTAC_OP_MAX (__PORTAC_OP_MAX - 1)

#ifdef __KERNEL__
#define PORTAC_MATCH_ISSET(entry, mask)  ((entry)->match & (mask))
#define PORTAC_MATCH_SET(entry, mask)    do { (entry)->match |= (mask); } while(0)
#define PORTAC_MATCH_CLEAR(entry, mask)  do { (entry)->match ^= (mask); } while(0)

#define PORTAC_FLAG_ISSET(entry, mask)   ((entry)->flags & (mask))
#define PORTAC_FLAG_SET(entry, mask)     do { (entry)->flags |= (mask); } while(0)
#define PORTAC_FLAG_CLEAR(entry, mask)   do { (entry)->flags ^= (mask); } while(0)

struct portac_entry {
	/* data */
	union {
		void *host;
		struct in_addr *ip4;
		struct in6_addr *ip6;
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

struct portac_proc_file {
	size_t size;
	char *data;
};
#endif

#define PORTAC_NL_VERSION 1

enum portac_nl_attr {
	PORTAC_NL_A_UNSPEC,
	PORTAC_NL_A_LIST,        /* NLA_NESTED */
	__PORTAC_NL_A_MAX
};
#define PORTAC_NL_A_MAX (__PORTAC_NL_A_MAX - 1)

enum portac_nl_list {
	PORTAC_NL_L_UNSPEC,
	PORTAC_NL_L_OP,          /* NLA_U8 */
	PORTAC_NL_L_RULE,        /* NLA_NESTED */
	__PORTAC_NL_L_MAX
};
#define PORTAC_NL_L_MAX (__PORTAC_NL_L_MAX - 1)

enum portac_nl_rule {
	PORTAC_NL_R_UNSPEC,
	PORTAC_NL_R_ACTION,      /* NLA_U16 */
	PORTAC_NL_R_MATCH,       /* NLA_U32 */
	PORTAC_NL_R_FLAGS,       /* NLA_U32 */
	PORTAC_NL_R_DATA_SPORT,  /* NLA_U16 */
	PORTAC_NL_R_DATA_EPORT,  /* NLA_U16 */
	PORTAC_NL_R_DATA_UID,    /* NLA_U64 */
	PORTAC_NL_R_DATA_GRP,    /* NLA_U64 */
	PORTAC_NL_R_DATA_IP4,    /* NLA_UNSPEC (struct in_addr) */
	PORTAC_NL_R_DATA_IP6,    /* NLA_UNSPEC (struct in6_addr) */
	__PORTAC_NL_R_MAX
};
#define PORTAC_NL_R_MAX (__PORTAC_NL_R_MAX - 1)

enum portac_nl_default {
	PORTAC_NL_D_UNSPEC,
	PORTAC_NL_D_ACTION,      /* NLA_U16 */
	PORTAC_NL_D_FLAGS,       /* NLA_U32 */
	__PORTAC_NL_D_MAX
};
#define PORTAC_NL_D_MAX (__PORTAC_NL_D_MAX - 1)

enum {
	PORTAC_NL_C_MODIFY,
	PORTAC_NL_C_REPLACE,
	PORTAC_NL_C_LIST,
	PORTAC_NL_C_DEFAULT,
	__PORTAC_NL_C_MAX,
};
#define PORTAC_NL_C_MAX (__PORTAC_NL_C_MAX - 1)

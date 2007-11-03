#include <sys/types.h>

void list(void);
void load(const char *filename);
void save(const char *filename);
void get_default(void);
void set_default(void);
void begin(void);
void clear(void);
void commit(void);
void abort_(void);
void op_add(void);
void op_del(void);
void help(void);

void rule_init(void);
void action_allow(void);
void action_deny(void);
void action_cap(void);
void action_log(void);

void match_tcp(void);
void match_udp(void);
void match_uid(u_int64_t uid);
void match_user(const char *username);
void match_gid(u_int64_t gid);
void match_group(const char *group);
void match_ip4(const char *host);
void match_ip6(const char *host);
void match_host(const char *host);
void match_port(u_int16_t from, u_int16_t to);

void flag_log(void);


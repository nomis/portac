#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "portac.h"
#include "../../linux/portac.h"

#define PORTAC_VERSION "1.0"

int yylex_init(void **scanner);
int yy_scan_buffer(char *base, int size, void *scanner);
int yyparse(void *scanner);
int yylex_destroy(void *scanner);

static char *name;
static FILE *list_out;
static int rule = 1;
static int noports;
static u_int8_t action;
static u_int32_t match;
static u_int32_t flags;
static u_int16_t sport;
static u_int16_t eport;
static u_int64_t uid;
static u_int64_t gid;
static struct in_addr *ip4;
static struct in6_addr *ip6;

static void inline quit(const char *msg) { fprintf(stderr, "%s\n", msg); fflush(stderr); _exit(1); }
static void inline quit_if(int expr, const char *msg) { if (expr) quit(msg); }
static void inline rquit(const char *msg) { fprintf(stderr, "%d: %s\n", rule, msg); fflush(stderr); _exit(1); }
static void inline rquit_if(int expr, const char *msg) { if (expr) rquit(msg); }
static void inline pquit(const char *msg) { perror(msg); fflush(stdout); _exit(1); }
static void inline pquit_if(int expr, const char *msg) { if (expr) pquit(msg); }

#define FPRINTF(stream, format, args...) do { \
	int __ret = fprintf(stream, format , ##args); \
		if (__ret <= 0) \
			_exit(1); \
	} while(0)

#define FFLUSH(stream) do { \
	int __ret = fflush(stream); \
		if (__ret != 0) \
			_exit(1); \
	} while(0)

int main(int argc, char *argv[]) {
	const int pad = 2;
	void *scanner;
	char *cmd = NULL;
	int i, cmdlen = 0;

	if (argc <= 0)
		_exit(1);
	name = argv[0];

	/* combine arguments into one string */
	for (i = 1; i < argc; i++) {
		int len = strlen(argv[i]);

		if (len == 0)
			continue;

		cmd = realloc(cmd, sizeof(char) * cmdlen + (i != 1 ? 1 : 0) + len);
		quit_if(!cmd, NULL);

		if (i != 1)
			cmd[cmdlen++] = ' ';
		memcpy(&cmd[cmdlen], argv[i], len);

		cmdlen += len;
	}
	if (cmdlen == 0)
		help(0);

	/* add null padding for flex */
	cmd = realloc(cmd, sizeof(char) * cmdlen + pad);
	quit_if(!cmd, NULL);
	memset(&cmd[cmdlen], 0, pad);
	cmdlen += pad;

	/* parse command */
	yylex_init(&scanner);
	yy_scan_buffer(cmd, cmdlen, scanner);
	yyparse(scanner);
	yylex_destroy(scanner);
	free(cmd);

	return 0;
}

void help(int ret) {
	FILE *out = ret == 0 ? stdout : stderr;

	/*            0         1         2         3         4         5         6         7         8 */
	FPRINTF(out, "Usage: %s ...\n", name);
	FPRINTF(out, "  list                        Lists current rules.\n");
	FPRINTF(out, "  default [action] [flags]    Gets/sets default action/flags.\n");
	FPRINTF(out, "  load [filename]             Loads rules from stdin or 'filename'.\n");
	FPRINTF(out, "  save <filename>             Saves rules to 'filename'.\n");
	FPRINTF(out, "\n");
	FPRINTF(out, "  add <action> [matches...]   Append rule.\n");
	FPRINTF(out, "  del <action> [matches...]   Delete rule.\n");
	FPRINTF(out, "\n");
	FPRINTF(out, "Additional commands available in 'load' mode:\n");
	FPRINTF(out, "  begin             Start a list of rule operations.\n");
	FPRINTF(out, "  clear             Clear the current rules before applying the list.\n");
	FPRINTF(out, "  abort             Abort list and exit.\n");
	FPRINTF(out, "  commit            Finish the list, apply it and exit.\n");
	FPRINTF(out, "\n");
	FPRINTF(out, "Actions:\n");
	FPRINTF(out, "  allow             Allow access.\n");
	FPRINTF(out, "  deny              Deny access.\n");
	FPRINTF(out, "  cap               Require CAP_NET_BIND_SERVICE for access.\n");
	FPRINTF(out, "                    (When used as the default action, access\n");
	FPRINTF(out, "                    is always allowed for ports below 1024.)\n");
	FPRINTF(out, "  log               Continue with next rule, but log end result.\n");
	FPRINTF(out, "                    (Equivalent to 'cap' above if used as default.)\n");
	FPRINTF(out, "\n");
	FPRINTF(out, "Matches:\n");
	FPRINTF(out, "  port <from>[:to]  Port range, inclusive. (bind() 1-65535, listen() 0 only)\n");
	FPRINTF(out, "  tcp               TCP protocol.\n");
	FPRINTF(out, "  udp               UDP/UDPLITE protocol.\n");
	FPRINTF(out, "  uid <id>          User with uid 'id'.\n");
	FPRINTF(out, "  user <name>       User with username 'name'.\n");
	FPRINTF(out, "  gid <id>          User member of group with gid 'id'.\n");
	FPRINTF(out, "  group <name>      User member of group with name 'name'.\n");
	FPRINTF(out, "  ip4 [host]        IPv4 protocol, bound IP. Host may be 'all' for 0.0.0.0.\n");
	FPRINTF(out, "  ip6 [host]        IPv6 protocol, bound IP. Host may be 'all' for ::.\n");
	FPRINTF(out, "\n");
	FPRINTF(out, "Flags:\n");
	FPRINTF(out, "  log               Log the result of this rule if matched.\n");

	FFLUSH(out);
	_exit(ret);
}

void list(void) {
	
}
void load(const char *filename) {
	FILE *in;

	if (!strcmp(filename, "-")) {
		in = stdin;
	} else {
		in = fopen(filename, "r");
		pquit_if(!in, filename);
	}

	// TODO
}
void save(const char *filename) {
	FILE *out;

	if (!strcmp(filename, "-")) {
		out = stdout;
	} else {
		out = fopen(filename, "w");
		pquit_if(!out, filename);
	}

	FPRINTF(out, "# Generated by portac v%s at %ld\n", PORTAC_VERSION, time(NULL));
	list_out = out;
	list();
	FPRINTF(out, "# Completed at %ld\n", time(NULL));

	FFLUSH(out);
	_exit(0);
}
void get_default(void) {}
void set_default(void) {}
void begin(void) {}
void clear(void) {}
void commit(void) {}
void abort_(void) {}
void op_add(void) {}
void op_del(void) {}

void rule_init(void) {
	noports = 1;
	match = 0;
	flags = 0;
	sport = 0;
	eport = 0;
	free(ip4);
	ip4 = NULL;
	free(ip6);
	ip6 = NULL;
}
void action_allow(void) { action = PORTAC_ALLOW; }
void action_deny()  { action = PORTAC_DENY; }
void action_cap()   { action = PORTAC_REQUIRE_CAP; }
void action_log()   { action = PORTAC_LOG; }

void match_tcp()    {
	rquit_if((match & PORTAC_MATCH_TCP) != 0, "TCP match specified twice");
	match |= PORTAC_MATCH_TCP;
}
void match_udp()    { 
	rquit_if((match & PORTAC_MATCH_UDP) != 0, "UDP match specified twice");
	match |= PORTAC_MATCH_UDP;
}
void match_uid(u_int64_t m_uid) {
	rquit_if((match & PORTAC_MATCH_UID) != 0, "user match specified twice");
	match |= PORTAC_MATCH_UID;
	uid = m_uid;
}
void match_user(const char *username) {
	// TODO
}
void match_gid(u_int64_t m_gid) {
	rquit_if((match & PORTAC_MATCH_GRP) != 0, "group match specified twice");
	match |= PORTAC_MATCH_GRP;
	gid = gid;
}
void match_group(const char *group) {
	// TODO
}
void match_ip4(const char *host) {
	rquit_if((match & PORTAC_MATCH_IP4) != 0, "IP4 match specified twice");
	match |= PORTAC_MATCH_IP4;
}
void match_ip6(const char *host) {
	rquit_if((match & PORTAC_MATCH_IP6) != 0, "IP6 match specified twice");
	match |= PORTAC_MATCH_IP6;
}
void match_host(const char *host) {
	struct in_addr host4;
	struct in6_addr host6;

	if (inet_pton(AF_INET, host, &host4)) {
		struct in_addr *tmp = malloc(sizeof(struct in_addr));
		pquit_if(!tmp, NULL);
		memcpy(ip4, &host4, sizeof(struct in_addr));
		ip4 = tmp;
		return;
	}
	if (inet_pton(AF_INET, host, &host6)) {
		struct in6_addr *tmp = malloc(sizeof(struct in6_addr));
		pquit_if(!tmp, NULL);
		memcpy(ip6, &host6, sizeof(struct in6_addr));
		ip6 = tmp;
	}
	rquit("invalid IP");
}
void match_port(u_int16_t from, u_int16_t to) {
	rquit_if(!noports, "port(s) specified twice");
	rquit_if(from > to, "invalid port range");
	noports = 0;
	sport = from;
	eport = to;
}

void flag_log(void) {
	rquit_if((flags & PORTAC_FLAG_LOG) != 0, "log flag specified twice");
	flags |= PORTAC_FLAG_LOG;
}

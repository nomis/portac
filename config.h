#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include "linux/portac.h"

uint16_t count = 0;

uint8_t default_action[8192];
inline int get_require_cap_net_bind_service(uint16_t port) {
	return (default_action[port >> 3] & (1 << (port & 0x07))) != 0;
}
inline void set_require_cap_net_bind_service(uint16_t port, int yes) {
	if (yes)
		default_action[port >> 3] |= (1 << (port & 0x07));
	else
		default_action[port >> 3] &= ~(1 << (port & 0x07));
}
struct portac_entry *portac_entries = NULL;

struct ports {
	uint16_t from;
	uint16_t to;
};

struct types {
	uint8_t types;
};

struct user {
	uint32_t user;
};

struct pacgroup {
	uint32_t group;
};

#define TCP4 PORTAC_TCP4
#define TCP6 PORTAC_TCP6
#define TCP (TCP4|TCP6)

#define UDP4 PORTAC_UDP4
#define UDP6 PORTAC_UDP6
#define UDP (UDP4|UDP6)

#define IPv4 (TCP4|UDP4)
#define IPv6 (TCP6|UDP6)
#define ANY (TCP|UDP)

struct ports *ports(uint16_t from, uint16_t to) {
	struct ports *ports = (struct ports*)malloc(sizeof(struct ports));
	if (from > to) {
		fprintf(stderr, "Port range %u-%u is invalid.\n", from, to);
		exit(1);
	}
	ports->from = from;
	ports->to = to;
	return ports;
}

struct ports *port(uint16_t port) {
	return ports(port, port);
}

struct types *type(uint8_t type) {
	struct types *types = (struct types*)malloc(sizeof(struct types));
	types->types = type;
	return types;
}

struct user *user(char *name) {
	struct user *user = (struct user*)malloc(sizeof(struct user));
	struct passwd *pwnam = getpwnam(name);
	if (pwnam == NULL) {
		fprintf(stderr, "User '%s' not found.\n", name);
		exit(1);
	}
	user->user = pwnam->pw_uid;
	return user;
}

struct pacgroup *group(char *name) {
	struct pacgroup *group = (struct pacgroup*)malloc(sizeof(struct pacgroup));
	struct group *grnam = getgrnam(name);
	if (grnam == NULL) {
		fprintf(stderr, "Group '%s' not found.\n", name);
		exit(1);
	}
	group->group = grnam->gr_gid;
	return group;
}

void _default(int deny, struct ports *ports) {
	int i;
	for (i = ports->from; i <= ports->to; i++)
		set_require_cap_net_bind_service(i, deny);
	free(ports);
}

void _add_entry(struct portac_entry *entry) {
	struct portac_entry *copy = (struct portac_entry *)malloc(sizeof(struct portac_entry));
	copy->sport = entry->sport;
	copy->eport = entry->eport;
	copy->flags = entry->flags;
	copy->uid = entry->uid;
	copy->grp = entry->grp;
	copy->next = NULL;

	if (portac_entries == NULL) {
		portac_entries = copy;
	} else {
		struct portac_entry *tmp = portac_entries;

	while (tmp->next != NULL)
		tmp = tmp->next;

		tmp->next = copy;
	}
	count++;
}


void _add(int action, struct ports *ports, struct types *types, struct user *user, struct pacgroup *group) {
	struct portac_entry entry;

	entry.sport = ports->from;
	entry.eport = ports->to;
	
	entry.flags = 0;
	if (types == NULL) types = type(ANY);
	entry.flags |= types->types;
	if (user != NULL) entry.flags |= PORTAC_UID;
	if (group != NULL) entry.flags |= PORTAC_GRP;
	if (action == 0) entry.flags |= PORTAC_DENY;
	if (action == 2) entry.flags |= PORTAC_LOG;

	if (user != NULL) entry.uid = user->user;
	else entry.uid = 0;
	if (group != NULL) entry.grp = group->group;
	else entry.grp = 0;

	_add_entry(&entry);

	free(types);
	if (user != NULL) free(user);
	if (group != NULL) free(group);
}

ssize_t _write(int fd, const void *buf, size_t count) {
	ssize_t ret = write(fd, buf, count);
	if (ret != count) {
		fprintf(stderr, "Tried to write %u bytes, only wrote %u.\n", count, ret);
		exit(1);
	}
	return ret;
}


void config();

int main() {
	struct portac_entry *tmp;
	char header[] = { 0, PORTAC_IFVER };

	config();
	_write(1, header, 2);
	count = htons(count);
	_write(1, &count, 2);
	_write(1, default_action, sizeof(default_action));

	tmp = portac_entries;
	while (tmp != NULL) {
		uint16_t sp = htons(tmp->sport);
		uint16_t ep = htons(tmp->eport);
		uint32_t uid = htonl(tmp->uid);
		uint32_t grp = htonl(tmp->grp);
		_write(1, &sp, 2);
		_write(1, &ep, 2);
		_write(1, &tmp->flags, 1);
		_write(1, &uid, 4);
		_write(1, &grp, 4);
		tmp = tmp->next;
	}
	return 0;
}



void default_allow(struct ports *ports) { _default(0, ports); }
void default_deny(struct ports *ports) { _default(1, ports); }

void denyP(struct ports *ports) { _add(0, ports, NULL, NULL, NULL); }
void denyPU(struct ports *ports, struct user *user) { _add(0, ports, NULL, user, NULL); }
void denyPG(struct ports *ports, struct pacgroup *group) { _add(0, ports, NULL, NULL, group); }
void denyPUG(struct ports *ports, struct user *user, struct pacgroup *group) { _add(0, ports, NULL, user, group); }
void denyPT(struct ports *ports, struct types *types) { _add(0, ports, types, NULL, NULL); }
void denyPTU(struct ports *ports, struct types *types, struct user *user) { _add(0, ports, types, user, NULL); }
void denyPTG(struct ports *ports, struct types *types, struct pacgroup *group) { _add(0, ports, types, NULL, group); }
void denyPTUG(struct ports *ports, struct types *types, struct user *user, struct pacgroup *group) { _add(0, ports, types, user, group); }

void allowP(struct ports *ports) { _add(1, ports, NULL, NULL, NULL); }
void allowPU(struct ports *ports, struct user *user) { _add(1, ports, NULL, user, NULL); }
void allowPG(struct ports *ports, struct pacgroup *group) { _add(1, ports, NULL, NULL, group); }
void allowPUG(struct ports *ports, struct user *user, struct pacgroup *group) { _add(1, ports, NULL, user, group); }
void allowPT(struct ports *ports, struct types *types) { _add(1, ports, types, NULL, NULL); }
void allowPTU(struct ports *ports, struct types *types, struct user *user) { _add(1, ports, types, user, NULL); }
void allowPTG(struct ports *ports, struct types *types, struct pacgroup *group) { _add(1, ports, types, NULL, group); }
void allowPTUG(struct ports *ports, struct types *types, struct user *user, struct pacgroup *group) { _add(1, ports, types, user, group); }

void logP(struct ports *ports) { _add(2, ports, NULL, NULL, NULL); }
void logPU(struct ports *ports, struct user *user) { _add(2, ports, NULL, user, NULL); }
void logPG(struct ports *ports, struct pacgroup *group) { _add(2, ports, NULL, NULL, group); }
void logPUG(struct ports *ports, struct user *user, struct pacgroup *group) { _add(2, ports, NULL, user, group); }
void logPT(struct ports *ports, struct types *types) { _add(2, ports, types, NULL, NULL); }
void logPTU(struct ports *ports, struct types *types, struct user *user) { _add(2, ports, types, user, NULL); }
void logPTG(struct ports *ports, struct types *types, struct pacgroup *group) { _add(2, ports, types, NULL, group); }
void logPTUG(struct ports *ports, struct types *types, struct user *user, struct pacgroup *group) { _add(2, ports, types, user, group); }

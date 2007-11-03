%{

#include <stdio.h>
#include <stdlib.h>

#include "portac.h"

#define YYLEX_PARAM scanner

int yylex(void *lvalp, void *scanner);
int yywrap(void *scanner) { return 1; }
void yyerror(void *scanner, const char reason[]) { fprintf(stderr, "%s\n", reason); }

%}

%pure-parser
%parse-param { void *scanner }
%union {
	char *text;
	unsigned long long val;
}

%token HELP LIST LOAD SAVE DEFAULT
%token BEGIN_ CLEAR COMMIT ABORT
%token ADD DEL
%token ALLOW DENY CAP LOG
%token TCP UDP IP4 IP6
%token UID USER GID GROUP
%token HOST PORT ALL
%token END 0 "end of input"

%token <text> STRING "string" FILENAME "filename" NAME "name" IP "IP address"
%token <val> INTEGER "number"

%error-verbose
%destructor { free($$); $$ = NULL; } STRING FILENAME NAME IP

%%

command : LIST END						{ list(); }
	| LOAD END							{ load("-"); }
	| LOAD FILENAME END					{ load($2); free($2); $2 = NULL; }
	| SAVE FILENAME END					{ save($2); free($2); $2 = NULL; }
	| DEFAULT END						{ get_default(); }
	| DEFAULT action flags END			{ set_default(); }
	| BEGIN_ END						{ begin(); }
	| CLEAR END							{ clear(); }
	| COMMIT END						{ commit(); }
	| ABORT END							{ abort_(); }
	| add action matches_and_flags END	{ op_add(); }
	| del action matches_and_flags END	{ op_del(); }
	| HELP END							{ help(); }

add : ADD								{ rule_init(); }
del : DEL								{ rule_init(); }

action : ALLOW							{ action_allow(); }
	| DENY								{ action_deny(); }
	| CAP								{ action_cap(); }
	| LOG								{ action_log(); }

matches_and_flags : match
	| flag
	| match matches_and_flags
	| flag matches_and_flags

match : TCP								{ match_tcp(); }
	| UDP								{ match_udp(); }
	| UID INTEGER						{ match_uid($2); }
	| USER NAME							{ match_user($2); free($2); $2 = NULL; }
	| GID INTEGER						{ match_gid($2); }
	| GROUP NAME						{ match_group($2); free($2); $2 = NULL; }
	| IP4								{ match_ip4(NULL); }
	| IP4 IP							{ match_ip4($2); free($2); $2 = NULL; }
	| IP4 ALL							{ match_ip4("0.0.0.0"); }
	| IP6								{ match_ip6(NULL); }
	| IP6 IP							{ match_ip6($2); free($2); $2 = NULL; }
	| IP6 ALL							{ match_ip6("::"); }
	| HOST IP							{ match_host($2); free($2); $2 = NULL; }
	| PORT INTEGER						{ match_port($2, $2); }
	| PORT INTEGER ':' INTEGER			{ match_port($2, $4); }

flags: flag
	| flag flags

flag : LOG								{ flag_log(); }

%%

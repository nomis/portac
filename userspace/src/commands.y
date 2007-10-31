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

%token <text> STRING
%token <val> INTEGER

%error-verbose
%destructor { free($$); $$ = NULL; } STRING

%%

command : LIST							{ list(); }
	| LOAD								{ load("-"); }
	| LOAD STRING						{ load($2); }
	| SAVE STRING						{ save($2); }
	| DEFAULT							{ get_default(); }
	| DEFAULT action flags				{ set_default(); }
	| BEGIN_							{ begin(); }
	| CLEAR								{ clear(); }
	| COMMIT							{ commit(); }
	| ABORT								{ abort_(); }
	| add action matches_and_flags		{ op_add(); }
	| del action matches_and_flags		{ op_del(); }
	| HELP								{ help(0); }
	|									{ help(1); }

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
	| USER STRING						{ match_user($2); }
	| GID INTEGER						{ match_gid($2); }
	| GROUP STRING						{ match_group($2); }
	| IP4								{ match_ip4(NULL); }
	| IP4 STRING						{ match_ip4($2); }
	| IP4 ALL							{ match_ip4("0.0.0.0"); }
	| IP6								{ match_ip6(NULL); }
	| IP6 STRING						{ match_ip6($2); }
	| IP6 ALL							{ match_ip6("::"); }
	| HOST STRING						{ match_host($2); }
	| PORT INTEGER						{ match_port($2, $2); }
	| PORT INTEGER ':' INTEGER			{ match_port($2, $4); }

flags: flag
	| flag flags

flag : LOG								{ flag_log(); }

%%

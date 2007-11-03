%{

#include "__commands-y.h"

enum lexer_state {
	LS_STRING,
	LS_NAME,
	LS_FILENAME,
	LS_IP
};

#define YY_EXTRA_TYPE enum lexer_state
#define YY_USER_INIT yyextra = LS_STRING;

%}

%option bison-bridge
%option reentrant

whitespace			[ ]+
digit				[0-9]
integer				{digit}+
string				[^\x00-\x20]+

%%

help			{ return HELP; }
-h				{ return HELP; }
--help			{ return HELP; }
list			{ return LIST; }
load			{ yyextra = LS_FILENAME; return LOAD; }
save			{ yyextra = LS_FILENAME;return SAVE; }
default			{ return DEFAULT; }

begin			{ return BEGIN_; }
clear			{ return CLEAR; }
commit			{ return COMMIT; }
abort			{ return ABORT; }

add				{ return ADD; }
del				{ return DEL; }

allow			{ return ALLOW; }
deny			{ return DENY; }
cap				{ return CAP; }
log				{ return LOG; }

tcp				{ return TCP; }
udp				{ return UDP; }
ipv?4			{ yyextra = LS_IP; return IP4; }
ipv?6			{ yyextra = LS_IP; return IP6; }

uid				{ return UID; }
user			{ yyextra = LS_NAME; return USER; }
gid				{ return GID; }
group			{ yyextra = LS_NAME; return GROUP; }

host			{ yyextra = LS_IP; return HOST; }
port			{ return PORT; }
\*				{ return ALL; }
all				{ return ALL; }

{whitespace}	{}
{integer}		{
	yylval->val = strtoull(yytext, NULL, 10);
	return INTEGER;
}
{string}		{
	YY_EXTRA_TYPE yyextra_ = yyextra;
	char *text = malloc(sizeof(char) * (strlen(yytext) + 1));
	if (!text) {
		perror(NULL);
		_exit(1);
	}
	strcpy(text, yytext);
	yylval->text = text;
	yyextra = LS_STRING;
	switch (yyextra_) {
	case LS_FILENAME:
		return FILENAME;
	case LS_NAME:
		return NAME;
	case LS_IP:
		return IP;
	case LS_STRING:
	default:
		return STRING;
	}
}
.				{}

%%

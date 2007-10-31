%{

#include "__commands-y.h"

%}

%option bison-bridge
%option reentrant

whitespace			[ ]+
digit				[0-9]
integer				{digit}+
string				[^\x00-\x20]+

%%

help				{ return HELP; }
-h					{ return HELP; }
--help				{ return HELP; }
list				{ return LIST; }
load				{ return LOAD; }
save				{ return SAVE; }
default				{ return DEFAULT; }

begin				{ return BEGIN_; }
clear				{ return CLEAR; }
commit				{ return COMMIT; }
abort				{ return ABORT; }

add					{ return ADD; }
del					{ return DEL; }

allow				{ return ALLOW; }
deny				{ return DENY; }
cap					{ return CAP; }
log					{ return LOG; }

tcp					{ return TCP; }
udp					{ return UDP; }
ipv?4				{ return IP4; }
ipv?6				{ return IP6; }

uid					{ return UID; }
user				{ return USER; }
gid					{ return GID; }
group				{ return GROUP; }

host				{ return HOST; }
port				{ return PORT; }
\*					{ return ALL; }
all					{ return ALL; }

{whitespace}		{}
{integer}			{
	yylval->val = strtoull(yytext, NULL, 10);
	return INTEGER;
}
{string}			{
	char *text = malloc(sizeof(char) * (strlen(yytext) + 1));
	strcpy(text, yytext);
	yylval->text = text;
	return STRING;
}
.					{ return yytext[0]; }

%%

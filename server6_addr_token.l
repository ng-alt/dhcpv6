/*	$Id: server6_addr_token.l,v 1.1.1.1 2003/01/16 15:41:11 root Exp $	*/

/*
 * Copyright (C) International Business Machines  Corp., 2003
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* Author: Shirley Ma, xma@us.ibm.com */

%option noyywrap

%{
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/in6.h>
#include <net/if.h>
#include <server6_conf.h>
#include "sf.tab.h"

int num_lines = 1;
int sfyyerrorcount = 0;
int sfparse(char *filename);
extern void sfyyerror(char *msg);
extern struct rootgroup *globalgroup;

%}

digit		[0-9]
number		({digit})+
snum		-?({digit})+
decimal		({number}"."{number})
hexdigit	([a-f]|[A-F]|[0-9])
hexpair		{hexdigit}{hexdigit}
iaid_id		{hexpair}{4}
addr1		{hexdigit}{1,4}":"({hexdigit}{1,4}":")*(":"{hexdigit}{1,4})+
addr2		{hexdigit}{1,4}(":"{hexdigit}{1,4})*"::"
addr3		({hexdigit}{1,4}":"){7}{hexdigit}{1,4}
addr		({addr1}|{addr2}|{addr3})
whitespace	([ \t])+
duid_id		{hexpair}(:{hexpair})*
string		[a-zA-Z]([a-zA-Z]|{digit})*(":"{digit}+)?

%%

#.*$			{/* ignore comments */}
\n			{num_lines++;}
{whitespace}		{}

interface		{ return INTERFACE; }
link			{ return LINK; }
relay			{ return RELAY; }
prefix			{ return PREFIX; }
host			{ return HOST; }
pool			{ return POOL; }
range			{ return RANGE; }
group			{ return GROUP; }
allow			{ return ALLOW; }
option			{ return OPTION; }
linklocal		{ return LINKLOCAL; }
duid			{ return DUID; }
iaid			{ return IAID; }

unicast			{ return UNICAST; }
preference		{ return PREFERENCE; }
info_only		{ return INFO_ONLY; }

RenewTime		{ return RENEWTIME; }
RebindTime		{ return REBINDTIME; }
RapidCommit		{ return RAPIDCOMMIT; }

TempIPv6Addr		{ return TEMPIPV6ADDR; }

FixedIPv6Addr		{ return FIXEDIPV6ADDR; }
ValidLifeTime		{ return VALIDLIFETIME; }
PreferredLifeTime	{ return PREFERLIFETIME; }

to			{ return TO; }

{addr}		{
			struct in6_addr addr;
			int i;
				
			i = inet_pton(AF_INET6, sfyytext, &addr);
			if (i < 1) {
				dprintf(LOG_ERR, "invalid address in line %d", num_lines); 
				return BAD_TOKEN;
			}

			sfyylval.addr = addr;
			return IPV6ADDR;
		}

{number}	{ sfyylval.num = atoi(sfyytext); return NUMBER; }

{snum}		{ sfyylval.snum = atoi(sfyytext); return SIGNEDNUMBER; }

{decimal}	{ sfyylval.dec = atof(sfyytext); return DECIMAL; }

{duid_id}	{ sfyylval.str = strdup(sfyytext); return DUID_ID; } 

infinity	{ return INFINITY; }

on		{ sfyylval.bool = 1; return BOOLEAN; }

off		{ sfyylval.bool = 0; return BOOLEAN; }

{string}	{
			static char name[IFNAMSIZ];
			strncpy(name, sfyytext, IFNAMSIZ-1);
			name[IFNAMSIZ-1] = '\0';
			sfyylval.str = name;
			return STRING;
		}

"{"|"}"|";"|"/"	{ return *sfyytext; }

.		{ return BAD_TOKEN; }

%%

int
sfparse(conf)
        char *conf;
{
        if ((sfyyin = fopen(conf, "r")) == NULL) {
                if (errno == ENOENT)
                        return(0);
                dprintf(LOG_ERR, "sfparse: fopen(%s): %s",
                        conf, strerror(errno));
		printf("open error\n");
                return(-1);
        }

        if (sfyyparse() || sfyyerrorcount) {
                sfyyerror("fatal parse failure: exiting");
                return(-1);
        }
	post_config(globalgroup);

}

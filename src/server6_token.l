/* $Id: server6_token.l,v 1.4 2007/11/12 22:36:49 dlc-atl Exp $ */

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
#include "config.h"

/*
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/queue.h>

#include "dhcp6.h"
#include "cfg.h"
#include "common.h"
#include "server6_conf.h"
#include "server6_parse.h"
*/

#define YY_NO_UNPUT 1
#define ECHO if (fwrite(yytext, yyleng, 1, yyout) != 1) { \
                 YY_FATAL_ERROR("error performing ECHO on yytext"); \
             }

int num_lines = 1;
int server6errorcount = 0;
extern int client6parse(void);
extern void server6error(char *msg);
extern struct rootgroup *globalgroup;

%}

whitespace	([ \t])+
digit		[0-9]
number		({digit})+
snum		-?({digit})+
decimal		({number}"."{number})
hexdigit	([a-f]|[A-F]|[0-9])
hexpair		{hexdigit}{hexdigit}
duid_id		{hexpair}(":"{hexpair})*
ipv4addr        ({digit}{1,3}"."{digit}{1,3}"."{digit}{1,3}"."{digit}{1,3})
addr_head       ("::"|{hexdigit}{1,4}(":"|"::"))
addr_tail       ({hexdigit}{1,4}|({hexdigit}{1,4}"::")|{ipv4addr})?
addr_body       ({hexdigit}{1,4}(":"|"::"))*
ipv6addr        {addr_head}{addr_body}{addr_tail}
string		[a-zA-Z0-9:\._-][a-zA-Z0-9:\._-]*
ifname		({string})+

%s S_IFACE
%s S_DUID
%s S_OPTION

%%

group		{ return GROUP; }

interface	{ BEGIN S_IFACE; return INTERFACE; }
<S_IFACE>{ifname} 	{ BEGIN INITIAL; server6lval.str = strdup(yytext); return IFNAME;}

link		{ return LINK; }
relay		{ return RELAY; }
host		{ return HOST; }

pool		{ return POOL; }
range		{ return RANGE; }

iaid		{ return IAID; }
iaidinfo 	{ return IAIDINFO; }

duid		{ BEGIN S_DUID; return DUID; }
<S_DUID>{duid_id} { BEGIN INITIAL; server6lval.str = strdup(yytext); return DUID_ID; } 

prefix		{ return PREFIX; }
address		{ return ADDRESS;}

allow		{ BEGIN S_OPTION; return ALLOW; }
send		{ BEGIN S_OPTION; return SEND; }
option		{ BEGIN S_OPTION; return OPTION; }

<S_OPTION>unicast	{ BEGIN INITIAL; return UNICAST; }
<S_OPTION>rapid-commit	{ BEGIN INITIAL; return RAPIDCOMMIT; }
<S_OPTION>temp-address	{ BEGIN INITIAL; return TEMPIPV6ADDR; }
<S_OPTION>information-only	{ BEGIN INITIAL; return INFO_ONLY; }
<S_OPTION>dns_servers	{ BEGIN INITIAL; return DNS_SERVERS;}

renew-time	{ return RENEWTIME; }
rebind-time	{ return REBINDTIME; }
valid-life-time	 { return VALIDLIFETIME; }
prefer-life-time { return PREFERLIFETIME; }
server-preference { return PREFERENCE; }
use-ra-prefix     { return USE_RA_PREFIX; }

to	{ return TO; }
infinity	{ return INFINITY; }

#.*$			{/* ignore comments */}
\n			{num_lines++;}
{whitespace}		{}
{ipv6addr} {
			struct in6_addr addr;
			int i;
				
			i = inet_pton(AF_INET6, yytext, &addr);
			if (i < 1) {
				dprintf(LOG_ERR, "invalid address in line %d", num_lines); 
				return BAD_TOKEN;
			}

			server6lval.addr = addr;
			return IPV6ADDR;
		}

{number}	{ server6lval.num = strtoll(yytext, NULL, 10); return NUMBER; }
{snum}	{ server6lval.snum = strtoll(yytext, NULL, 10); return SIGNEDNUMBER; }
{decimal} { server6lval.dec = atof(yytext); return DECIMAL; }
{string}	{
			static char name[MAXDNAME];
			strncpy(name, yytext, MAXDNAME-1);
			name[MAXDNAME-1] = '\0';
			server6lval.str = name;
			return STRING;
		}
"{"|"}"|";"|"/"	{ return *yytext; }
.		{ return BAD_TOKEN; }

%%


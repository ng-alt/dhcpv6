/*	$Id: ra_token.l,v 1.4 2003/04/30 19:04:12 shirleyma Exp $	*/

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
 */

%option noyywrap

%{
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <syslog.h>
#include <string.h>

#include "queue.h"
#include "dhcp6.h"
#include "config.h"
#include "common.h"

#define YYABORT(msg) dprintf(LOG_ERR, msg " %s lineno %d.", \
	yytext, num_lines)

#define ABORT   do {    \
	YYABORT("lease parse error");   \
	exit(1);        \
} while (0)

extern struct dhcp6_if *dhcp6_if;
const char *rafile = "/proc/net/ra_inet6";

static struct ra_info *rainfo;
static int num_lines = 0;

%}

digit           [0-9]
number          ({digit})+
hexdigit        ([a-f]|[A-F]|[0-9])
ipv4addr        ({digit}{1,3}"."{digit}{1,3}"."{digit}{1,3}"."{digit}{1,3})
addr_head       ("::"|{hexdigit}{1,4}(":"|"::"))
addr_tail       ({hexdigit}{1,4}|({hexdigit}{1,4}"::")|{ipv4addr})?
addr_body       ({hexdigit}{1,4}(":"|"::"))*
ipv6addr        {addr_head}{addr_body}{addr_tail}
whitespace      ([ \t])+
ifname          [a-zA-Z]+[0-9]+
flags		[a-zA-Z]+
nl              \n


%s S_CNF S_INDEX S_PLEN S_FLAGS S_PREFIX

%%

{nl}            {num_lines++; BEGIN INITIAL;}
{whitespace}    {;}

<S_CNF>{ifname} {if (strcmp(rayytext, dhcp6_if->ifname))
			BEGIN S_CNF;
		else {
			rainfo = (struct ra_info *)malloc(sizeof(*rainfo));
			if (rainfo == NULL)
				ABORT;
			else 
				BEGIN S_INDEX;}
		}
<S_CNF>. {ABORT;}
<S_INDEX>{number} {if (atoi(rayytext) != dhcp6_if->ifid)
			ABORT;
		else   
			BEGIN S_PLEN;}
<S_INDEX>. {ABORT;}
<S_PLEN>{number} {rainfo->plen = atoi(rayytext); BEGIN S_FLAGS;}
<S_PLEN>. {ABORT;}
<S_FLAGS>{flags} {if (strchr(rayytext, 'M') != NULL)
			rainfo->flags |= RA_MBIT_SET;
		else if (strchr(rayytext, 'O') != NULL)
			rainfo->flags |= RA_OBIT_SET;
		BEGIN S_PREFIX;}
<S_FLAGS>. {ABORT;}
<S_PREFIX>{ipv6addr} {struct in6_addr addr;
		struct ra_info *ri, *ri_prev;
		if (inet_pton(AF_INET6, rayytext, &addr) < 1) 
			ABORT;
		else {
			memcpy(&rainfo->prefix, &addr, sizeof(rainfo->prefix));
			if (dhcp6_if->ralist == NULL) {
				dhcp6_if->ralist = rainfo;
				rainfo->next = NULL;
			} else {
				ri_prev = dhcp6_if->ralist;
				for (ri = dhcp6_if->ralist; ri; ri = ri->next) {
					if (rainfo->plen < ri->plen) {
						if (ri->next == NULL) {
							ri->next = rainfo;
							rainfo->next = NULL;
							break;
						}
					} else {
						ri_prev->next = rainfo;
						rainfo->next = ri;
						break;
					}
					ri_prev = ri->next;	
					continue;
				}
			}
			BEGIN S_CNF;}
		}
<S_PREFIX>. {ABORT;}

%%

int
ra_parse(const char *raname)
{
	if ((rayyin = fopen(raname, "r")) == NULL) {
		if (errno == ENOENT)
			return (0);
		dprintf(LOG_ERR, "ra_parse: fopen(%s): %s",
			configfilename, strerror(errno));
		return (-1);
	}
	yylex();
}

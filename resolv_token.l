/*	$Id: resolv_token.l,v 1.1 2003/04/12 00:25:33 shirleyma Exp $	*/

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
	YYABORT("resolv parse error");   \
	exit(1);        \
} while (0)

extern struct dhcp6_if *dhcp6_if;
extern char *device;
extern const char *resolv_file;

static int num_lines = 0;

int resolv_parse __P((const char *));

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
domainname	[a-zA-Z0-9:\._-]+
nl              \n


%s S_ADDR S_DOMAIN

%%

{nl}            {num_lines++; BEGIN INITIAL;}
{whitespace}    {;}

"nameserver"	{BEGIN S_ADDR;}
"search"	{BEGIN S_DOMAIN;}

<S_DOMAIN>{domainname} { struct domain_list *domainname, *temp;
		domainname = (struct domain_list *)malloc(sizeof(*domainname));
		if (domainname == NULL)
			ABORT;
		if (strlen(yytext) > MAXDNAME)
			ABORT;
		strcpy(domainname->name, yytext);
		dprintf(LOG_DEBUG, "parse domain name %s", domainname->name);
		domainname->next = NULL;
		if (dhcp6_if->dnslist.domainlist == NULL)
			dhcp6_if->dnslist.domainlist = domainname;
		else {
			for (temp = dhcp6_if->dnslist.domainlist; temp; temp = temp->next) {
				if (temp->next == NULL) {
					temp->next = domainname;
					break;
				}
			}
		}
		BEGIN S_DOMAIN;}

<S_DOMAIN>. {BEGIN INITIAL;}

<S_ADDR>{ipv6addr} {struct in6_addr addr;
		if (inet_pton(AF_INET6, yytext, &addr) < 1) 
			ABORT;
		dprintf(LOG_DEBUG, "parse name server %s", in6addr2str(&addr, 0));
		if (dhcp6_add_listval(&dhcp6_if->dnslist.addrlist,
		    &addr, DHCP6_LISTVAL_ADDR6) == NULL) {
			dprintf(LOG_ERR, "%s" "failed to add a DNS server", FNAME);
			ABORT;
		}
		BEGIN S_ADDR;}
<S_ADDR>. {BEGIN INITIAL;}

%%

int
resolv_parse(const char *resolvname)
{
	TAILQ_INIT(&dhcp6_if->dnslist.addrlist);
	dhcp6_if->dnslist.domainlist = NULL;
	if ((yyin = fopen(resolvname, "r")) == NULL) {
		if (errno == ENOENT)
			return (0);
		dprintf(LOG_ERR, "resolv_parse: fopen(%s): %s",
			resolvname, strerror(errno));
		return (-1);
	}
	yylex();
}

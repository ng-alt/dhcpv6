/*	$Id: cftoken.l,v 1.1 2003/01/16 15:41:11 root Exp $	*/
/*	from KAME: cftoken.l,v 1.15 2002/09/24 14:20:49 itojun Exp	*/

/*
 * Copyright (C) 2002 WIDE Project.
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

%option noyywrap

%{
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <netinet/in.h>

#include <errno.h>
#include <syslog.h>
#include <string.h>
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include "dhcp6.h"
#include "config.h"
#include "common.h"
#include "cf.tab.h"

char *configfilename;
int lineno = 1;

static int cfyy_first_time = 1;
static int cfyyerrorcount = 0;

 
#ifndef NOCONFIG_DEBUG
#define YYDEBUG 1

int cfdebug = 1;
#else
int cfdebug = 0;
#endif

static void cfdebug_print __P((char *, char *, int));

#define DP(str) if (cfdebug) cfdebug_print(str, cfyytext, cfyyleng)
#define DECHO if (cfdebug) cfdebug_print(NULL, cfyytext, cfyyleng);
%}

/* abbreviations */
nl		\n
ws		[ \t]+
comma		,
comment		\#.*
semi		\;
string		[a-zA-Z0-9:\._][a-zA-Z0-9:\._]*
digit		[0-9]
integer 	{digit}+
number		{integer}|({digit}*\.{integer})
hexdigit	[0-9A-Fa-f]
hexpair		{hexdigit}{hexdigit}
hexstring	0[xX]{hexpair}+
duid 		{hexpair}(:{hexpair})*
ifname		[a-zA-Z]+[0-9]+
slash		\/
bcl		\{
ecl		\}

%s S_CNF
%s S_IFACE
%s S_PREF
%s S_HOST
%s S_DUID

%%
%{
	if (cfyy_first_time) {
		BEGIN S_CNF;
		cfyy_first_time = 0;
	}
%}
	/* interface configuration */
<S_CNF>interface { DECHO; BEGIN S_IFACE; return (INTERFACE); }
<S_IFACE>{string} {
	DECHO;
	cfyylval.str = strdup(cfyytext);
	BEGIN S_CNF;
	return (IFNAME);
}

	/* host configuration */
<S_CNF>host { DECHO; BEGIN S_HOST; return (HOST); }
<S_HOST>{string} {
	DECHO;
	cfyylval.str = strdup(cfyytext);
	BEGIN S_CNF;
	return (HOSTNAME);
}

<S_CNF>duid { DECHO; BEGIN S_DUID; return (DUID); }
<S_DUID>{duid} {
	DECHO;
	cfyylval.str = strdup(cfyytext);
	BEGIN S_CNF;
	return (DUID_ID);
}

<S_CNF>prefix { DECHO; return (PREFIX); }

<S_CNF>preference { DECHO; return (PREFERENCE); }

	/* request */
<S_CNF>request { DECHO; return (REQUEST); }

	/* send */
<S_CNF>send { DECHO; return (SEND); }

	/* DHCP options */
<S_CNF>option { DECHO; return (OPTION); }

<S_CNF>rapid-commit { DECHO; return (RAPID_COMMIT); }
<S_CNF>prefix-delegation { DECHO; return (PREFIX_DELEGATION); }
<S_CNF>domain-name-servers { DECHO; return (DNS_SERVERS); }

	/* generic options */
<S_CNF>information-only { DECHO; return (INFO_ONLY); }

<S_CNF>allow { DECHO; return (ALLOW); }

	/* interface parameters for delegated prefix configuration */
<S_CNF>prefix-interface { DECHO; BEGIN S_IFACE; return (PREFIX_INTERFACE); }
<S_CNF>sla-id { DECHO; return (SLA_ID); }
<S_CNF>sla-len { DECHO; return (SLA_LEN); }

	/* duration */
<S_CNF>infinity { DECHO; return (INFINITY); }

	/* misc */
{ws}		{ ; }
{nl}		{ lineno++; }
{comment}	{ DP("comment"); }
{number} 	{
	DECHO;
	cfyylval.num = strtoll(cfyytext, NULL, 10);
	return (NUMBER);
}
{slash} { DECHO; return (SLASH); }
{comma} { DECHO; return (COMMA); }
{semi} { DP("end of sentence"); return (EOS); }
{bcl} { DP("begin of closure"); return (BCL); }
{ecl} { DP("end of closure"); return (ECL); }

	/* generic string */
{string} {
		DECHO;
		cfyylval.str = strdup(cfyytext);
		return (STRING);
	}

%%
static void
cfdebug_print(w, t, l)
	char *w, *t;
	int l;
{
	if (w)
		dprintf(LOG_DEBUG, "<%d>%s [%s] (%d)", yy_start, w, t, l);
	else
		dprintf(LOG_DEBUG, "<%d>[%s] (%d)", yy_start, t, l);
}

static void
cfyyerror0(int level, char *s, va_list ap)
{
	char ebuf[BUFSIZ], *bp, *ep;

	bp = ebuf;
	ep = ebuf + sizeof(ebuf);
	bp += snprintf(bp, ep - bp, "%s %d: ", configfilename, lineno);
	if (bp < ep)
		bp += vsnprintf(bp, ep - bp, s, ap);

	dprintf(level, ebuf);
}

void
cfyyerror(char *s, ...)
{
	va_list ap;
#ifdef HAVE_STDARG_H
	va_start(ap, s);
#else
	va_start(ap);
#endif
	cfyyerror0(LOG_ERR, s, ap);
	va_end(ap);
	cfyyerrorcount++;
}

void
cfyywarn(char *s, ...)
{
	va_list ap;
#ifdef HAVE_STDARG_H
	va_start(ap, s);
#else
	va_start(ap);
#endif
	cfyyerror0(LOG_WARNING, s, ap);
	va_end(ap);
}

int
cfparse(conf)
	char *conf;
{
	configfilename = conf;
	if ((cfyyin = fopen(configfilename, "r")) == NULL) {
		if (errno == ENOENT)
			return (0);
		dprintf(LOG_ERR, "cfparse: fopen(%s): %s",
			configfilename, strerror(errno));
		return (-1);
	}

	if (cfyyparse() || cfyyerrorcount) {
		if (cfyyerrorcount) {
			cfyyerror("fatal parse failure: exiting (%d errors)",
				cfyyerrorcount);
		} else
			cfyyerror("fatal parse failure: exiting");
		return (-1);
	}

	return (cf_post_config());
}

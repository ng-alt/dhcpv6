/*	$Id: server6_lparse.l,v 1.1 2003/01/16 15:41:11 root Exp $	*/

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

/* Author: Elizabeth Kon, beth@us.ibm.com */

%option noyywrap
%{
#include <time.h> 
#include <string.h> 
#include <syslog.h>
#include <errno.h>
#include <linux/in6.h> 
#include "server6_addr.h"
#include "hash.h"


static int parser_i = 0, parser_rc, parsing_lease = 0;
extern struct hash_table **hash_anchors;
extern FILE *lease_file;
static struct server6_lease *lease_rec;
static struct client_if temp_iaid_key;
static int num_lines = 1;

%}
hexdigit	([0-9A-Fa-f])
hexpair		{hexdigit}{hexdigit}
addr1		{hexdigit}{1,4}":"({hexdigit}{1,4}":")*(":"{hexdigit}{1,4})+
addr2		{hexdigit}{1,4}(":"{hexdigit}{1,4})*"::"
addr3		({hexdigit}{1,4}":"){7}{hexdigit}{1,4}
addr		({addr1}|{addr2}|{addr3})
duid_id 	{hexpair}(:{hexpair})*

COLON		(:)
HEXCHAR		([0-9A-Fa-f])
NUMCHAR		([0-9A-Za-z])
LETTER		([A-Za-z])
HEXPAIR		{HEXCHAR}{2}
EIGHTHIPV6ADDR	({HEXCHAR}{1,4})
HEXNUM          (0x{HEXCHAR}{1,8})
NUMBER          ([0-9]+)
WHITESPACE      ([ \t]+)
LBRACE		("{")
RBRACE		("}")

%s LEASE
%s PREFIX_LEN
%s SDATE
%s PLIFE
%s VLIFE
%s IAID
%s DUIDLEN
%s DUID
%s LINKLOCAL
%s HOSTNAME
%s STATE
%s START

%%
^"lease" {parsing_lease = 1;
 	  lease_rec = (struct server6_lease *)
			malloc(sizeof(struct server6_lease));
	  if (!lease_rec) {
		dprintf(LOG_ERR, "Couldn't malloc lease");
		return (-1);
	  } 
	  BEGIN LEASE;}
{WHITESPACE}"start date:" {BEGIN SDATE;}
{WHITESPACE}"preferred lifetime:" {BEGIN PLIFE;}
{WHITESPACE}"valid lifetime:" {BEGIN VLIFE;}
{WHITESPACE}"IAID:" {BEGIN IAID;}
{WHITESPACE}"DUID string length:" {BEGIN DUIDLEN;}
{WHITESPACE}"DUID:" {BEGIN DUID;}
{WHITESPACE}"linklocal:" {BEGIN LINKLOCAL;}
{WHITESPACE}"hostname:" {BEGIN HOSTNAME;}
{WHITESPACE}"state:" {BEGIN STATE;}
{WHITESPACE}"(program use only: start date" {BEGIN START;}
^"\n" {;}
{WHITESPACE}   {;}

<LEASE>{addr} { if (inet_pton(AF_INET6, yytext, 
			&lease_rec->lease_addr) < 1) {
				dprintf(LOG_ERR, "invalid address"); 
				return (-1);
			}
	      }
<LEASE>{COLON}     {;} 
<LEASE>"/"     {BEGIN PREFIX_LEN;}
<PREFIX_LEN>{NUMBER}  {lease_rec->plen = (u_int8_t)atoi(yytext);}
<PREFIX_LEN>{LBRACE}  {;} 
<PREFIX_LEN>\n        {parser_i = 0; BEGIN INITIAL;}

<SDATE>\n      {BEGIN INITIAL;}
<SDATE>.       {;}

<PLIFE>{HEXNUM}          {lease_rec->preferlifetime = (u_int)strtoul(yytext,NULL,16);}
<PLIFE>.                 {;}
<PLIFE>[\n]              {BEGIN INITIAL;}

<VLIFE>{HEXNUM}          {lease_rec->validlifetime = (u_int)strtoul(yytext,NULL,16);}
<VLIFE>.                 {;}
<VLIFE>[\n]              {BEGIN INITIAL;}

<IAID>{HEXNUM}          {temp_iaid_key.client_iaid = (u_int)strtoul(yytext,NULL,16);}
<IAID>temporary         {temp_iaid_key.client_iatype = 1;}
<IAID>non-temporary     {temp_iaid_key.client_iatype = 0;}
<IAID>[\n]              {BEGIN INITIAL;}
<IAID>.      {;} 

<DUIDLEN>{NUMBER}    {temp_iaid_key.clientid.duid_len = (u_int)atoi(yytext);
                      strcpy(temp_iaid_key.clientid.duid_id,"");}
<DUIDLEN>.            {;}
<DUIDLEN>\n           {BEGIN INITIAL;}

<DUID>{duid_id}       {strcat(temp_iaid_key.clientid.duid_id, yytext);}
<DUID>;               {;} 
<DUID>\n              {BEGIN INITIAL;}
                        
<LINKLOCAL>{addr} {if (inet_pton(AF_INET6, yytext, &lease_rec->linklocal) < 1) {
				dprintf(LOG_ERR, "invalid linklocal address"); 
				return (-1);
		   }
		   parser_i = (++parser_i)%8;} 
<LINKLOCAL>{COLON}|";"      {;} 
<LINKLOCAL>\n               {parser_i = 0; BEGIN INITIAL;}

<HOSTNAME>{NUMCHAR}+  {lease_rec->hostname = strdup(yytext);}
<HOSTNAME>.       {;}
<HOSTNAME>\n      {BEGIN INITIAL;}

<STATE>{NUMBER}   {lease_rec->state = (u_int8_t)strtoul(yytext,NULL,16);}
<STATE>.          {;}
<STATE>\n         {BEGIN INITIAL;}

<START>{NUMBER}   {lease_rec->start_date = strtoul(yytext,NULL,0); parsing_lease = 0;}
<START>\n         {if (do_iaidaddr_hash(lease_rec, &temp_iaid_key) != 0)
			return (-1);
	           BEGIN INITIAL;} 
<START>.          {;}
<RBRACE>.	  {;}
\n		  {;}
%%

/* parsing_lease is for checking for partial lease in file, and causing sync so
that the partial lease is removed before any more leases are added beneath it.
*/
unsigned int 
parse_leases(void) 
{
	fseek(lease_file, 0,0);
        yyin = lease_file;
	temp_iaid_key.clientid.duid_id =(char *)malloc(MAX_DUID_LEN + 1);
	if (!temp_iaid_key.clientid.duid_id) {
		dprintf(LOG_ERR, "%s" "Couldn't malloc duid space", FNAME);
		return(-1);
	} 
        yylex();
	if (1 == parsing_lease) {
		sync_leases();
	}
	free(temp_iaid_key.clientid.duid_id);
	return 0;
}

unsigned int 
do_iaidaddr_hash(struct server6_lease *lease_rec, struct client_if *key)
{
	struct server6_cl_iaidaddr *iaidaddr;
	struct server6_lease *found_lease;
	iaidaddr = (struct server6_cl_iaidaddr *)hash_search(hash_anchors[HT_IAIDADDR], key); 
	if (iaidaddr){
		found_lease = hash_search(hash_anchors[HT_IPV6ADDR], lease_rec);
		if(found_lease) {
			if (hash_delete(hash_anchors[HT_IPV6ADDR], lease_rec) != 0) {
				dprintf(LOG_ERR, "%s" "hash delete failed", FNAME);
				return (-1);
			}
			TAILQ_REMOVE(&iaidaddr->ifaddr_list, found_lease, link);
			free(found_lease);
		} 
		lease_rec->iaidinfo = iaidaddr;
		TAILQ_INSERT_TAIL(&iaidaddr->ifaddr_list, lease_rec, link);
		if (hash_add(hash_anchors[HT_IPV6ADDR], &lease_rec->lease_addr, lease_rec) != 0)  {
			dprintf(LOG_ERR, "%s" "hash add failed", FNAME);
			return (-1);
		}
	} else {
		iaidaddr = (struct server6_cl_iaidaddr *)malloc(sizeof(struct server6_cl_iaidaddr));
	  	if (!iaidaddr) {
			dprintf(LOG_ERR, "%s" "failed to allocate memory", FNAME);
			return (-1);
	  	} 
		iaidaddr->client_info.clientid.duid_len = temp_iaid_key.clientid.duid_len;
		iaidaddr->client_info.clientid.duid_id = 
			(char *)malloc(temp_iaid_key.clientid.duid_len);
	  	if (!iaidaddr->client_info.clientid.duid_id) {
			dprintf(LOG_ERR, "%s" "failed to allocate memory", FNAME);
			return(-1);
	  	} 
		duidcpy(&iaidaddr->client_info.clientid, &temp_iaid_key.clientid);
		iaidaddr->client_info.client_iaid = temp_iaid_key.client_iaid;
		iaidaddr->client_info.client_iatype = temp_iaid_key.client_iatype;
		iaidaddr->timer = NULL;
		iaidaddr->evdata = NULL;
		TAILQ_INIT(&iaidaddr->ifaddr_list);
		lease_rec->iaidinfo = iaidaddr;
		TAILQ_INSERT_TAIL(&iaidaddr->ifaddr_list, lease_rec, link);
		if (hash_add(hash_anchors[HT_IPV6ADDR], &lease_rec->lease_addr, lease_rec) != 0) {
			dprintf(LOG_ERR, "%s" "hash add failed", FNAME);
			return (-1);
		}
	}
	return (0);
}

/*	$Id: server6_conf.c,v 1.2 2003/01/20 20:25:23 shirleyma Exp $	*/

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

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <linux/in6.h>
#include <sys/socket.h>
#include <net/if.h>
#include <openssl/md5.h>
#include <ifaddrs.h>
#include "server6_conf.h"

#define NMASK(n) htonl((1<<(n))-1)

static void get_random_bytes __P((u_int8_t *, int)); 
static void download_scope __P((struct scope *, struct scope *));
void printf_in6addr __P((struct in6_addr *));

void 
printf_in6addr(addr)
	struct in6_addr *addr;
{
	char addr_str[100];
	inet_ntop(AF_INET6, addr, addr_str, sizeof(struct in6_addr));
	printf("addr is %s\n", addr_str);
	return;
}


int 
ipv6addrcmp(addr1, addr2)
	struct in6_addr *addr1;
	struct in6_addr *addr2;
{
	int i;
	for (i = 0; i < 16; i++) {
		if (addr1->s6_addr[i] < addr2->s6_addr[i]) return (-1);
		else if (addr1->s6_addr[i] > addr2->s6_addr[i]) return 1;
	}
	return 0;
}


struct in6_addr 
*inc_ipv6addr(current)
	struct in6_addr *current;
{
	int i;
	for (i = 15; i >= 0; i--) {
		current->s6_addr[i]++;
		if (current->s6_addr[i] != 0x00) break;
	}
	return current;
}
			
struct v6addr
*getprefix(addr, len)
	struct in6_addr *addr;
	int len;
{
	int i, num_bytes;
	struct v6addr *prefix;
	prefix = (struct v6addr *)malloc(sizeof(*prefix));
	if (prefix == NULL) {
		dprintf(LOG_ERR, "fail to malloc memory", strerror(errno));
		return NULL;
	}
	memset(prefix, 0, sizeof(*prefix));
	prefix->plen = len;
	num_bytes = len / 8;
	for (i = 0; i < num_bytes; i++) {
		prefix->addr.s6_addr[i] = 0xFF;
	}
	prefix->addr.s6_addr[num_bytes] = 0xFF << 8 - len % 8 ;
	for (i = 0; i <= num_bytes; i++) {
		prefix->addr.s6_addr[i] &= addr->s6_addr[i];
	}
	for (i = num_bytes + 1; i < 16; i++) {
		prefix->addr.s6_addr[i] = 0x00;
	}
	return prefix;
}

static void
get_random_bytes(u_int8_t seed[], int num)
{
	int i;
	for (i = 0; i < num; i++)
		seed[i] = random();
	return;
}

int
prefixcmp(addr, prefix, len)
	struct in6_addr *addr;
	struct in6_addr *prefix;
	int len;
{
	int i, num_bytes;
	struct in6_addr mask;
	num_bytes = len / 8;
	for (i = 0; i < num_bytes; i++) {
		mask.s6_addr[i] = 0xFF;
	}
	mask.s6_addr[num_bytes] = 0xFF << 8 - len % 8 ;
	for (i = 0; i < num_bytes; i++) {
		if (addr->s6_addr[i] != prefix->s6_addr[i]) return -1;
	}
	if(addr->s6_addr[num_bytes] & mask.s6_addr[num_bytes] != 
	   prefix->s6_addr[num_bytes] & mask.s6_addr[num_bytes])
 		return -1;
	return 0;
}

int
get_numleases(currentpool, poolfile)
	struct pool_decl *currentpool;
       	char *poolfile;
{
	return 0;
}


struct scopelist
*push_double_list(current, scope)
	struct scopelist *current;
	struct scope *scope;
{
	struct scopelist *item;
	item = (struct scopelist *)malloc(sizeof(*item));
	if (item == NULL) {
		dprintf(LOG_ERR, "fail to allocate memory");
		return NULL;
	}
	memset(item, 0, sizeof(*item));
	item->scope = scope;
	if (current) {
		if (current->next) 
			current->next->prev = item;
		item->next = current->next;
		current->next = item;
	} else
		item->next = NULL;
	item->prev = current;
	current = item;
	return current;
}

struct scopelist
*pop_double_list(current)
       struct scopelist *current;	
{
	struct scopelist *temp;
	temp = current;
	/* current must not be NULL */
	if (current->next)
		current->next->prev = current->prev;
	if (current->prev) 
		current->prev->next = current->next;
	current = current->prev;
	temp->prev = NULL;
	temp->next = NULL;
	temp->scope = NULL;
	free(temp);
	return current;
}

void
post_config(root)
	struct rootgroup *root;
{
	struct interface *ifnetwork;
	struct link_decl *link;
	struct host_decl *host;
	struct v6addrseg *seg;
	struct scope *current;
	struct scope *up;
	
	if (root->group)
		download_scope(root->group, &root->scope);
	up = &root->scope;
	for (ifnetwork = root->iflist; ifnetwork; ifnetwork = ifnetwork->next) {
		if (ifnetwork->group)
			download_scope(ifnetwork->group, &ifnetwork->ifscope);
		current = &ifnetwork->ifscope;
		download_scope(up, current);
		up = &ifnetwork->ifscope;
		for (host = ifnetwork->hostlist; host; host = host->next) {
			if (host->group)
				download_scope(host->group, &host->hostscope);
			current = &host->hostscope;
			download_scope(up, current);
		}
			
	}
	for (ifnetwork = root->iflist; ifnetwork; ifnetwork = ifnetwork->next) {
		if (ifnetwork->group)
			download_scope(ifnetwork->group, &ifnetwork->ifscope);
		current = &ifnetwork->ifscope;
		download_scope(up, current);
		up = &ifnetwork->ifscope;
		for (link = ifnetwork->linklist; link; link = link->next) {
				if (link->group)
					download_scope(link->group, &link->linkscope);
				current = &link->linkscope;
				download_scope(up, current);
				up = &link->linkscope;
				for (seg = link->seglist; seg; seg = seg->next) {
					if (seg->pool) {
						if (seg->pool->group)
							download_scope(seg->pool->group, &seg->pool->poolscope);
						current = &seg->pool->poolscope;
						download_scope(up, current);
						memcpy(&seg->parainfo, current, sizeof(seg->parainfo));
					} else {
						memcpy(&seg->parainfo, up, sizeof(seg->parainfo));
					}
				}
			}
	}
	return;				
}

static void
download_scope(up, current)
	struct scope *up;
	struct scope *current;
{
	if (current->prefer_life_time == 0 && up->prefer_life_time != 0)
		current->prefer_life_time = up->prefer_life_time;	
	if (current->valid_life_time == 0 && up->valid_life_time != 0)
		current->valid_life_time = up->valid_life_time;
	if (current->renew_time == 0 && up->renew_time != 0)
		current->renew_time = up->renew_time;
	if (current->rebind_time == 0 && up->rebind_time != 0)
		current->rebind_time = up->rebind_time;
	if (current->server_pref == 0 && up->server_pref != 0)
		current->server_pref = up->server_pref;
	current->allow_flags |= up->allow_flags;
	current->send_flags |= up->send_flags;
	return;
}

int
get_linklocal(ifname, linklocal)
	char *ifname; 
	struct in6_addr *linklocal;
{	
	struct ifaddrs *ifa, *ifap;
	struct sockaddr *sd;
	if (getifaddrs(&ifap) < 0) {
		perror("getifaddrs");
		return -1;
	}
	/* ifa->ifa_addr is sockaddr_in6 */
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (!strcpy(ifa->ifa_name, ifname)) continue;
		sd = (struct sockaddr *)ifa->ifa_addr;
		if (sd->sa_family != AF_INET6) continue;
		if (!IN6_IS_ADDR_LINKLOCAL(&sd->sa_data[6])) continue;
		/* which linklocal do we want, if find many 
		 * from scope id??? sa_data[32]
		 * */
		memcpy(linklocal, &sd->sa_data[6], sizeof(*linklocal));
	}
	freeifaddrs(ifap);
	return 0;
}

int 
is_anycast(struct in6_addr *in, int plen)
{
	int wc;

	if (plen == 64) { /* assume EUI64 */
		/* doesn't cover none EUI64 */
		return in->s6_addr32[2] == htonl(0xFDFFFFFF) &&
			(in->s6_addr32[3] | htonl(0x7f)) ==
				(u_int32_t) ~0;
	}
	/* not EUI64 */
	if (plen > 121) 
		return 0;
	wc = plen / 32;
	if (plen) {
		if (in->s6_addr32[wc] != NMASK(32 - (plen%32)))
			return 0;
		wc++;
		
	}
	for (/*empty*/; wc < 2; wc++)
		if (in->s6_addr32[wc] != (u_int32_t) ~0)
			return 0;
	return (in->s6_addr32[3] | htonl(0x7f)) == (u_int32_t)~0;
}


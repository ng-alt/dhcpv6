/*	$Id: server6_addr.h,v 1.1.1.1 2003/01/16 15:41:11 root Exp $	*/

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

#ifndef __SERVER_ADDR_H_DEFINED
#define __SERVER_ADDR_H_DEFINED 

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <net/if.h>
#include "hash.h"
#include "queue.h"
#include "server6_conf.h"

#define PATH_DHCPv6S_LEASE "/var/db/dhcpv6.leases"
#define PATH_DHCPv6S_TEMPLEASE "/var/db/dhcpv6.leases~"

enum hash_type{HT_IPV6ADDR = 0, HT_IAIDADDR};
#define HASH_TABLE_COUNT 2
#define MAX_DUID_LEN 130

typedef enum { ADDR6S_ACTIVE, ADDR6S_EXPIRED,
	       ADDR6S_ABANDONED} addr6state_t;

struct client_if {
        struct duid clientid;
        u_int32_t client_iaid;
	u_int8_t client_iatype;
};

struct server6_cl_iaidaddr {
	struct client_if client_info;
	addr6state_t state;
	struct dhcp6_timer *timer;
	struct dhcp6_eventdata *evdata;

	/* list of interface addresses */
	TAILQ_HEAD(, server6_lease) ifaddr_list;
};

struct  server6_lease {
	TAILQ_ENTRY(server6_lease) link;
	struct server6_cl_iaidaddr *iaidinfo;
        struct in6_addr lease_addr;
	int plen;
	time_t start_date;
	u_int32_t preferlifetime; /* value at start_date */
	u_int32_t validlifetime;  /* value at start_date */
	addr6state_t state;
	/* address assigned on the interface */
	struct dhcp6_timer *timer;
	struct dhcp6_eventdata *evdata;
	struct in6_addr linklocal;
	char* hostname;
};

unsigned int iaid_hash __P((void *));
unsigned int addr_hash __P((void *));
void * addr_findkey(void *data);
int addr_key_compare(void *data, void * key);
unsigned int addr_hashfunc(void *key);
void * iaid_findkey(void *data);
int iaid_key_compare(void *data, void * key);
unsigned int iaid_hashfunc(void *key);
unsigned int parse_leases(void);
unsigned int do_ipv6addr_hash(struct server6_lease *lease_rec);
unsigned int do_iaidaddr_hash(struct server6_lease *lease_rec, struct client_if *key);
struct server6_lease * server6_find_iaidlease(struct server6_cl_iaidaddr *iaidaddr, 
		struct server6_lease *lease_rec);
int write_lease(struct server6_lease *lease_ptr, FILE *file);
int sync_leases(void);

extern struct link_decl *server6_allocate_link __P((struct rootgroup *));
extern int server6_create_addrlist __P((int, struct link_decl *, 
			struct dhcp6_optinfo *, struct dhcp6_optinfo *));
extern void server6_iaidaddr_init __P((void));
extern int server6_delete_iaidaddr __P((struct dhcp6_optinfo *));
extern int server6_add_iaidaddr __P((struct dhcp6_optinfo *));
extern int server6_update_iaidaddr __P((struct dhcp6_optinfo *));
extern struct host_decl *find_hostdecl __P((struct duid *, u_int32_t, struct host_decl *));

#endif

/*	$Id: client6_addr.h,v 1.3 2003/02/12 21:51:18 shirleyma Exp $	*/
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

#ifndef __CLIENT6_ADDR_H_DEFINED
#define __CLIENT6_ADDR_H_DEFINED

#define LEASE_FILENAME_SIZE

typedef enum { ADDR6S_ACTIVE, ADDR6S_RENEW,
	       ADDR6S_REBIND, ADDR6S_EXPIRED,
	       ADDR6S_INVALID } addr6state_t;

typedef enum { IAID6S_ACTIVE, IAID6S_RENEW,
	       IAID6S_REBIND, IAID6S_EXPIRED,
	       IAID6S_INVALID } iaid6state_t;

typedef enum { IFADDRCONF_ADD, IFADDRCONF_REMOVE } ifaddrconf_cmd_t;

struct client6_iaidaddr {
	TAILQ_ENTRY(client6_iaidaddr) link;
	struct dhcp6_if *ifp;
	time_t start_date;
	struct duid clientid;
	struct duid serverid;
	struct dhcp6_iaid_info iaidinfo;
	iaid6state_t state;
	struct dhcp6_timer *timer;
	struct dhcp6_eventdata *evdata;

	/* list of client leases */
	TAILQ_HEAD(, client6_lease) ifaddr_list;
};

struct client6_lease {
	TAILQ_ENTRY(client6_lease) link;
	struct client6_iaidaddr *iaidaddr;
	time_t start_date;
	/* address assigned on the interface */
	struct dhcp6_addr dhcp6addr;
	addr6state_t state;
	struct dhcp6_timer *timer;
};

extern void client6_init_iaidaddr __P((void));
extern void client6_remove_iaidaddr __P((void));
extern int client6_add_iaidaddr __P((struct dhcp6_if *, struct dhcp6_optinfo *,
			       struct duid *));
extern int client6_update_iaidaddr __P((struct dhcp6_event *, struct dhcp6_optinfo *,
				  struct duid *));
extern int client6_ifaddrconf __P((ifaddrconf_cmd_t, struct dhcp6_addr *));
#endif

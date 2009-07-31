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

#ifndef __SERVER6_CONF_H_DEFINED
#define __SERVER6_CONF_H_DEFINED

#define DEFAULT_PREFERRED_LIFE_TIME 360000
#define DEFAULT_VALID_LIFE_TIME 720000

/* provide common paramters within scopes */
typedef struct _scope_t {
    gint32 prefer_life_time;
    gint32 valid_life_time;
    gint32 renew_time;
    gint32 rebind_time;
    gint32 irt;
    gint8 server_pref;
    guint8 send_flags;
    guint8 allow_flags;
    dns_info_t dnsinfo;
} scope_t;

/* interface network declaration */
/* interface declaration is used to inform DHCPv6 server that the links */
/* and pool declared within it are connected to the same network segment */
typedef struct _server_interface_t {
    gchar name[IFNAMSIZ];
    hardware_t hw_address;
    struct in6_addr primary_v6addr;
    struct in6_addr linklocal;
    GSList *linklist;
    GSList *hostlist;
    scope_t ifscope;
    scope_t *group;
} server_interface_t;

/* host declaration provides information about a particular DHCPv6 client */
typedef struct _host_decl_t {
    gchar name[IFNAMSIZ];
    duid_t cid;
    dhcp6_iaid_info_t iaidinfo;
    GSList *addrlist;
    GSList *prefixlist;
    server_interface_t *network;
    scope_t hostscope;
    scope_t *group;
} host_decl_t;

typedef struct _rootgroup_t {
    scope_t scope;
    scope_t *group;
    GSList *iflist;
} rootgroup_t;

/* FIXME: remove this global */
rootgroup_t *globalgroup;

typedef struct _v6addr_t {
    struct in6_addr addr;
    guint8 plen;
} v6addr_t;

/* link declaration */
/* link declaration is used to provide the DHCPv6 server with enough   */
/* information to determin whether a particular IPv6 addresses is on the */

/* link */
typedef struct _link_decl_t {
    gchar name[IFNAMSIZ];
    GSList *relaylist;
    GSList *seglist;
    GSList *prefixlist;
    GSList *poollist;
    server_interface_t *network;
    scope_t linkscope;
    scope_t *group;
} link_decl_t;

/* The pool declaration is used to declare an address pool from which IPv6 */
/* address can be allocated, with its own permit to control client access  */
/* and its own scope in which you can declare pool-specific parameter*/
typedef struct _pool_decl_t {
    server_interface_t *network;
    link_decl_t *link;
    scope_t poolscope;
    scope_t *group;
} pool_decl_t;

typedef struct _v6addrseg_t {
    link_decl_t *link;
    pool_decl_t *pool;
    struct in6_addr min;
    struct in6_addr max;
    struct in6_addr free;
    v6addr_t prefix;
    struct lease *active;
    struct lease *expired;
    struct lease *abandoned;
    scope_t parainfo;
} v6addrseg_t;

typedef struct _v6prefix_t {
    link_decl_t *link;
    pool_decl_t *pool;
    v6addr_t prefix;
    scope_t parainfo;
} v6prefix_t;

/* host declaration */

gint is_anycast(struct in6_addr *, gint);
void post_config(rootgroup_t *);
gint sfparse(const gchar *);
gint ipv6addrcmp(struct in6_addr *, struct in6_addr *);
v6addr_t *getprefix(struct in6_addr *, gint);
struct in6_addr *inc_ipv6addr(struct in6_addr *);
gint get_primary_ipv6addr(const gchar *);

#endif /* __SERVER6_CONF_H_DEFINED */

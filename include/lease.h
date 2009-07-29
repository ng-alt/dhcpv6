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

#ifndef __LEASE_H_DEFINED
#define __LEASE_H_DEFINED

#define LEASE_FILENAME_SIZE
#define ADDR_UPDATE   0
#define ADDR_REMOVE   1
#define ADDR_VALIDATE 2
#define ADDR_ABANDON  3

#define PATH_SERVER6_LEASE DB_FILE_PATH"/server6.leases"
#define PATH_CLIENT6_LEASE DB_FILE_PATH"/client6.leases"

#define HASH_TABLE_COUNT 4

#define PREFIX_LEN_NOTINRA 64
#define MAX_FILE_SIZE 512*1024

typedef enum {
    IFADDRCONF_ADD,
    IFADDRCONF_REMOVE
} ifaddrconf_cmd_t;

struct dhcp6_iaidaddr client6_iaidaddr;
FILE *server6_lease_file;
FILE *client6_lease_file;
FILE *lease_file;
FILE *sync_file;

struct client6_if {
    iatype_t type;
    struct dhcp6_iaid_info iaidinfo;
    struct duid clientid;
    struct duid serverid;
};

struct dhcp6_iaidaddr {
    TAILQ_ENTRY(dhcp6_iaidaddr) link;
    struct client6_if client6_info;
    time_t start_date;
    state_t state;
    struct dhcp6_if *ifp;
    struct dhcp6_timer *timer;
    /* list of client leases */
    GSList *lease_list;
};

guint32 do_hash(const void *, guint8);
gint get_linklocal(const gchar *, struct in6_addr *);
void dhcp6_init_iaidaddr(void);
gint dhcp6_remove_iaidaddr(struct dhcp6_iaidaddr *);
gint dhcp6_add_iaidaddr(struct dhcp6_optinfo *, ia_t *);
gint dhcp6_update_iaidaddr(struct dhcp6_optinfo *, ia_t *,
                           gint);
struct dhcp6_timer *dhcp6_iaidaddr_timo(void *);
struct dhcp6_timer *dhcp6_lease_timo(void *);
guint32 get_min_preferlifetime(struct dhcp6_iaidaddr *);
guint32 get_max_validlifetime(struct dhcp6_iaidaddr *);
struct dhcp6_iaidaddr *dhcp6_find_iaidaddr(struct duid *, guint32,
                                           iatype_t);
dhcp6_lease_t *dhcp6_find_lease(struct dhcp6_iaidaddr *, struct dhcp6_addr *);
gint dhcp6_validate_bindings(GSList *, struct dhcp6_iaidaddr *, gint);
gint get_iaid(const gchar *, const struct iaid_table *, gint);
gint create_iaid(struct iaid_table *, gint);
FILE *init_leases(const gchar *);
void lease_parse(FILE *);
gint do_iaidaddr_hash(dhcp6_lease_t *, struct client6_if *);
gint write_lease(const dhcp6_lease_t *, FILE *);
FILE *sync_leases(FILE *, const gchar *, gchar *);
struct dhcp6_timer *syncfile_timo(void *);
guint addr_hash(const void *);
guint iaid_hash(const void *);
void *iaid_findkey(const void *);
gint iaid_key_compare(const void *, const void *);
void *lease_findkey(const void *);
gint lease_key_compare(const void *, const void *);
void *v6addr_findkey(const void *);
gint v6addr_key_compare(const void *, const void *);
gint client6_ifaddrconf(ifaddrconf_cmd_t, struct dhcp6_addr *);
gint dhcp6_get_prefixlen(struct in6_addr *, struct dhcp6_if *);
gint prefixcmp(struct in6_addr *, struct in6_addr *, gint);
gint addr_on_addrlist(GSList *, struct dhcp6_addr *);
gint dhcp6_create_prefixlist(ia_t *, ia_t *, const struct dhcp6_iaidaddr *,
                             const struct link_decl *, guint16 *);
gint dhcp6_create_addrlist(ia_t *, ia_t *, const struct dhcp6_iaidaddr *,
                           const struct link_decl *, guint16 *);
gint dad_parse(const gchar *, GSList *);

#endif /* __LEASE_H_DEFINED */

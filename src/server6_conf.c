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

#include "config.h"

#include <string.h>
#include <syslog.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>

#include <glib.h>

#include "duid.h"
#include "dhcp6.h"
#include "confdata.h"
#include "common.h"
#include "server6_conf.h"

#define NMASK(n) htonl((1<<(n))-1)

/* BEGIN STATIC FUNCTIONS */

static void _download_scope(scope_t *up, scope_t *current) {
    if (current->prefer_life_time == 0 && up->prefer_life_time != 0) {
        current->prefer_life_time = up->prefer_life_time;
    }

    if (current->valid_life_time == 0 && up->valid_life_time != 0) {
        current->valid_life_time = up->valid_life_time;
    }

    if (current->renew_time == 0 && up->renew_time != 0) {
        current->renew_time = up->renew_time;
    }

    if (current->rebind_time == 0 && up->rebind_time != 0) {
        current->rebind_time = up->rebind_time;
    }

    if (current->renew_time > current->rebind_time) {
        g_error("dhcpv6 server defines T1 > T2");
        exit(1);
    }

    if (current->irt == 0 && up->irt != 0) {
        current->irt = up->irt;
    }

    if (current->server_pref == 0 ||
        current->server_pref == DH6OPT_PREF_UNDEF) {
        if (up->server_pref != 0) {
            current->server_pref = up->server_pref;
        } else {
            current->server_pref = DH6OPT_PREF_UNDEF;
        }
    }

    current->allow_flags |= up->allow_flags;
    current->send_flags |= up->send_flags;

    if (!g_slist_length(current->dnsinfo.servers)) {
        current->dnsinfo.servers = g_slist_copy(up->dnsinfo.servers);
    }

    if (!g_slist_length(current->dnsinfo.domains)) {
        current->dnsinfo.domains = up->dnsinfo.domains;
    }

    return;
}

/* END STATIC FUNCTIONS */

gint ipv6addrcmp(struct in6_addr *addr1, struct in6_addr *addr2) {
    gint i;

    for (i = 0; i < 16; i++) {
        if (addr1->s6_addr[i] < addr2->s6_addr[i]) {
            return -1;
        } else if (addr1->s6_addr[i] > addr2->s6_addr[i]) {
            return 1;
        }
    }

    return 0;
}

struct in6_addr *inc_ipv6addr(struct in6_addr *current) {
    gint i;

    for (i = 15; i >= 0; i--) {
        current->s6_addr[i]++;

        if (current->s6_addr[i] != 0x00) {
            break;
        }
    }

    return current;
}

v6addr_t *getprefix(struct in6_addr *addr, gint len) {
    gint i, num_bytes;
    v6addr_t *prefix = NULL;

    prefix = (v6addr_t *) g_malloc0(sizeof(*prefix));
    if (prefix == NULL) {
        g_error("%s: failed to allocate memory", __func__);
        return NULL;
    }

    prefix->plen = len;
    num_bytes = len / 8;

    for (i = 0; i < num_bytes; i++) {
        prefix->addr.s6_addr[i] = 0xFF;
    }

    prefix->addr.s6_addr[num_bytes] = (0xFF << 8) - len % 8;

    for (i = 0; i <= num_bytes; i++) {
        prefix->addr.s6_addr[i] &= addr->s6_addr[i];
    }

    for (i = num_bytes + 1; i < 16; i++) {
        prefix->addr.s6_addr[i] = 0x00;
    }

    return prefix;
}

gint get_numleases(pool_decl_t *currentpool, gchar *poolfile) {
    return 0;
}

void post_config(rootgroup_t *root) {
    server_interface_t *ifnetwork = NULL;
    link_decl_t *link = NULL;
    host_decl_t *host = NULL;
    v6addrseg_t *seg = NULL;
    v6prefix_t *prefix6 = NULL;
    scope_t *current = NULL;
    scope_t *up = NULL;
    GSList *iterator = NULL, *link_iterator = NULL, *seg_iterator = NULL;
    GSList *prefix_iterator = NULL, *host_iterator;

    if (root->group) {
        _download_scope(root->group, &root->scope);
    }

    up = &root->scope;

    /* XXX: check the physical interfaces for the server */
    iterator = root->iflist;
    while (iterator) {
        ifnetwork = (server_interface_t *) iterator->data;

        if (ifnetwork->group) {
            _download_scope(ifnetwork->group, &ifnetwork->ifscope);
        }

        current = &ifnetwork->ifscope;
        _download_scope(up, current);
        up = &ifnetwork->ifscope;

        host_iterator = ifnetwork->hostlist;
        while (host_iterator) {
            host = (host_decl_t *) host_iterator->data;

            if (host->group) {
                _download_scope(host->group, &host->hostscope);
            }

            current = &host->hostscope;
            _download_scope(up, current);

            host_iterator = g_slist_next(host_iterator);
        }

        iterator = g_slist_next(iterator);
    }

    iterator = root->iflist;
    while (iterator) {
        ifnetwork = (server_interface_t *) iterator->data;

        if (ifnetwork->group) {
            _download_scope(ifnetwork->group, &ifnetwork->ifscope);
        }

        current = &ifnetwork->ifscope;
        _download_scope(up, current);
        up = &ifnetwork->ifscope;

        /* XXX: check host */
        link_iterator = ifnetwork->linklist;
        while (link_iterator) {
            link = (link_decl_t *) link_iterator->data;

            if (link->group) {
                _download_scope(link->group, &link->linkscope);
            }

            current = &link->linkscope;
            _download_scope(up, current);
            up = &link->linkscope;
            seg_iterator = link->seglist;

            while (seg_iterator) {
                seg = (v6addrseg_t *) seg_iterator->data;

                if (seg->pool) {
                    if (seg->pool->group) {
                        _download_scope(seg->pool->group,
                                        &seg->pool->poolscope);
                    }

                    current = &seg->pool->poolscope;
                    _download_scope(up, current);

                    if (current->prefer_life_time != 0 &&
                        current->valid_life_time != 0 &&
                        current->prefer_life_time >
                        current->valid_life_time) {
                        g_error("%s: preferlife time is greater than "
                                "validlife time", __func__);
                        exit(1);
                    }

                    memcpy(&seg->parainfo, current, sizeof(seg->parainfo));
                } else {
                    memcpy(&seg->parainfo, up, sizeof(seg->parainfo));
                }

                seg_iterator = g_slist_next(seg_iterator);
            }

            prefix_iterator = link->prefixlist;
            while (prefix_iterator) {
                prefix6 = (v6prefix_t *) prefix_iterator->data;

                if (prefix6->pool) {
                    if (prefix6->pool->group) {
                        _download_scope(prefix6->pool->group,
                                        &prefix6->pool->poolscope);
                    }

                    current = &prefix6->pool->poolscope;
                    _download_scope(up, current);

                    if (current->prefer_life_time != 0 &&
                        current->valid_life_time != 0 &&
                        current->prefer_life_time >
                        current->valid_life_time) {
                        g_error("%s: preferlife time is greater than "
                                "validlife time", __func__);
                        exit(1);
                    }

                    memcpy(&prefix6->parainfo, current,
                           sizeof(prefix6->parainfo));
                } else {
                    memcpy(&prefix6->parainfo, up, sizeof(prefix6->parainfo));
                }

                prefix_iterator = g_slist_next(prefix_iterator);
            }

            link_iterator = g_slist_next(link_iterator);
        }

        iterator = g_slist_next(iterator);
    }

    return;
}

gint is_anycast(struct in6_addr *in, gint plen) {
    gint wc;

    if (plen == 64) {           /* assume EUI64 */
        /* doesn't cover none EUI64 */
        return in->s6_addr32[2] == htonl(0xFDFFFFFF) &&
            (in->s6_addr32[3] | htonl(0x7f)) == (guint32) ~ 0;
    }

    /* not EUI64 */
    if (plen > 121) {
        return 0;
    }

    wc = plen / 32;
    if (plen) {
        if (in->s6_addr32[wc] != NMASK(32 - (plen % 32))) {
            return 0;
        }

        wc++;
    }

    for ( /* empty */ ; wc < 2; wc++) {
        if (in->s6_addr32[wc] != (guint32) ~ 0) {
            return 0;
        }
    }

    return (in->s6_addr32[3] | htonl(0x7f)) == (guint32) ~ 0;
}

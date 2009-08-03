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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <ifaddrs.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# include <time.h>
#endif

#include <glib.h>

#include "lease.h"

extern dhcp6_iaidaddr_t client6_iaidaddr;
extern FILE *server6_lease_file;
extern gchar *server6_lease_temp;
extern FILE *client6_lease_file;
extern gchar *client6_lease_temp;

GHashTable *host_addr_hash_table = NULL;
GHashTable *lease_hash_table = NULL;
GHashTable *server6_hash_table = NULL;

/* BEGIN STATIC FUNCTIONS */

static gint _init_lease_hashes(void) {
    host_addr_hash_table = g_hash_table_new(NULL, NULL);
    if (!host_addr_hash_table) {
        g_error("%s: Couldn't create hash table", __func__);
        return -1;
    }

    lease_hash_table = g_hash_table_new(NULL, NULL);
    if (!lease_hash_table) {
        g_error("%s: Couldn't create hash table", __func__);
        return -1;
    }

    server6_hash_table = g_hash_table_new(NULL, NULL);
    if (!server6_hash_table) {
        g_error("%s: Couldn't create hash table", __func__);
        return -1;
    }

    return 0;
}

static void _sync_lease(gpointer key, gpointer value, gpointer user_data) {
    dhcp6_lease_t *lease = (dhcp6_lease_t *) value;
    FILE *sync_file = (FILE *) user_data;

    if (write_lease(lease, sync_file) < 0) {
        g_error("%s: write lease failed", __func__);
    }

    return;
}

/* END STATIC FUNCTIONS */

gint write_lease(const dhcp6_lease_t *lease_ptr, FILE *file) {
    struct tm brokendown_time;
    gchar addr_str[64];

    if ((inet_ntop(AF_INET6, &lease_ptr->lease_addr.addr,
                   addr_str, sizeof(addr_str))) == 0) {
        g_debug("%s: inet_ntop %s", __func__, strerror(errno));
        return -1;
    }

    gmtime_r(&lease_ptr->start_date, &brokendown_time);
    fprintf(file, "lease %s/%d { \n", addr_str, lease_ptr->lease_addr.plen);
    fprintf(file, "\t DUID: %s;\n",
            duidstr(&lease_ptr->iaidaddr->client6_info.clientid));

    if (dhcp6_mode == DHCP6_MODE_CLIENT) {
        fprintf(file, "\t SDUID: %s;\n",
                duidstr(&lease_ptr->iaidaddr->client6_info.serverid));
    }

    fprintf(file, "\t IAID: %u ",
            lease_ptr->iaidaddr->client6_info.iaidinfo.iaid);
    fprintf(file, "\t type: %d;\n", lease_ptr->iaidaddr->client6_info.type);
    fprintf(file, "\t RenewTime: %u;\n",
            lease_ptr->iaidaddr->client6_info.iaidinfo.renewtime);
    fprintf(file, "\t RebindTime: %u;\n",
            lease_ptr->iaidaddr->client6_info.iaidinfo.rebindtime);

    if (!IN6_IS_ADDR_UNSPECIFIED(&lease_ptr->linklocal)) {
        if ((inet_ntop(AF_INET6, &lease_ptr->linklocal, addr_str,
                       sizeof(struct in6_addr))) == 0) {
            g_debug("%s: inet_ntop %s", __func__, strerror(errno));
            return -1;
        }

        fprintf(file, "\t linklocal: %s;\n", addr_str);
    }

    fprintf(file, "\t state: %d;\n", lease_ptr->state);

    if (lease_ptr->hostname != NULL) {
        fprintf(file, "\t hostname: %s;\n", lease_ptr->hostname);
    }

    fprintf(file, "\t (start_date: %d %d/%d/%d %d:%d:%d UTC);\n",
            brokendown_time.tm_wday, brokendown_time.tm_year + 1900,
            brokendown_time.tm_mon + 1, brokendown_time.tm_mday,
            brokendown_time.tm_hour, brokendown_time.tm_min,
            brokendown_time.tm_sec);
    fprintf(file, "\t start date: %lu;\n", lease_ptr->start_date);
    fprintf(file, "\t PreferredLifeTime: %u;\n",
            lease_ptr->lease_addr.preferlifetime);
    fprintf(file, "\t ValidLifeTime: %u;\n",
            lease_ptr->lease_addr.validlifetime);
    fprintf(file, "}\n");

    if (fflush(file) == EOF) {
        g_message("%s: write lease fflush failed %s",
                  __func__, strerror(errno));
        return -1;
    }

    if (fsync(fileno(file)) < 0) {
        g_message("%s: write lease fsync failed %s",
                  __func__, strerror(errno));
        return -1;
    }

    return 0;
}

FILE *sync_leases(FILE * file, const gchar *original, gchar *template) {
    gint fd;
    dhcp6_lease_t *lease = NULL;
    GSList *iterator = client6_iaidaddr.lease_list;

    fd = mkstemp(template);

    if (fd < 0 || (sync_file = fdopen(fd, "w")) == NULL) {
        g_error("%s: could not open sync file", __func__);
        return NULL;
    }

    if (dhcp6_mode == DHCP6_MODE_SERVER) {
        g_hash_table_foreach(lease_hash_table, _sync_lease, sync_file);
    } else if (dhcp6_mode == DHCP6_MODE_CLIENT) {
        while (iterator) {
            lease = (dhcp6_lease_t *) iterator->data;

            if (write_lease(lease, sync_file) < 0) {
                g_error("%s: write lease failed", __func__);
            }

            iterator = g_slist_next(iterator);
        }
    }

    fclose(sync_file);
    fclose(file);

    if (rename(template, original) < 0) {
        g_error("%s: Could not rename sync file", __func__);
        return NULL;
    }

    if ((file = fopen(original, "a+")) == NULL) {
        g_error("%s: could not open sync file", __func__);
        return NULL;
    }

    return file;
}

dhcp6_timer_t *syncfile_timo(void *arg) {
    /* XXX: ToDo */
    return NULL;
}

FILE *init_leases(const gchar *name) {
    FILE *file;
    struct stat stbuf;

    if (name != NULL) {
        file = fopen(name, "a+");
    } else {
        g_error("%s: no lease file specified", __func__);
        return NULL;
    }

    if (!file) {
        g_error("%s: could not open lease file", __func__);
        return NULL;
    }

    if (stat(name, &stbuf)) {
        g_error("%s: could not stat lease file", __func__);
        return NULL;
    }

    if (_init_lease_hashes() != 0) {
        g_error("%s: Could not initialize hash arrays", __func__);
        return NULL;
    }

    if (stbuf.st_size > 0) {
        lease_parse(file);
    }

    return file;
}

gint prefixcmp(struct in6_addr *addr, struct in6_addr *prefix, gint len) {
    gint i, num_bytes;
    struct in6_addr mask;

    num_bytes = len / 8;

    for (i = 0; i < num_bytes; i++) {
        mask.s6_addr[i] = 0xFF;
    }

    mask.s6_addr[num_bytes] = 0xFF << (8 - len % 8);

    for (i = 0; i < num_bytes; i++) {
        if (addr->s6_addr[i] != prefix->s6_addr[i]) {
            return -1;
        }
    }

    if ((addr->s6_addr[num_bytes] & mask.s6_addr[num_bytes]) !=
        (prefix->s6_addr[num_bytes] & mask.s6_addr[num_bytes])) {
        return -1;
    }

    return 0;
}

gint get_linklocal(const gchar *ifname, struct in6_addr *linklocal) {
#if defined(__linux__)
    struct ifaddrs *ifa = 0, *ifap = 0;
    struct sockaddr *sd = 0;

    if (getifaddrs(&ifap) < 0) {
        g_error("getifaddrs error");
        return -1;
    }

    /* ifa->ifa_addr is sockaddr_in6 */
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (strcmp(ifa->ifa_name, ifname)) {
            continue;
        }

        sd = (struct sockaddr *) ifa->ifa_addr;

        if (!sd || sd->sa_family != AF_INET6) {
            continue;
        }

        if (!IN6_IS_ADDR_LINKLOCAL(&sd->sa_data[6])) {
            continue;
        }

        /* which linklocal do we want, if find many from scope id???
         * sa_data[32] */
        memcpy(linklocal, &sd->sa_data[6], sizeof(*linklocal));
        break;
    }

    freeifaddrs(ifap);
    return 0;
#else
    return -1;
#endif
}

gint dhcp6_get_prefixlen(struct in6_addr *addr, dhcp6_if_t *ifp) {
    ra_info_t *rainfo = NULL;
    GSList *iterator = ifp->ralist;

    while (iterator) {
        rainfo = (ra_info_t *) iterator->data;

        if (prefixcmp(addr, &rainfo->prefix, rainfo->plen) == 0) {
            return rainfo->plen;
        }

        iterator = g_slist_next(iterator);
    }

    return PREFIX_LEN_NOTINRA;
}

gint addr_on_addrlist(GSList *addrlist, dhcp6_addr_t *addr6) {
    dhcp6_value_t *lv = NULL;
    GSList *iterator = addrlist;

    if (!g_slist_length(iterator)) {
        return 0;
    }

    while (iterator) {
        lv = (dhcp6_value_t *) iterator->data;

        if (IN6_ARE_ADDR_EQUAL(&lv->val_dhcp6addr.addr, &addr6->addr)) {
            if ((lv->val_dhcp6addr.type != IAPD) ||
                ((lv->val_dhcp6addr.type == IAPD) &&
                 (lv->val_dhcp6addr.plen == addr6->plen))) {
                return 1;
            }
        }

        iterator = g_slist_next(iterator);
    }

    return 0;
}

guint32 get_min_preferlifetime(dhcp6_iaidaddr_t *sp) {
    dhcp6_lease_t *lease = NULL;
    guint32 min;
    GSList *iterator = sp->lease_list;

    if (!g_slist_length(sp->lease_list)) {
        return 0;
    }

    lease = (dhcp6_lease_t *) iterator->data;
    min = lease->lease_addr.preferlifetime;

    while ((iterator = g_slist_next(iterator)) != NULL) {
        lease = (dhcp6_lease_t *) iterator->data;
        min = MIN(min, lease->lease_addr.preferlifetime);
    }

    return min;
}

guint32 get_max_validlifetime(dhcp6_iaidaddr_t *sp) {
    dhcp6_lease_t *lease = NULL;
    guint32 max;
    GSList *iterator = sp->lease_list;

    if (!g_slist_length(sp->lease_list)) {
        return 0;
    }

    lease = (dhcp6_lease_t *) iterator->data;
    max = lease->lease_addr.preferlifetime;

    while ((iterator = g_slist_next(iterator)) != NULL) {
        lease = (dhcp6_lease_t *) iterator->data;
        max = MAX(max, lease->lease_addr.preferlifetime);
    }

    return max;
}

dhcp6_lease_t *dhcp6_find_lease(dhcp6_iaidaddr_t *iaidaddr,
                                dhcp6_addr_t *ifaddr) {
    dhcp6_lease_t *lease;
    GSList *iterator = iaidaddr->lease_list;

    if (!g_slist_length(iterator)) {
        return NULL;
    }

    while (iterator) {
        lease = (dhcp6_lease_t *) iterator->data;

        g_debug("%s: request address is %s/%d ", __func__,
                in6addr2str(&ifaddr->addr, 0), ifaddr->plen);
        g_debug("%s: lease address is %s/%d ", __func__,
                in6addr2str(&lease->lease_addr.addr, 0), ifaddr->plen);

        if (IN6_ARE_ADDR_EQUAL(&lease->lease_addr.addr, &ifaddr->addr)) {
            if (ifaddr->type == IAPD &&
                lease->lease_addr.plen == ifaddr->plen) {
                return lease;
            } else if (ifaddr->type == IANA || ifaddr->type == IATA) {
                return lease;
            }
        }

        iterator = g_slist_next(iterator);
    }

    return NULL;
}

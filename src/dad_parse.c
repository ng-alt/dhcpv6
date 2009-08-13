/*
 * dad_parse.c
 * Reads current interface state from /proc/net/if_inet6 and does things.
 *
 * Copyright (C) 2008  Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author(s): David Cantrell <dcantrell@redhat.com>
 */

/*
 * (Adapted from dad_token.l, which is BSD licensed code from IBM.)
 *
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include "dad_parse.h"

extern dhcp6_if_t *dhcp6_if;

gint dad_parse(const gchar *file, GSList *dad_list) {
    gint i = 0;
    gint len = 0;
    gint ret = 0;
    FILE *fp = NULL;
    gchar buf[55];               /* max line length in /proc/net/if_inet6 */
    gchar addrbuf[64];
    struct in6_addr addr6;
    ifproc_info_t *ifinfo = NULL;

    if (file == NULL) {
        g_error("dad_parse: NULL filename");
        return -1;
    }

    memset(&buf, '\0', sizeof(buf));
    memset(&addr6, 0, sizeof(addr6));

    if ((fp = fopen(file, "r")) == NULL) {
        if (errno == ENOENT) {
            return 0;
        }

        g_error("dad_parse: fopen(%s): %s", file, strerror(errno));
        return -1;
    }

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        gchar **tokens = g_strsplit_set(buf, " \n", -1);
        gchar **token = tokens;

        /* read address */
        if (*token == NULL) {
            g_strfreev(tokens);
            continue;
        }

        len = 0;

        for (i = 0; i < 32; i += 4) {
            gchar *tokentmp = *token;
            strncpy(addrbuf + len, &tokentmp[i], 4);
            len += 4;

            if (i < 28) {
                g_stpcpy(addrbuf + len, ":");
                len += 1;
            } else {
                g_stpcpy(addrbuf + len, "\0");
            }
        }

        if (inet_pton(AF_INET6, addrbuf, &addr6) < 1) {
            g_error("failed to parse %s from %s", addrbuf, file);
            abort();
        }

        if ((ifinfo = g_malloc0(sizeof(*ifinfo))) == NULL) {
            g_error("memory allocation failure");
            abort();
        }

        memcpy(&ifinfo->addr, &addr6, sizeof(ifinfo->addr));
        token++;

        /* read the index */
        if (*token == NULL) {
            g_strfreev(tokens);
            continue;
        }

        ifinfo->index = strtol(*token, NULL, 16);
        if ((errno == EINVAL) || (errno == ERANGE)) {
            g_error("error reading index from %s", file);
            g_strfreev(tokens);
            goto fail;
        }

        token++;

        /* read the prefix length */
        if (*token == NULL) {
            g_strfreev(tokens);
            continue;
        }

        ifinfo->plen = strtol(*token, NULL, 16);
        if ((errno == EINVAL) || (errno == ERANGE)) {
            g_error("error reading prefix length from %s", file);
            g_strfreev(tokens);
            goto fail;
        }

        token++;

        /* read the scope */
        if (*token == NULL) {
            g_strfreev(tokens);
            continue;
        }

        ifinfo->scope = strtol(*token, NULL, 16);
        if ((errno == EINVAL) || (errno == ERANGE)) {
            g_error("error reading scope from %s", file);
            g_strfreev(tokens);
            goto fail;
        }

        token++;

        /* read the flags */
        if (*token == NULL) {
            g_strfreev(tokens);
            continue;
        }

        ifinfo->flags = strtol(*token, NULL, 16);
        if ((errno == EINVAL) || (errno == ERANGE)) {
            g_error("error reading flags from %s", file);
            g_strfreev(tokens);
            goto fail;
        }

        if (ifinfo->flags == DAD_FLAGS) {
            g_message("duplicated IPv6 address %s detected",
                      in6addr2str(&ifinfo->addr, 0));
        } else {
            g_free(ifinfo);
            ifinfo = NULL;

            g_strfreev(tokens);
            continue;
        }

        token++;

        /* read the interface name */
        if (*token == NULL) {
            g_strfreev(tokens);
            continue;
        }

        if (g_strcmp0(*token, dhcp6_if->ifname)) {
            g_free(ifinfo);
            ifinfo = NULL;

            g_strfreev(tokens);
            continue;
        } else {
            dhcp6_value_t *lv;

            strncpy(ifinfo->name, *token, IFNAMSIZ);
            ifinfo->next = NULL;

            /* check address on client6_iaidaddr list */
            if ((lv = g_malloc0(sizeof(*lv))) == NULL) {
                g_error("memory allocation failure");
                abort();
            }

            memcpy(&lv->val_dhcp6addr.addr, &ifinfo->addr,
                   sizeof(lv->val_dhcp6addr.addr));
            lv->val_dhcp6addr.type = IANA;
            lv->val_dhcp6addr.plen = ifinfo->plen;
            lv->val_dhcp6addr.status_code = DH6OPT_STCODE_UNDEFINE;
            lv->val_dhcp6addr.preferlifetime = 0;
            lv->val_dhcp6addr.validlifetime = 0;
            dad_list = g_slist_append(dad_list, lv);
        }

        g_strfreev(tokens);
    }

out:
    if (fclose(fp) == EOF) {
        fprintf(stderr, "%s (%d): %s\n", __func__, __LINE__, strerror(errno));
        fflush(stderr);
        abort();
    }

    return ret;

fail:
    g_slist_free(dad_list);
    dad_list = NULL;
    ret = -1;
    goto out;
}

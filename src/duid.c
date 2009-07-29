/*
 * duid.c
 * DUID utility functions for dhcpv6.
 *
 * Copyright (C) 2009  Red Hat, Inc.
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

/* ported from KAME: common.c,v 1.65 2002/12/06 01:41:29 suz Exp */

/*
 * Copyright (C) 1998 and 1999 WIDE Project.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <glib.h>

#include "duid.h"
#include "dhcp6.h"
#include "str.h"

gint configure_duid(const gchar *str, struct duid *duid) {
    const gchar *cp;
    guchar *bp, *idbuf = NULL;
    guint8 duidlen, slen;
    guint x;

    /* calculate DUID len */
    slen = strlen(str);
    if (slen < 2) {
        goto bad;
    }

    duidlen = 1;
    slen -= 2;
    if ((slen % 3) != 0) {
        goto bad;
    }

    duidlen += (slen / 3);
    if ((idbuf = (guchar *) g_malloc0(duidlen)) == NULL) {
        g_error("%s: memory allocation failed", __func__);
        return -1;
    }

    for (cp = str, bp = idbuf; *cp;) {
        if (*cp == ':') {
            cp++;
            continue;
        }

        if (sscanf(cp, "%02x", &x) != 1) {
            goto bad;
        }

        *bp = x;
        cp += 2;
        bp++;
    }

    duid->duid_len = duidlen;
    duid->duid_id = idbuf;
    g_debug("configure duid is %s", duidstr(duid));
    return 0;

bad:
    if (idbuf) {
        g_free(idbuf);
        idbuf = NULL;
    }

    g_error("%s: assumption failure (bad string)", __func__);
    return -1;
}

gint duid_match_llt(struct duid *client, struct duid *server) {
    struct dhcp6_duid_type1 *client_duid = NULL;
    struct dhcp6_duid_type1 *server_duid = NULL;

    server_duid = (struct dhcp6_duid_type1 *) server->duid_id;
    client_duid = (struct dhcp6_duid_type1 *) client->duid_id;

    if (server_duid != NULL && client_duid != NULL) {
        server_duid->dh6duid1_time = client_duid->dh6duid1_time;
    } else {
        return -1;
    }

    return 0;
}

gint get_duid(const gchar *idfile, const gchar *ifname, struct duid *duid) {
    FILE *fp = NULL;
    guint16 len = 0, hwtype;
    struct dhcp6_duid_type1 *dp;        /* we only support the type1 DUID */
    guchar tmpbuf[256];  /* DUID should be no more than 256 bytes */

    if ((fp = fopen(idfile, "r")) == NULL && errno != ENOENT) {
        g_message("%s: failed to open DUID file: %s", __func__, idfile);
    }

    if (fp) {
        /* decode length */
        if (fread(&len, sizeof(len), 1, fp) != 1) {
            g_error("%s: DUID file corrupted", __func__);
            goto fail;
        }
    } else {
        len = calculate_duid_len(ifname, &hwtype);

        if (len == 0) {
            goto fail;
        }
    }

    memset(duid, 0, sizeof(*duid));
    duid->duid_len = len;

    if ((duid->duid_id = (guchar *) g_malloc0(len)) == NULL) {
        g_error("%s: failed to allocate memory", __func__);
        goto fail;
    }

    /* copy (and fill) the ID */
    if (fp) {
        if (fread(duid->duid_id, len, 1, fp) != 1) {
            g_error("%s: DUID file corrupted", __func__);
            goto fail;
        }

        g_debug("%s: extracted an existing DUID from %s: %s", __func__,
                idfile, duidstr(duid));
    } else {
        guint64 t64;

        dp = (struct dhcp6_duid_type1 *) duid->duid_id;
        dp->dh6duid1_type = htons(1);   /* type 1 */
        dp->dh6duid1_hwtype = htons(hwtype);
        t64 = (guint64) (time(NULL) - 946684800);
        dp->dh6duid1_time = htonl((u_long) (t64 & 0xffffffff));

        if (gethwid(tmpbuf, sizeof(tmpbuf), ifname, &hwtype) < 0) {
            g_debug("%s: failed to get hw ID for %s", __func__, ifname);
            goto fail;
        }

        memcpy((void *) (dp + 1), tmpbuf, (len - sizeof(*dp)));

        g_debug("%s: generated a new DUID: %s", __func__, duidstr(duid));
    }

    /* save DUID */
    if (save_duid(idfile, ifname, duid)) {
        g_debug("%s: failed to save DUID: %s", __func__, duidstr(duid));
        goto fail;
    }

    if (fp) {
        fclose(fp);
    }

    return 0;

fail:
    if (fp) {
        fclose(fp);
    }

    if (duid->duid_id != NULL) {
        duidfree(duid);
    }

    return -1;
}

gint save_duid(const gchar *idfile, const gchar *ifname, struct duid *duid) {
    FILE *fp = NULL;
    guint16 len = 0, hwtype;

    /* calculate DUID length */
    len = calculate_duid_len(ifname, &hwtype);

    if (len == 0) {
        goto fail;
    }

    /* save the (new) ID to the file for next time */
    if ((fp = fopen(idfile, "w+")) == NULL) {
        g_error("%s: failed to open DUID file for save", __func__);
        goto fail;
    }

    if ((fwrite(&len, sizeof(len), 1, fp)) != 1) {
        g_error("%s: failed to save DUID", __func__);
        goto fail;
    }

    if ((fwrite(duid->duid_id, len, 1, fp)) != 1) {
        g_error("%s: failed to save DUID", __func__);
        goto fail;
    }

    g_debug("%s: saved generated DUID to %s", __func__, idfile);

    if (fp) {
        fclose(fp);
    }

    return 0;

fail:
    if (fp) {
        fclose(fp);
    }

    if (duid->duid_id != NULL) {
        duidfree(duid);
    }

    return -1;
}

guint16 calculate_duid_len(const gchar *ifname, guint16 * hwtype) {
    gint l;
    guint16 ret = 0;
    guchar tmpbuf[256];  /* DUID should be no more than 256 bytes */

    if ((l = gethwid(tmpbuf, sizeof(tmpbuf), ifname, hwtype)) < 0) {
        g_message("%s: failed to get a hardware address", __func__);
        return 0;
    }

    ret = l + sizeof(struct dhcp6_duid_type1);
    return ret;
}

ssize_t gethwid(guchar *buf, gint len, const gchar *ifname,
                guint16 * hwtypep) {
    int skfd;
    ssize_t l;
    struct ifreq if_hwaddr;

    if ((skfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
        close(skfd);
        return -1;
    }

    strcpy(if_hwaddr.ifr_name, ifname);

#if defined(__linux__)
    if (ioctl(skfd, SIOCGIFHWADDR, &if_hwaddr) < 0) {
        close(skfd);
        return -1;
    }

    close(skfd);

    /* only support Ethernet */
    switch (if_hwaddr.ifr_hwaddr.sa_family) {
        case ARPHRD_ETHER:
        case ARPHRD_IEEE802:
            *hwtypep = ARPHRD_ETHER;
            l = 6;
            break;
        case ARPHRD_PPP:
            *hwtypep = ARPHRD_PPP;
            l = 0;
            return l;
        default:
            g_message("dhcpv6 doesn't support hardware type %d",
                      if_hwaddr.ifr_hwaddr.sa_family);
            return -1;          /* XXX */
    }

    memcpy(buf, if_hwaddr.ifr_hwaddr.sa_data, l);
    g_debug("%s: found an interface %s harware %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
            __func__, ifname, *buf, *(buf + 1), *(buf + 2), *(buf + 3),
            *(buf + 4), *(buf + 5));
    return l;
#else
    return -1;
#endif
}

gint duidcpy(struct duid *dd, const struct duid *ds) {
    dd->duid_len = ds->duid_len;

    if ((dd->duid_id = g_malloc0(dd->duid_len)) == NULL) {
        g_error("%s: len %d memory allocation failed", __func__, dd->duid_len);
        return -1;
    }

    memcpy(dd->duid_id, ds->duid_id, dd->duid_len);

    return 0;
}

gint duidcmp(const struct duid *d1, const struct duid *d2) {
    if (d1->duid_len == d2->duid_len) {
        return memcmp(d1->duid_id, d2->duid_id, d1->duid_len);
    } else {
        return -1;
    }
}

void duidfree(struct duid *duid) {
    g_debug("%s: DUID is %s, DUID_LEN is %d",
            __func__, duidstr(duid), duid->duid_len);

    if (duid->duid_id != NULL && duid->duid_len != 0) {
        g_debug("%s: removing ID (ID: %s)", __func__, duidstr(duid));
        g_free(duid->duid_id);
        duid->duid_id = NULL;
        duid->duid_len = 0;
    }

    duid->duid_len = 0;
}

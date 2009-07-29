/* ported from KAME: config.c,v 1.21 2002/09/24 14:20:49 itojun Exp */

/*
 * Copyright (C) 2002 WIDE Project.
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

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <netinet/in.h>
#include <sys/types.h>

#include <glib.h>

#include "queue.h"
#include "duid.h"
#include "dhcp6.h"
#include "confdata.h"
#include "common.h"
#include "str.h"

extern gint errno;

static struct dhcp6_ifconf *dhcp6_ifconflist;
static struct host_conf *host_conflist0, *host_conflist;
static GSList *dnslist0;

enum {
    DHCPOPTCODE_SEND,
    DHCPOPTCODE_REQUEST,
    DHCPOPTCODE_ALLOW
};

/* BEGIN STATIC FUNCTIONS */

static void _clear_ifconf(struct dhcp6_ifconf *iflist) {
    struct dhcp6_ifconf *ifc, *ifc_next;

    for (ifc = iflist; ifc; ifc = ifc_next) {
        ifc_next = ifc->next;

        g_free(ifc->ifname);
        ifc->ifname = NULL;

        g_slist_free(ifc->reqopt_list);
        ifc->reqopt_list = NULL;

        g_free(ifc);
        ifc = NULL;
    }

    return;
}

static void _clear_hostconf(struct host_conf *hlist) {
    struct host_conf *host = NULL, *host_next = NULL;

    for (host = hlist; host; host = host_next) {
        host_next = host->next;
        g_free(host->name);
        host->name = NULL;

        g_slist_free(host->prefix_list);
        host->prefix_list = NULL;

        if (host->duid.duid_id) {
            g_free(host->duid.duid_id);
            host->duid.duid_id = NULL;
        }

        g_free(host);
        host = NULL;
    }

    return;
}

static gint _add_options(gint opcode, struct dhcp6_ifconf *ifc,
                         struct cf_list *cfl0) {
    dhcp6_value_t *opt;
    struct cf_list *cfl;
    gint opttype;
    GSList *iterator = NULL;

    for (cfl = cfl0; cfl; cfl = cfl->next) {
        if (opcode == DHCPOPTCODE_REQUEST) {
            iterator = ifc->reqopt_list;

            if (g_slist_length(iterator)) {
                do {
                    opt = (dhcp6_value_t *) iterator->data;

                    if (opt->val_num == cfl->type) {
                        g_message("%s: duplicated requested option: %s",
                                  __func__, dhcp6optstr(cfl->type));
                        goto next;  /* ignore it */
                    }
                } while ((iterator = g_slist_next(iterator)) != NULL);
            }
        }

        switch (cfl->type) {
            case DHCPOPT_RAPID_COMMIT:
                switch (opcode) {
                    case DHCPOPTCODE_SEND:
                        ifc->send_flags |= DHCIFF_RAPID_COMMIT;
                        break;
                    case DHCPOPTCODE_ALLOW:
                        ifc->allow_flags |= DHCIFF_RAPID_COMMIT;
                        break;
                    default:
                        g_error("%s: invalid operation (%d) "
                                "for option type (%d)",
                                __func__, opcode, cfl->type);
                        return -1;
                }

                break;
            case DHCPOPT_PREFIX_DELEGATION:
                switch (opcode) {
                    case DHCPOPTCODE_REQUEST:
                        ifc->send_flags |= DHCIFF_PREFIX_DELEGATION;
                        break;
                    default:
                        g_error("%s: invalid operation (%d) "
                                "for option type (%d)",
                                __func__, opcode, cfl->type);
                        return -1;
                }

                break;
            case DHCPOPT_DNS:
                switch (opcode) {
                    case DHCPOPTCODE_REQUEST:
                        opttype = DH6OPT_DNS_SERVERS;
                        if (dhcp6_add_listval(ifc->reqopt_list,
                                              &opttype,
                                              DHCP6_LISTVAL_NUM) == NULL) {
                            g_error("%s: failed to configure an option",
                                    __func__);
                            return -1;
                        }

                        break;
                    default:
                        g_error("%s: invalid operation (%d) "
                                "for option type (%d)",
                                __func__, opcode, cfl->type);
                        break;
                }

                break;
            case DHCPOPT_DOMAIN_LIST:
                switch (opcode) {
                    case DHCPOPTCODE_REQUEST:
                        opttype = DH6OPT_DOMAIN_LIST;
                        if (dhcp6_add_listval(ifc->reqopt_list,
                                              &opttype,
                                              DHCP6_LISTVAL_NUM) == NULL) {
                            g_error("%s: failed to configure an option",
                                    __func__);
                            return -1;
                        }

                        break;
                    default:
                        g_error("%s: invalid operation (%d) "
                                "for option type (%d)",
                                __func__, opcode, cfl->type);
                        break;
                }

                break;
            default:
                g_error("%s: unknown option type: %d", __func__, cfl->type);
                return -1;
        }

      next:;
    }

    return 0;
}

static gint _add_address(GSList *addr_list, struct dhcp6_addr *v6addr) {
    dhcp6_value_t *lv, *val;
    GSList *iterator = addr_list;

    /* avoid invalid addresses */
    if (IN6_IS_ADDR_RESERVED(&v6addr->addr)) {
        g_error("%s: invalid address: %s", __func__,
                in6addr2str(&v6addr->addr, 0));
        return -1;
    }

    /* address duplication check */
    if (g_slist_length(iterator)) {
        do {
            lv = (dhcp6_value_t *) iterator->data;

            if (IN6_ARE_ADDR_EQUAL(&lv->val_dhcp6addr.addr, &v6addr->addr) &&
                lv->val_dhcp6addr.plen == v6addr->plen) {
                g_error("%s: duplicated address: %s/%d", __func__,
                        in6addr2str(&v6addr->addr, 0), v6addr->plen);
                return -1;
            }
        } while ((iterator = g_slist_next(iterator)) != NULL);
    }

    if ((val = (dhcp6_value_t *) malloc(sizeof(*val))) == NULL) {
        g_error("%s: memory allocation failed", __func__);
    }

    memset(val, 0, sizeof(*val));
    memcpy(&val->val_dhcp6addr, v6addr, sizeof(val->val_dhcp6addr));
    g_debug("%s: add address: %s", __func__, in6addr2str(&v6addr->addr, 0));
    addr_list = g_slist_append(addr_list, val);
    return 0;
}

/* END STATIC FUNCTIONS */

gint configure_interface(const struct cf_namelist *iflist) {
    const struct cf_namelist *ifp;
    struct dhcp6_ifconf *ifc;

    for (ifp = iflist; ifp; ifp = ifp->next) {
        struct cf_list *cfl;

        if ((ifc = malloc(sizeof(*ifc))) == NULL) {
            g_error("%s: memory allocation for %s failed",
                    __func__, ifp->name);
            goto bad;
        }

        memset(ifc, 0, sizeof(*ifc));
        ifc->next = dhcp6_ifconflist;
        dhcp6_ifconflist = ifc;

        if ((ifc->ifname = strdup(ifp->name)) == NULL) {
            g_error("%s: failed to copy ifname", __func__);
            goto bad;
        }

        ifc->server_pref = DH6OPT_PREF_UNDEF;
        ifc->default_irt = IRT_DEFAULT;
        ifc->maximum_irt = DHCP6_DURATITION_INFINITE;
        ifc->reqopt_list = NULL;
        ifc->addr_list = NULL;
        ifc->option_list = NULL;

        for (cfl = ifp->params; cfl; cfl = cfl->next) {
            switch (cfl->type) {
                case DECL_REQUEST:
                    if (dhcp6_mode != DHCP6_MODE_CLIENT) {
                        g_message("%s: %s:%d client-only configuration",
                                  __func__, configfilename, cfl->line);
                        goto bad;
                    }

                    if (_add_options(DHCPOPTCODE_REQUEST, ifc, cfl->list)) {
                        goto bad;
                    }

                    break;
                case DECL_SEND:
                    if (_add_options(DHCPOPTCODE_SEND, ifc, cfl->list)) {
                        goto bad;
                    }

                    break;
                case DECL_ALLOW:
                    if (_add_options(DHCPOPTCODE_ALLOW, ifc, cfl->list)) {
                        goto bad;
                    }

                    break;
                case DECL_INFO_ONLY:
                    if (dhcp6_mode == DHCP6_MODE_CLIENT) {
                        ifc->send_flags |= DHCIFF_INFO_ONLY;
                    }

                    break;
                case DECL_DEFAULT_IRT:
                    if (dhcp6_mode != DHCP6_MODE_CLIENT) {
                        g_message("%s: %s:%d client-only configuration",
                                  __func__, configfilename, cfl->line);
                        goto bad;
                    }

                    if (cfl->num == -1) {
                        cfl->num = DHCP6_DURATITION_INFINITE;
                    } else if (cfl->num < IRT_MINIMUM ||
                               DHCP6_DURATITION_INFINITE < cfl->num) {
                        g_message("%s: %s:%d bad value: %lld", __func__,
                                  configfilename, cfl->line, cfl->num);
                        goto bad;
                    }

                    ifc->default_irt = cfl->num;

                    break;
                case DECL_MAXIMUM_IRT:
                    if (dhcp6_mode != DHCP6_MODE_CLIENT) {
                        g_message("%s: %s:%d client-only configuration",
                                  __func__, configfilename, cfl->line);
                        goto bad;
                    }

                    if (cfl->num == -1) {
                        cfl->num = DHCP6_DURATITION_INFINITE;
                    } else if (cfl->num < IRT_MINIMUM ||
                               DHCP6_DURATITION_INFINITE < cfl->num) {
                        g_message("%s: %s:%d bad value: %lld", __func__,
                                  configfilename, cfl->line, cfl->num);
                        goto bad;
                    }

                    ifc->maximum_irt = cfl->num;
                    break;
                case DECL_TEMP_ADDR:
                    if (dhcp6_mode == DHCP6_MODE_CLIENT) {
                        ifc->send_flags |= DHCIFF_TEMP_ADDRS;
                    }

                    break;
                case DECL_PREFERENCE:
                    if (dhcp6_mode != DHCP6_MODE_SERVER) {
                        g_message("%s: %s:%d server-only configuration",
                                  __func__, configfilename, cfl->line);
                        goto bad;
                    }

                    ifc->server_pref = (int) cfl->num;

                    if (ifc->server_pref < 0 || ifc->server_pref > 255) {
                        g_message("%s: %s:%d bad value: %d", __func__,
                                  configfilename, cfl->line, ifc->server_pref);
                        goto bad;
                    }

                    break;
                case DECL_IAID:
                    if (ifc->iaidinfo.iaid) {
                        g_error("%s: %s:%d duplicated IAID for %s",
                                __func__, configfilename,
                                cfl->line, ifc->ifname);
                        goto bad;
                    } else {
                        ifc->iaidinfo.iaid = (guint32) cfl->num;
                    }

                    break;
                case DECL_RENEWTIME:
                    if (ifc->iaidinfo.renewtime) {
                        g_error("%s: %s:%d duplicated renewtime for %s",
                                __func__, configfilename,
                                cfl->line, ifc->ifname);
                        goto bad;
                    } else {
                        ifc->iaidinfo.renewtime = (guint32) cfl->num;
                    }

                    break;
                case DECL_REBINDTIME:
                    if (ifc->iaidinfo.iaid) {
                        g_error("%s: %s:%d duplicated rebindtime for %s",
                                __func__, configfilename,
                                cfl->line, ifc->ifname);
                        goto bad;
                    } else {
                        ifc->iaidinfo.rebindtime = (guint32) cfl->num;
                    }

                    break;
                case DECL_ADDRESS:
                    if (_add_address(ifc->addr_list, cfl->ptr)) {
                        g_error("%s: failed to configure ipv6address for %s",
                                __func__, ifc->ifname);
                        goto bad;
                    }

                    break;
                case DECL_PREFIX_REQ:
                    /* XX: ToDo */
                    break;
                case DECL_PREFIX_INFO:
                    break;
                default:
                    g_error("%s: %s:%d invalid interface configuration",
                            __func__, configfilename, cfl->line);
                    goto bad;
            }
        }

        if (ifc->default_irt > ifc->maximum_irt) {
            g_message("%s: %s information refresh time: "
                      "default (%u) is bigger than maximum (%u)",
                      __func__, configfilename,
                      ifc->default_irt, ifc->maximum_irt);
            goto bad;
        }
    }

    return 0;

bad:
    _clear_ifconf(dhcp6_ifconflist);
    dhcp6_ifconflist = NULL;
    return -1;
}

gint configure_host(const struct cf_namelist *hostlist) {
    const struct cf_namelist *host;
    struct host_conf *hconf;

    for (host = hostlist; host; host = host->next) {
        struct cf_list *cfl;

        if ((hconf = malloc(sizeof(*hconf))) == NULL) {
            g_error("%s: memory allocation failed for host %s",
                    __func__, host->name);
            goto bad;
        }

        memset(hconf, 0, sizeof(*hconf));
        hconf->addr_list = NULL;
        hconf->addr_binding_list = NULL;
        hconf->prefix_list = NULL;
        hconf->prefix_binding_list = NULL;
        hconf->next = host_conflist0;
        host_conflist0 = hconf;

        if ((hconf->name = strdup(host->name)) == NULL) {
            g_error("%s: failed to copy host name: %s", __func__, host->name);
            goto bad;
        }

        for (cfl = host->params; cfl; cfl = cfl->next) {
            switch (cfl->type) {
                case DECL_DUID:
                    if (hconf->duid.duid_id) {
                        g_error("%s: %s:%d duplicated DUID for %s",
                                __func__, configfilename,
                                cfl->line, host->name);
                        goto bad;
                    }

                    if ((configure_duid((gchar *) cfl->ptr,
                                        &hconf->duid)) != 0) {
                        g_error("%s: %s:%d failed to configure DUID for %s",
                                __func__, configfilename, cfl->line,
                                host->name);
                        goto bad;
                    }

                    g_debug("%s: configure DUID for %s: %s", __func__,
                            host->name, duidstr(&hconf->duid));
                    break;
                case DECL_PREFIX:
                    if (_add_address(hconf->prefix_list, cfl->ptr)) {
                        g_error("%s: failed to configure prefix for %s",
                                __func__, host->name);
                        goto bad;
                    }

                    break;
                case DECL_IAID:
                    if (hconf->iaidinfo.iaid) {
                        g_error("%s: %s:%d duplicated IAID for %s",
                                __func__, configfilename,
                                cfl->line, host->name);
                        goto bad;
                    } else {
                        hconf->iaidinfo.iaid = (guint32) cfl->num;
                    }

                    break;
                case DECL_RENEWTIME:
                    if (hconf->iaidinfo.renewtime) {
                        g_error("%s: %s:%d duplicated renewtime for %s",
                                __func__, configfilename,
                                cfl->line, host->name);
                        goto bad;
                    } else {
                        hconf->iaidinfo.renewtime = (guint32) cfl->num;
                    }

                    break;
                case DECL_REBINDTIME:
                    if (hconf->iaidinfo.rebindtime) {
                        g_error("%s: %s:%d duplicated rebindtime for %s",
                                __func__, configfilename,
                                cfl->line, host->name);
                        goto bad;
                    } else {
                        hconf->iaidinfo.rebindtime = (guint32) cfl->num;
                    }

                    break;
                case DECL_ADDRESS:
                    if (_add_address(hconf->addr_list, cfl->ptr)) {
                        g_error("%s: failed to configure ipv6address for %s",
                                __func__, host->name);
                        goto bad;
                    }

                    break;
                case DECL_LINKLOCAL:
                    if (IN6_IS_ADDR_UNSPECIFIED(&hconf->linklocal)) {
                        g_error("%s: %s:%d duplicated linklocal for %s",
                                __func__, configfilename,
                                cfl->line, host->name);
                        goto bad;
                    } else {
                        memcpy(&hconf->linklocal, cfl->ptr,
                               sizeof(hconf->linklocal));
                    }

                    break;
                default:
                    g_error("%s: %d invalid host configuration for %s",
                            configfilename, cfl->line, host->name);
                    goto bad;
            }
        }
    }

    return 0;

bad:
    /* there is currently nothing special to recover the error */
    return -1;
}

gint configure_global_option(void) {
    struct cf_list *cl;

    /* DNS servers */
    if (cf_dns_list && dhcp6_mode != DHCP6_MODE_SERVER) {
        g_message("%s: %s:%d server-only configuration",
                  __func__, configfilename, cf_dns_list->line);
        goto bad;
    }

    dnslist0 = NULL;

    for (cl = cf_dns_list; cl; cl = cl->next) {
        /* duplication check */
        if (dhcp6_find_listval(dnslist0, cl->ptr, DHCP6_LISTVAL_ADDR6)) {
            g_message("%s: %s:%d duplicated DNS server: %s", __func__,
                      configfilename, cl->line,
                      in6addr2str((struct in6_addr *) cl->ptr, 0));
            goto bad;
        }

        if (dhcp6_add_listval(dnslist0, cl->ptr,
                              DHCP6_LISTVAL_ADDR6) == NULL) {
            g_error("%s: failed to add a DNS server", __func__);
            goto bad;
        }
    }

    return 0;

bad:
    return -1;
}

void configure_cleanup(void) {
    _clear_ifconf(dhcp6_ifconflist);
    dhcp6_ifconflist = NULL;

    _clear_hostconf(host_conflist0);
    host_conflist0 = NULL;

    g_slist_free(dnslist0);
    dnslist0 = NULL;

    return;
}

void configure_commit(void) {
    struct dhcp6_ifconf *ifc;
    struct dhcp6_if *ifp;

    /* commit interface configuration */
    for (ifc = dhcp6_ifconflist; ifc; ifc = ifc->next) {
        if ((ifp = find_ifconfbyname(ifc->ifname)) != NULL) {
            ifp->send_flags = ifc->send_flags;

            ifp->allow_flags = ifc->allow_flags;

            g_slist_free(ifp->reqopt_list);
            ifp->reqopt_list = ifc->reqopt_list;
            ifc->reqopt_list = NULL;

            g_slist_free(ifp->addr_list);
            ifp->addr_list = ifc->addr_list;
            ifc->addr_list = NULL;

            g_slist_free(ifp->prefix_list);
            ifp->prefix_list = ifc->prefix_list;
            ifc->prefix_list = NULL;

            g_slist_free(ifp->option_list);
            ifp->option_list = NULL;

            ifp->server_pref = ifc->server_pref;

            ifp->default_irt = ifc->default_irt;
            ifp->maximum_irt = ifc->maximum_irt;

            memcpy(&ifp->iaidinfo, &ifc->iaidinfo, sizeof(ifp->iaidinfo));
        }
    }

    _clear_ifconf(dhcp6_ifconflist);

    /* commit prefix configuration */
    if (host_conflist) {
        /* clear previous configuration. (need more work?) */
        _clear_hostconf(host_conflist);
    }

    host_conflist = host_conflist0;
    host_conflist0 = NULL;
    return;
}

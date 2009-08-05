/* ported from KAME: dhcp6s.c,v 1.91 2002/09/24 14:20:50 itojun Exp */

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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <getopt.h>
#include <string.h>
#include <libgen.h>
#include <syslog.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netdb.h>
#include <sys/types.h>
#include <unistd.h>
#include <err.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/param.h>

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# include <time.h>
#endif

#ifdef HAVE_LINUX_SOCKIOS_H
# include <linux/sockios.h>
#endif

#include <glib.h>

#include "dhcp6s.h"

static gchar *pidfile = NULL;
static gchar *device[MAX_DEVICE];
static gint num_device = 0;
static const struct sockaddr_in6 *sa6_any_downstream;
static guint16 upstream_port;
static struct msghdr rmh;
static gchar rdatabuf[BUFSIZ];
static gint rmsgctllen;
static gchar *rmsgctlbuf;
static duid_t server_duid;
static dns_info_t arg_dnsinfo;
static dhcp6_timer_t *sync_lease_timer;

const dhcp6_mode_t dhcp6_mode = DHCP6_MODE_SERVER;
gint iosock = -1;                /* inbound/outbound udp port */
extern FILE *server6_lease_file;
gchar server6_lease_temp[100];
link_decl_t *subnet = NULL;
host_decl_t *host = NULL;
rootgroup_t *globalgroup = NULL;

/* BEGIN STATIC FUNCTIONS */

static void _server6_sighandler(gint sig) {
    g_message("%s: received a signal (%d)", __func__, sig);

    switch (sig) {
        case SIGTERM:
        case SIGHUP:
        case SIGINT:
            g_message("%s: exiting", __func__);
            unlink(pidfile);
            exit(0);
            break;
        default:
            break;
    }

    return;
}

/*
 * Parse all of the RELAY-FORW messages and interface ID options. Each
 * RELAY-FORW messages will have its hop count, link address, peer-address,
 * and interface ID (if any) put into a relay_listval structure.
 * A pointer to the actual original client message will be returned.
 * If this client message cannot be found, NULL is returned to signal an error.
 */
static dhcp6_t *_dhcp6_parse_relay(dhcp6_relay_t *relay_msg,
                                   dhcp6_relay_t *endptr,
                                   dhcp6_optinfo_t *optinfo,
                                   struct in6_addr *relay_addr) {
    relay_t *relay_val;
    dhcp6_t *relayed_msg;  /* the original message that the relay
                            * received */
    dhcp6opt_t *option, *option_endptr = (dhcp6opt_t *) endptr;
    guint16 optlen;
    guint16 opt;

    while ((relay_msg + 1) < endptr) {
        relay_val = (relay_t *) calloc(1, sizeof(relay_t));

        if (relay_val == NULL) {
            g_error("%s: failed to allocate memory", __func__);
            g_slist_free(optinfo->relay_list);
            optinfo->relay_list = NULL;
            return NULL;
        }

        /* copy the msg-type, hop-count, link-address, and peer-address */
        memcpy(&relay_val->relay, relay_msg, sizeof(dhcp6_relay_t));

        /* set the msg type to relay reply now so that it doesn't need to be
         * done when formatting the reply */
        relay_val->relay.dh6_msg_type = DH6_RELAY_REPL;

        optinfo->relay_list = g_slist_append(optinfo->relay_list, relay_val);

        /* 
         * need to record the first relay's link address field for later use.
         * The first relay is the last one we see, so keep overwriting the
         * relay value.
         */
        memcpy(relay_addr, &relay_val->relay.link_addr,
               sizeof(struct in6_addr));

        /* now handle the options in the RELAY-FORW message */
        /* 
         * The only options that should appear in a RELAY-FORW message are:
         * - Interface identifier
         * - Relay message
         *
         * All other options are ignored.
         */
        option = (dhcp6opt_t *) (relay_msg + 1);

        relayed_msg = NULL;     /* if this is NULL at the end of the loop, no
                                 * relayed message was found */

        /* since the order of options is not specified, all of the options
         * must be processed */
        while ((option + 1) < option_endptr) {
            memcpy(&opt, &option->dh6opt_type, sizeof(opt));
            opt = ntohs(opt);
            memcpy(&optlen, &option->dh6opt_len, sizeof(optlen));
            optlen = ntohs(optlen);

            if ((gchar *) (option + 1) + optlen > (gchar *) option_endptr) {
                g_error("%s: invalid option length in %s option",
                        __func__, dhcp6optstr(opt));
                g_slist_free(optinfo->relay_list);
                optinfo->relay_list = NULL;
                return NULL;
            }

            if (opt == DH6OPT_INTERFACE_ID) {
                /* if this is not the first interface identifier option, then 
                 * the message is incorrectly formed */
                if (relay_val->intf_id == NULL) {
                    if (optlen) {
                        relay_val->intf_id = (intf_id_t *)
                            g_malloc0(sizeof(intf_id_t));

                        if (relay_val->intf_id == NULL) {
                            g_error("%s: failed to allocate memory", __func__);
                            g_slist_free(optinfo->relay_list);
                            optinfo->relay_list = NULL;
                            return NULL;
                        } else {
                            relay_val->intf_id->intf_len = optlen;
                            relay_val->intf_id->intf_id = (gchar *)
                                g_malloc0(optlen);

                            if (relay_val->intf_id->intf_id == NULL) {
                                g_error("%s: failed to allocate memory",
                                        __func__);
                                g_slist_free(optinfo->relay_list);
                                optinfo->relay_list = NULL;
                                return NULL;
                            } else {    /* copy the interface identifier so
                                         * it can be sent in the reply */
                                memcpy(relay_val->intf_id->intf_id,
                                       ((gchar *) (option + 1)), optlen);
                            }
                        }
                    } else {
                        g_error("%s: Invalid length for interface "
                                "identifier option", __func__);
                    }
                } else {
                    g_message("%s: Multiple interface identifier "
                              "options in RELAY-FORW Message ", __func__);
                    g_slist_free(optinfo->relay_list);
                    optinfo->relay_list = NULL;
                    return NULL;
                }
            } else if (opt == DH6OPT_RELAY_MSG) {
                if (relayed_msg == NULL) {
                    relayed_msg = (dhcp6_t *) (option + 1);
                } else {
                    g_message("%s: Duplicated Relay Message option", __func__);
                    g_slist_free(optinfo->relay_list);
                    optinfo->relay_list = NULL;
                    return NULL;
                }
            } else {            /* No other options besides interface
                                 * identifier and relay message make sense,
                                 * so ignore them with a warning */
                g_message("%s: Unsupported option %s found in "
                          "RELAY-FORW message", __func__, dhcp6optstr(opt));
            }

            /* advance the option pointer */
            option = (dhcp6opt_t *) (((gchar *) (option + 1)) + optlen);
        }

        /*
         * If the relayed message is non-NULL and is a regular client
         * message, then the relay processing is done. If it is another
         * RELAY_FORW message, then continue. If the relayed message is
         * NULL, signal an error.
         */
        if (relayed_msg != NULL && (gchar *) (relayed_msg + 1) <=
            (gchar *) endptr) {
            /* done if have found the client message */
            if (relayed_msg->dh6_msgtype != DH6_RELAY_FORW) {
                return relayed_msg;
            } else {
                relay_msg = (dhcp6_relay_t *) relayed_msg;
            }
        } else {
            g_error("%s: invalid relayed message", __func__);
            g_slist_free(optinfo->relay_list);
            optinfo->relay_list = NULL;
            return NULL;
        }
    }

    return NULL;
}

/*
 * Fill in all of the opt-len fields for the Relay Message options now that
 * the length of the entire message is known.
 *
 * len - the length of the DHCPv6 message to the client (not including any
 *       relay options)
 *
 * Precondition: dhcp6_set_relay has already been called and the relay->option
 *               fields of all of the elements in optinfo->relay_list are 
 *               non-NULL
 */
static void _dhcp6_set_relay_option_len(dhcp6_optinfo_t *optinfo,
                                        gint reply_msg_len) {
    relay_t *relay, *last = NULL;
    guint16 len;
    GSList *iterator = g_slist_reverse(optinfo->relay_list);

    while (iterator) {
        relay = (relay_t *) iterator->data;

        if (last == NULL) {
            len = htons(reply_msg_len);
            memcpy(&relay->option->dh6opt_len, &len, sizeof(len));
            last = relay;
        } else {
            len = reply_msg_len + (((void *) (last->option + 1)) -
                                   ((void *) (relay->option + 1)));
            len = htons(len);
            memcpy(&relay->option->dh6opt_len, &len, sizeof(len));
        }

        iterator = g_slist_next(iterator);
    }

    return;
}

/*
 * Format all of the RELAY-REPL messages and options to send back to the 
 * client. A RELAY-REPL message and Relay Message option are added for 
 * each of the relays that were in the RELAY-FORW packet that this is 
 * in response to.
 */
static gint _dhcp6_set_relay(dhcp6_relay_t *msg, dhcp6_relay_t *endptr,
                             dhcp6_optinfo_t *optinfo) {
    relay_t *relay;
    dhcp6opt_t *option;
    gint relaylen = 0;
    guint16 type, len;
    GSList *iterator = optinfo->relay_list;

    while (iterator) {
        relay = (relay_t *) iterator->data;

        /* bounds check */
        if (((gchar *) msg) + sizeof(dhcp6_relay_t) >= (gchar *) endptr) {
            g_error("%s: insufficient buffer size for RELAY-REPL", __func__);
            return -1;
        }

        memcpy(msg, &relay->relay, sizeof(dhcp6_relay_t));
        relaylen += sizeof(dhcp6_relay_t);
        option = (dhcp6opt_t *) (msg + 1);

        /* include an Interface Identifier option if it was present in the
         * original message */
        if (relay->intf_id != NULL) {
            /* bounds check */
            if ((((gchar *) option) + sizeof(dhcp6opt_t) +
                 relay->intf_id->intf_len) >= (gchar *) endptr) {
                g_error("%s: insufficient buffer size for RELAY-REPL",
                        __func__);
                return -1;
            }

            type = htons(DH6OPT_INTERFACE_ID);
            memcpy(&option->dh6opt_type, &type, sizeof(type));
            len = htons(relay->intf_id->intf_len);
            memcpy(&option->dh6opt_len, &len, sizeof(len));
            memcpy(option + 1, relay->intf_id->intf_id,
                   relay->intf_id->intf_len);

            option = (dhcp6opt_t *) (((gchar *) (option + 1)) +
                                          relay->intf_id->intf_len);
            relaylen += sizeof(dhcp6opt_t) + relay->intf_id->intf_len;
        }

        /* save a pointer to the relay message option so that it is easier to 
         * fill in the length later */
        relay->option = option;

        /* bounds check */
        if ((gchar *) (option + 1) >= (gchar *) endptr) {
            g_error("%s: insufficient buffer size for RELAY-REPL", __func__);
            return -1;
        }

        /* lastly include the Relay Message option, which encapsulates the
         * message being relayed */
        type = htons(DH6OPT_RELAY_MSG);
        memcpy(&option->dh6opt_type, &type, sizeof(type));
        relaylen += sizeof(dhcp6opt_t);
        /* dh6opt_len will be set by dhcp6_set_relay_option_len */

        msg = (dhcp6_relay_t *) (option + 1);

        iterator = g_slist_next(iterator);
    }

    /*
     * if there were no relays, this is an error since this function should
     * not have even been called in this case
     */
    if (relaylen == 0) {
        return -1;
    } else {
        return relaylen;
    }
}

static gint _server6_send(gint type, dhcp6_if_t *ifp, dhcp6_t *origmsg,
                          dhcp6_optinfo_t *optinfo, struct sockaddr *from,
                          gint fromlen, dhcp6_optinfo_t *roptinfo) {
    gchar replybuf[BUFSIZ];
    struct sockaddr_in6 dst;
    gint len, optlen, relaylen = 0;
    dhcp6_t *dh6;

    if (sizeof(dhcp6_t) > sizeof(replybuf)) {
        g_error("%s: buffer size assumption failed", __func__);
        return -1;
    }

    if (g_slist_length(optinfo->relay_list) &&
        (relaylen = _dhcp6_set_relay((dhcp6_relay_t *) replybuf,
                                     (dhcp6_relay_t *) (replybuf +
                                                             sizeof(replybuf)),
                                     optinfo)) < 0) {
        g_message("%s: failed to construct relay message", __func__);
        return -1;
    }

    dh6 = (dhcp6_t *) (replybuf + relaylen);
    len = sizeof(*dh6);
    memset(dh6, 0, sizeof(*dh6));
    dh6->dh6_msgtypexid = origmsg->dh6_msgtypexid;
    dh6->dh6_msgtype = (guint8) type;

    /* set options in the reply message */
    if ((optlen = dhcp6_set_options((dhcp6opt_t *) (dh6 + 1),
                                    (dhcp6opt_t *) (replybuf +
                                                    sizeof(replybuf)),
                                    roptinfo)) < 0) {
        g_message("%s: failed to construct reply options", __func__);
        return -1;
    }

    len += optlen;

    /*
     * If there were any Relay Message options, fill in the option-len
     * field(s) with the appropriate value(s).
     */
    if (g_slist_length(optinfo->relay_list)) {
        _dhcp6_set_relay_option_len(optinfo, len);
    }

    len += relaylen;

    /* specify the destination and send the reply */
    dst = *sa6_any_downstream;
    dst.sin6_addr = ((struct sockaddr_in6 *) from)->sin6_addr;

    /* RELAY-REPL messages need to be directed back to the port the relay
     * agent is listening on, namely DH6PORT_UPSTREAM */
    if (relaylen > 0) {
        dst.sin6_port = upstream_port;
    }

    dst.sin6_scope_id = ((struct sockaddr_in6 *) from)->sin6_scope_id;
    g_debug("send destination address is %s, scope id is %d",
            addr2str((struct sockaddr *) &dst, sizeof(dst)),
            dst.sin6_scope_id);

    if (transmit_sa(iosock, &dst, replybuf, len) != 0) {
        g_error("%s: transmit %s to %s failed", __func__,
                dhcp6msgstr(type), addr2str((struct sockaddr *) &dst,
                sizeof(dst)));
        return -1;
    }

    g_debug("%s: transmit %s to %s", __func__, dhcp6msgstr(type),
            addr2str((struct sockaddr *) &dst, sizeof(dst)));

    return 0;
}

static gint _handle_addr_request(dhcp6_optinfo_t *roptinfo,
                                 GSList *ria_list, GSList *ia_list,
                                 gint resptype, gint *status_code) {
    ia_t *ria = NULL, *ia = NULL;
    dhcp6_iaidaddr_t *iaidaddr = NULL;
    gint addr_flag = 0;
    gint found_binding = 0;
    GSList *iterator = ia_list;

    if (!g_slist_length(iterator)) {
        goto fail;
    }

    while (iterator) {
        ia = (ia_t *) iterator->data;

        /* find bindings */
        if ((iaidaddr = dhcp6_find_iaidaddr(&roptinfo->clientID,
                                            ia->iaidinfo.iaid,
                                            ia->type)) != NULL) {
            found_binding = 1;
            addr_flag = ADDR_UPDATE;
        }

        if ((ria = ia_create_listval()) == NULL) {
            goto fail;
        }

        ria->type = ia->type;
        ria->iaidinfo.iaid = ia->iaidinfo.iaid;

        if (host) {
            dhcp6_get_hostconf(ria, ia, iaidaddr, host);
        }

        /* valid and create addresses list */
        if (ia->type == IAPD) {
            if (dhcp6_create_prefixlist(ria, ia, iaidaddr,
                                        subnet, &ria->status_code)) {
                goto fail;
            }
        } else {
            if (dhcp6_create_addrlist(ria, ia, iaidaddr,
                                      subnet, &ria->status_code)) {
                goto fail;
            }
        }

        if (!g_slist_length(ria->addr_list)) {
            if (resptype == DH6_ADVERTISE) {
                /* Omit IA option */
                g_free(ria);
                ria = NULL;
                continue;
            } else if (resptype == DH6_REPLY) {
                /* Set status code in IA */
                ria->status_code = DH6OPT_STCODE_NOADDRAVAIL;
            }
        } else if (resptype == DH6_REPLY &&
                   ria->status_code == DH6OPT_STCODE_UNDEFINE) {
            /* valid client request address list */
            if (found_binding) {
                if (dhcp6_update_iaidaddr(roptinfo, ria, addr_flag) != 0) {
                    g_error("assigned ipv6address for client iaid %u failed",
                            ria->iaidinfo.iaid);
                    ria->status_code = DH6OPT_STCODE_UNSPECFAIL;
                } else {
                    ria->status_code = DH6OPT_STCODE_SUCCESS;
                }
            } else {
                if (dhcp6_add_iaidaddr(roptinfo, ria) != 0) {
                    g_error("assigned ipv6address for client iaid %u failed",
                            ria->iaidinfo.iaid);
                    ria->status_code = DH6OPT_STCODE_UNSPECFAIL;
                } else {
                    ria->status_code = DH6OPT_STCODE_SUCCESS;
                }
            }
        }

        ria_list = g_slist_append(ria_list, ria);
        iterator = g_slist_next(iterator);
    }

    if (resptype == DH6_ADVERTISE && !g_slist_length(ria_list)) {
        *status_code = DH6OPT_STCODE_NOADDRAVAIL;
    }

    return 0;

fail:
    g_free(ria);
    ria = NULL;
    ia_clear_list(ia_list);
    return -1;
}

static gint _update_binding_ia(dhcp6_optinfo_t *roptinfo,
                               GSList *ria_list, GSList *ia_list,
                               guint8 msgtype, gint addr_flag,
                               gint *status_code) {
    ia_t *ria, *ia;
    dhcp6_iaidaddr_t *iaidaddr = NULL;
    size_t num_ia = 0;
    size_t num_noaddr_ia = 0;
    size_t num_nobinding_ia = 0;
    size_t num_invalid_ia = 0;
    GSList *iterator = ia_list;

    if (!g_slist_length(ia_list)) {
        goto fail;
    }

    while (iterator) {
        ia = (ia_t *) iterator->data;
        num_ia++;
        ria = NULL;

        if (g_slist_length(ia->addr_list)) {
            if (addr_flag != ADDR_VALIDATE) {
                if ((ria = ia_create_listval()) == NULL) {
                    goto fail;
                }

                ria->type = ia->type;
                ria->iaidinfo = ia->iaidinfo;
            }

            if ((iaidaddr = dhcp6_find_iaidaddr(&roptinfo->clientID,
                                                ia->iaidinfo.iaid,
                                                ia->type)) == NULL) {
                /* Not found binding IA Addr */
                num_nobinding_ia++;
                g_message("%s: Nobinding for client %s iaid %u", __func__,
                          duidstr(&roptinfo->clientID),
                          ia->iaidinfo.iaid);

                if (addr_flag == ADDR_VALIDATE) {
                    goto out;
                } else if (msgtype == DH6_REBIND) {
                    g_free(ria);
                    ria = NULL;
                } else {
                    ria->status_code = DH6OPT_STCODE_NOBINDING;
                }
            } else {
                /* Found a binding IA Addr */
                switch (addr_flag) {
                    case ADDR_VALIDATE:
                        if (dhcp6_validate_bindings(ia->addr_list,
                                                    iaidaddr, 0)) {
                            num_invalid_ia++;
                            goto out;
                        }

                        break;
                    case ADDR_UPDATE:
                        /* get static host configuration */
                        if (dhcp6_validate_bindings(ia->addr_list,
                                                    iaidaddr, 1)) {
                            num_invalid_ia++;
                            dhcp6_copy_list(ria->addr_list, ia->addr_list);
                            break;
                        }

                        if (host) {
                            dhcp6_get_hostconf(ria, ia, iaidaddr, host);
                        }

                        /* allow dynamic address assginment for the host too */
                        if (ria->type == IAPD) {
                            if (dhcp6_create_prefixlist(ria, ia,
                                                        iaidaddr, subnet,
                                                        &ria->status_code)) {
                                goto fail;
                            }
                        } else {
                            if (dhcp6_create_addrlist(ria, ia,
                                                      iaidaddr, subnet,
                                                      &ria->status_code)) {
                                goto fail;
                            }
                        }

                        break;
                    case ADDR_REMOVE:
                        if (dhcp6_update_iaidaddr(roptinfo, ia,
                                                  addr_flag) != 0) {
                            g_error("removed IPv6 address for "
                                    "client iaid %u failed",
                                    ia->iaidinfo.iaid);
                        }

                        break;
                    default:
                        dhcp6_copy_list(ria->addr_list, ia->addr_list);
                        break;
                }
            }

            if (ria != NULL) {
                ria_list = g_slist_append(ria_list, ria);
            }
        } else {
            /* IA doesn't include any IA Addr */
            num_noaddr_ia++;
        }

        iterator = g_slist_next(iterator);
    }

out:
    switch (msgtype) {
        case DH6_CONFIRM:
            if (num_noaddr_ia == num_ia) {
                g_debug("No addresses in confirm message");
                goto fail;
            } else if (num_nobinding_ia || num_invalid_ia) {
                *status_code = DH6OPT_STCODE_NOTONLINK;
            } else {
                *status_code = DH6OPT_STCODE_SUCCESS;
            }

            break;
        case DH6_RENEW:
            break;
        case DH6_REBIND:
            if (num_noaddr_ia + num_nobinding_ia == num_ia) {
                goto fail;
            }
        case DH6_RELEASE:
        case DH6_DECLINE:
            *status_code = DH6OPT_STCODE_SUCCESS;
            break;
    }

    return 0;

fail:
    g_free(ria);
    ria = NULL;
    ia_clear_list(ria_list);
    return -1;
}

static gint _server6_react_message(dhcp6_if_t *ifp, struct in6_pktinfo *pi,
                                   dhcp6_t *dh6, dhcp6_optinfo_t *optinfo,
                                   struct sockaddr *from, gint fromlen) {
    dhcp6_optinfo_t roptinfo;
    gint addr_flag = 0;
    gint resptype = DH6_REPLY;
    gint num = DH6OPT_STCODE_UNDEFINE;

    /* message validation according to Section 18.2 of dhcpv6-28 */

    /* the message must include a Client Identifier option */
    if (optinfo->clientID.duid_len == 0) {
        g_message("%s: no client ID option", __func__);
        return -1;
    } else {
        g_debug("%s: client ID %s", __func__, duidstr(&optinfo->clientID));
    }

    /* Make sure DUID LLT time field matches the client */
    if (duid_match_llt(&optinfo->clientID, &server_duid)) {
        g_message("failed to match DUID LLT time field between server "
                  "and client");
        return -1;
    }

    /* what kind of message did we receive? */
    switch (dh6->dh6_msgtype) {
            /* these messages must include a Server Identifier option */
        case DH6_REQUEST:
        case DH6_RENEW:
        case DH6_DECLINE:
        case DH6_RELEASE:
            if (optinfo->serverID.duid_len == 0) {
                g_message("%s: no server ID option", __func__);
                return -1;
            }

            /* the contents of the Server Identifier option must match ours */
            if (duidcmp(&optinfo->serverID, &server_duid)) {
                g_message("server ID %s mismatch %s",
                          duidstr(&optinfo->serverID), duidstr(&server_duid));
                return -1;
            }

            break;

            /* these messages must not include a Server Identifier option */
        case DH6_SOLICIT:
        case DH6_CONFIRM:
        case DH6_REBIND:
            if (optinfo->serverID.duid_len != 0) {
                g_message("%s: found server ID option in message "
                          "Solicit/Confirm/Rebind", __func__);
                return -1;
            }

            break;

        default:
            break;
    }

    /* configure necessary options based on the options in request. */
    dhcp6_init_options(&roptinfo);

    /* server information option */
    if (duidcpy(&roptinfo.serverID, &server_duid)) {
        g_error("%s: failed to copy server ID", __func__);
        goto fail;
    }

    /* copy client information back */
    if (duidcpy(&roptinfo.clientID, &optinfo->clientID)) {
        g_error("%s: failed to copy client ID", __func__);
        goto fail;
    }

    /* if the client is not on the link */
    if (host == NULL && subnet == NULL) {
        num = DH6OPT_STCODE_NOTONLINK;

        /* Draft-28 18.2.2, drop the message if NotOnLink */
        if (dh6->dh6_msgtype == DH6_CONFIRM || dh6->dh6_msgtype == DH6_REBIND) {
            goto fail;
        } else {
            goto send;
        }
    }

    if (subnet) {
        if (dhcp6_has_option(optinfo->reqopt_list, DH6OPT_PREFERENCE)) {
            roptinfo.pref = subnet->linkscope.server_pref;
        }

        roptinfo.flags = (optinfo->flags & subnet->linkscope.allow_flags) |
            subnet->linkscope.send_flags;

        if (dhcp6_has_option(optinfo->reqopt_list, DH6OPT_DNS_SERVERS) ||
            dhcp6_has_option(optinfo->reqopt_list, DH6OPT_DOMAIN_LIST)) {
            dnsinfo = subnet->linkscope.dnsinfo;
        }

        if (dhcp6_has_option(optinfo->reqopt_list, DH6OPT_INFO_REFRESH_TIME)) {
            roptinfo.irt = subnet->linkscope.irt;
        }
    }

    if (host) {
        if (dhcp6_has_option(optinfo->reqopt_list, DH6OPT_PREFERENCE)) {
            roptinfo.pref = host->hostscope.server_pref;
        }

        roptinfo.flags = (optinfo->flags & host->hostscope.allow_flags) |
            host->hostscope.send_flags;

        if (dhcp6_has_option(optinfo->reqopt_list, DH6OPT_DNS_SERVERS) ||
            dhcp6_has_option(optinfo->reqopt_list, DH6OPT_DOMAIN_LIST)) {
            dnsinfo = host->hostscope.dnsinfo;
        }

        if (dhcp6_has_option(optinfo->reqopt_list, DH6OPT_INFO_REFRESH_TIME)) {
            roptinfo.irt = host->hostscope.irt;
        }
    }

    /* prohibit a mixture of old and new style of DNS server config */
    if (dhcp6_has_option(optinfo->reqopt_list, DH6OPT_DNS_SERVERS)) {
        if (g_slist_length(arg_dnsinfo.servers)) {
            if (g_slist_length(dnsinfo.servers)) {
                g_message("%s: do not specify DNS servers both by command line "
                          "and by configuration file.", __func__);
                exit(1);
            }

            dnsinfo = arg_dnsinfo;
            dnsinfo.servers = NULL;
        }
    }

    if (dhcp6_has_option(optinfo->reqopt_list, DH6OPT_PREFERENCE)) {
        g_debug("server preference is %2x", roptinfo.pref);
    }

    if (roptinfo.flags & DHCIFF_UNICAST) {
        /* todo find the right server unicast address to client */
        /* get_linklocal(device, &roptinfo.server_addr) */
        memcpy(&roptinfo.server_addr, &ifp->linklocal,
               sizeof(roptinfo.server_addr));
        g_debug("%s: server address is %s", __func__,
                in6addr2str(&roptinfo.server_addr, 0));
    }

    /*
     * When the server receives a Request message via unicast from a
     * client to which the server has not sent a unicast option, the server
     * discards the Request message and responds with a Reply message
     * containing a Status Code option with value UseMulticast, a Server
     * Identifier option containing the server's DUID, the Client
     * Identifier option from the client message and no other options.
     * [dhcpv6-26 18.2.1]
     */
    switch (dh6->dh6_msgtype) {
        case DH6_REQUEST:
        case DH6_RENEW:
        case DH6_DECLINE:
            /*
             * If the message was relayed, then do not check whether the
             * message came in via unicast or multicast, since the relay
             * may be configured to send messages via unicast.
             */
            if (!g_slist_length(optinfo->relay_list) &&
                !IN6_IS_ADDR_MULTICAST(&pi->ipi6_addr)) {
                if (!(roptinfo.flags & DHCIFF_UNICAST)) {
                    num = DH6OPT_STCODE_USEMULTICAST;
                    goto send;
                } else {
                    break;
                }
            }

            break;
        case DH6_SOLICIT:
        case DH6_CONFIRM:
        case DH6_REBIND:
        case DH6_INFORM_REQ:
            /* A server MUST discard any Solicit, Confirm, Rebind or
             * Information-request * messages it receives with a unicast
             * destination address. [RFC3315 Section 15] */
            if (!g_slist_length(optinfo->relay_list) &&
                !IN6_IS_ADDR_MULTICAST(&pi->ipi6_addr)) {
                g_debug("reply no message as %s received with unicast "
                        "destination address", dhcp6msgstr(num));
                goto fail;
            }

            break;
        default:
            /*
             * If the message was relayed, then do not check whether the
             * message came in via unicast or multicast, since the relay
             * may be configured to send messages via unicast.
             */
            if (!g_slist_length(optinfo->relay_list) &&
                !IN6_IS_ADDR_MULTICAST(&pi->ipi6_addr)) {
                num = DH6OPT_STCODE_USEMULTICAST;
                goto send;
            }

            break;
    }

    switch (dh6->dh6_msgtype) {
        case DH6_SOLICIT:
            /*
             * If the client has included a Rapid Commit option and the
             * server has been configured to respond with committed address
             * assignments and other resources, responds to the Solicit
             * with a Reply message.
             * [dhcpv6-28 Section 17.2.1]
             * [dhcpv6-28 Section 17.2.2]
             * If Solicit has IA option, responds to Solicit with a Advertise
             * message.
             */
            if (g_slist_length(optinfo->ia_list) &&
                !(roptinfo.flags & DHCIFF_INFO_ONLY)) {
                resptype = (roptinfo.flags & DHCIFF_RAPID_COMMIT)
                    ? DH6_REPLY : DH6_ADVERTISE;
                if (_handle_addr_request(&roptinfo, roptinfo.ia_list,
                                         optinfo->ia_list, resptype, &num)) {
                    goto fail;
                }
            }

            break;
        case DH6_INFORM_REQ:
            /* don't response to info-req if there is any IA or server ID
             * option */
            if (g_slist_length(optinfo->ia_list) ||
                optinfo->serverID.duid_len) {
                goto fail;
            }

            break;
        case DH6_REQUEST:
            /* get iaid for that request client for that interface */
            if (g_slist_length(optinfo->ia_list) &&
                !(roptinfo.flags & DHCIFF_INFO_ONLY)) {
                if (_handle_addr_request(&roptinfo, roptinfo.ia_list,
                                         optinfo->ia_list, resptype, &num)) {
                    goto fail;
                }
            }

            break;
        case DH6_DECLINE:
        case DH6_RELEASE:
        case DH6_RENEW:
        case DH6_REBIND:
        case DH6_CONFIRM:
            /*
             * Locates the client's binding and verifies that the information
             * from the client matches the information stored for that client.
             */
            switch (dh6->dh6_msgtype) {
                case DH6_CONFIRM:
                    addr_flag = ADDR_VALIDATE;
                    break;
                case DH6_RENEW:
                case DH6_REBIND:
                    /*
                     * XXX: how server know the diff between rebind_confirm and
                     * rebind for prefix delegation?
                     */
                    addr_flag = ADDR_UPDATE;
                    break;
                case DH6_RELEASE:
                    addr_flag = ADDR_REMOVE;
                    break;
                case DH6_DECLINE:
                    addr_flag = ADDR_ABANDON;
                    break;
            }

            if (g_slist_length(optinfo->ia_list)) {
                if (_update_binding_ia(&roptinfo, roptinfo.ia_list,
                                       optinfo->ia_list, dh6->dh6_msgtype,
                                       addr_flag, &num)) {
                    goto fail;
                }
            } else {
                g_error("invalid message type");
            }

            break;
        default:
            break;
    }

    /* Options regarding DNS */
    switch (dh6->dh6_msgtype) {
        case DH6_SOLICIT:
        case DH6_REQUEST:
        case DH6_RENEW:
        case DH6_REBIND:
        case DH6_INFORM_REQ:
            /* DNS Recursive Name Server option */
            if (dhcp6_has_option(optinfo->reqopt_list, DH6OPT_DNS_SERVERS)) {
                roptinfo.dnsinfo.servers = g_slist_copy(dnsinfo.servers);
                if (roptinfo.dnsinfo.servers == NULL) {
                    g_error("%s: failed to copy DNS servers", __func__);
                    goto fail;
                }
            }

            /* Domain Search List option */
            if (dhcp6_has_option(optinfo->reqopt_list, DH6OPT_DOMAIN_LIST)) {
                roptinfo.dnsinfo.domains = dnsinfo.domains;
            }

            break;
    }

    /* Information refresh time option (RFC 4242) */
    if (dhcp6_has_option(optinfo->reqopt_list, DH6OPT_INFO_REFRESH_TIME)) {
        switch (dh6->dh6_msgtype) {
            case DH6_INFORM_REQ:
                if (roptinfo.irt == 0) {
                    roptinfo.irt = IRT_DEFAULT;
                }

                g_debug("information refresh time is %u", roptinfo.irt);
                break;
            default:
                g_message("Ignore the requirement to reply an information "
                          "refresh time option as the message is %s",
                          dhcp6msgstr(dh6->dh6_msgtype));
                roptinfo.irt = 0;
                break;
        }
    } else {
        /* make sure that the infomation refresh time is set to 0 */
        roptinfo.irt = 0;
    }

    /* add address status code */
send:
    g_debug(" status code: %s", dhcp6_stcodestr(num));
    roptinfo.status_code = num;

    /* send a reply message. */
    (void) _server6_send(resptype, ifp, dh6, optinfo, from, fromlen, &roptinfo);

    dhcp6_clear_options(&roptinfo);
    return 0;

fail:
    dhcp6_clear_options(&roptinfo);
    return -1;
}

static gboolean dh6_valid_message(guint8 type) {
    if ((type == DH6_SOLICIT) || (type == DH6_REQUEST) ||
        (type == DH6_RENEW) || (type == DH6_REBIND) ||
        (type == DH6_CONFIRM) || (type == DH6_RELEASE) ||
        (type == DH6_DECLINE) || (type == DH6_INFORM_REQ)) {
        return TRUE;
    } else {
        return FALSE;
    }
}

static gint _server6_recv(gint s) {
    ssize_t len;
    struct sockaddr_storage from;
    gint fromlen;
    struct msghdr mhdr;
    struct iovec iov;
    gchar cmsgbuf[BUFSIZ];
    struct cmsghdr *cm;
    struct in6_pktinfo *pi = NULL;
    dhcp6_if_t *ifp;
    dhcp6_t *dh6;
    dhcp6_optinfo_t optinfo;
    struct in6_addr relay;      /* the address of the first relay, if any */

    memset(&iov, 0, sizeof(iov));
    memset(&mhdr, 0, sizeof(mhdr));

    iov.iov_base = rdatabuf;
    iov.iov_len = sizeof(rdatabuf);
    mhdr.msg_name = &from;
    mhdr.msg_namelen = sizeof(from);
    mhdr.msg_iov = &iov;
    mhdr.msg_iovlen = 1;
    mhdr.msg_control = (caddr_t) cmsgbuf;
    mhdr.msg_controllen = sizeof(cmsgbuf);

    if ((len = recvmsg(iosock, &mhdr, 0)) < 0) {
        g_error("%s: recvmsg: %s", __func__, strerror(errno));
        return -1;
    }

    fromlen = mhdr.msg_namelen;

    for (cm = (struct cmsghdr *) CMSG_FIRSTHDR(&mhdr); cm;
         cm = (struct cmsghdr *) CMSG_NXTHDR(&mhdr, cm)) {
        if (cm->cmsg_level == IPPROTO_IPV6 &&
            cm->cmsg_type == IPV6_PKTINFO &&
            cm->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) {
            pi = (struct in6_pktinfo *) (CMSG_DATA(cm));
        }
    }

    if (pi == NULL) {
        g_message("%s: failed to get packet info", __func__);
        return -1;
    }

    g_debug("received message packet info addr is %s, scope id (%d)",
            in6addr2str(&pi->ipi6_addr, 0), (guint) pi->ipi6_ifindex);

    if ((ifp = find_ifconfbyid((guint) pi->ipi6_ifindex)) == NULL) {
        g_message("%s: unexpected interface (%d)", __func__,
                  (guint) pi->ipi6_ifindex);
        return -1;
    }

    if (len < sizeof(*dh6)) {
        g_message("%s: short packet", __func__);
        return -1;
    }

    dh6 = (dhcp6_t *) rdatabuf;
    g_debug("%s: received %s from %s", __func__, dhcp6msgstr(dh6->dh6_msgtype),
            addr2str((struct sockaddr *) &from, sizeof(from)));
    dhcp6_init_options(&optinfo);

    /*
     * If this is a relayed message, parse all of the relay data, storing
     * the link addresses, peer addresses, and interface identifiers for
     * later use. Get a pointer to the original client message.
     */
    if (dh6->dh6_msgtype == DH6_RELAY_FORW) {
        dh6 = _dhcp6_parse_relay((dhcp6_relay_t *) dh6,
                                 (dhcp6_relay_t *) (rdatabuf + len),
                                 &optinfo, &relay);

        /*
         * NULL means there was an error in the relay format or no
         * client message was found.
         */
        if (dh6 == NULL) {
            g_message("%s: failed to parse relay fields or could not find "
                      "client message", __func__);
            return -1;
        }
    }

    /*
     * parse and validate options in the request
     */
    if (dhcp6_get_options((dhcp6opt_t *) (dh6 + 1),
                          (dhcp6opt_t *) (rdatabuf + len),
                          &optinfo) < 0) {
        g_message("%s: failed to parse options", __func__);
        return -1;
    }

    /* check host decl first */
    host = dhcp6_allocate_host(ifp, globalgroup, &optinfo);
    /* ToDo: allocate subnet after relay agent done now assume client is on
     * the same link as server if the subnet couldn't be found return status
     * code NotOnLink to client */
    /* 
     * If the relay list is empty, then this is a message received directly
     * from the client, so client is on the same link as the server. 
     * Otherwise, allocate the client an address based on the first relay
     * that forwarded the message.
     */
    if (!g_slist_length(optinfo.relay_list)) {
        subnet = dhcp6_allocate_link(ifp, globalgroup, NULL);
    } else {
        subnet = dhcp6_allocate_link(ifp, globalgroup, &relay);
    }

    if (!dh6_valid_message(dh6->dh6_msgtype)) {
        g_message("%s: unknown or unsupported msgtype %s",
                  __func__, dhcp6msgstr(dh6->dh6_msgtype));
    } else {
        _server6_react_message(ifp, pi, dh6, &optinfo,
                               (struct sockaddr *) &from, fromlen);
    }

    dhcp6_clear_options(&optinfo);
    return 0;
}

static void _server6_mainloop(void) {
    struct timeval *w;
    gint ret;
    fd_set r;

    while (1) {
        w = dhcp6_check_timer();

        FD_ZERO(&r);
        FD_SET(iosock, &r);
        ret = select(iosock + 1, &r, NULL, NULL, w);
        switch (ret) {
            case -1:
                g_error("%s: select: %s", __func__, strerror(errno));
                exit(1);
                /* NOTREACHED */
            case 0:            /* timeout */
                break;
            default:
                break;
        }

        if (FD_ISSET(iosock, &r)) {
            if (_server6_recv(iosock)) {
                exit(1);
            }
        }
    }

    return;
}

static dhcp6_timer_t *_check_lease_file_timo(void *arg) {
    gdouble d;
    struct timeval timo;
    struct stat buf;
    FILE *file;

    strcpy(server6_lease_temp, PATH_SERVER6_LEASE);
    strcat(server6_lease_temp, "XXXXXX");

    if (!stat(PATH_SERVER6_LEASE, &buf)) {
        if (buf.st_size > MAX_FILE_SIZE) {
            file =
                sync_leases(server6_lease_file, PATH_SERVER6_LEASE,
                            server6_lease_temp);
            if (file != NULL) {
                server6_lease_file = file;
            }
        }
    }

    d = DHCP6_SYNCFILE_TIME;
    timo.tv_sec = (long) d;
    timo.tv_usec = 0;
    dhcp6_set_timer(&timo, sync_lease_timer);
    return sync_lease_timer;
}

/* END STATIC FUNCTIONS */

void server6_init(void) {
    struct addrinfo hints;
    struct addrinfo *res, *res2;
    gint error, skfd, i;
    gint on = 1;
    gint ifidx[MAX_DEVICE];
    struct ipv6_mreq mreq6;
    static struct iovec iov;
    static struct sockaddr_in6 sa6_any_downstream_storage;
    gchar buff[1024];
    struct ifconf ifc;
    struct ifreq *ifr;
    gdouble d;
    struct timeval timo;

    /* initialize socket for inbound packets */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_INET6;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_PASSIVE;
    error = getaddrinfo(NULL, DH6PORT_UPSTREAM_SERVICE, &hints, &res);

    if (error) {
        g_error("%s: getaddrinfo: %s", __func__, gai_strerror(error));
        exit(1);
    }

    iosock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (iosock < 0) {
        g_error("%s: socket: %s", __func__, strerror(errno));
        exit(1);
    }

#ifdef IPV6_RECVPKTINFO
    if (setsockopt(iosock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on,
                   sizeof(on)) < 0) {
        g_error("%s: setsockopt(inbound, IPV6_RECVPKTINFO): %s",
                __func__, strerror(errno));
        exit(1);
    }
#else
    if (setsockopt(iosock, IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof(on)) < 0) {
        g_error("%s: setsockopt(inbound, IPV6_PKTINFO): %s",
                __func__, strerror(errno));
        exit(1);
    }
#endif

    if (bind(iosock, res->ai_addr, res->ai_addrlen) < 0) {
        g_error("%s: bind: %s", __func__, strerror(errno));
        exit(1);
    }

    upstream_port = ((struct sockaddr_in6 *) res->ai_addr)->sin6_port;
    freeaddrinfo(res);

    /* initiallize socket address structure for outbound packets */
    hints.ai_flags = AI_PASSIVE;

    error = getaddrinfo(NULL, DH6PORT_DOWNSTREAM_SERVICE, &hints, &res);
    if (error) {
        g_error("%s: getaddrinfo: %s", __func__, gai_strerror(error));
        exit(1);
    }

    memcpy(&sa6_any_downstream_storage, res->ai_addr, res->ai_addrlen);
    sa6_any_downstream =
        (const struct sockaddr_in6 *) &sa6_any_downstream_storage;
    freeaddrinfo(res);

    /* initialize send/receive buffer */
    iov.iov_base = (caddr_t) rdatabuf;
    iov.iov_len = sizeof(rdatabuf);
    rmh.msg_iov = &iov;
    rmh.msg_iovlen = 1;

    rmsgctllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
    if ((rmsgctlbuf = (gchar *) g_malloc0(rmsgctllen)) == NULL) {
        g_error("%s: memory allocation failed", __func__);
        exit(1);
    }

    if (num_device != 0) {
        for (i = 0; i < num_device; i++) {
            ifidx[i] = if_nametoindex(device[i]);

            if (ifidx[i] == 0) {
                g_error("%s: invalid interface %s", __func__, device[0]);
                exit(1);
            }

            ifinit(device[i]);
        }

        if (get_duid(DUID_FILE, device[0], &server_duid)) {
            g_error("%s: failed to get a DUID", __func__);
            exit(1);
        }

        if (save_duid(DUID_FILE, device[0], &server_duid)) {
            g_error("%s: failed to save server ID", __func__);
        }
    } else {
        /* all the interfaces join multicast group */
        ifc.ifc_len = sizeof(buff);
        ifc.ifc_buf = buff;

        if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            g_error("new socket failed");
            exit(1);
        }

        if (ioctl(skfd, SIOCGIFCONF, &ifc) < 0) {
            g_error("SIOCGIFCONF: %s", strerror(errno));
            exit(1);
        }

        ifr = ifc.ifc_req;

        for (i = ifc.ifc_len / sizeof(struct ifreq); --i >= 0; ifr++) {
            g_debug("found device %s", ifr->ifr_name);
            ifidx[num_device] = if_nametoindex(ifr->ifr_name);

            if (ifidx[num_device] < 0) {
                g_error("%s: unknown interface", ifr->ifr_name);
                continue;
            }

            g_debug("if %s index is %d", ifr->ifr_name, ifidx[num_device]);

            if (g_strcmp0(ifr->ifr_name, "lo")) {
                /* get our DUID */
                if (get_duid(DUID_FILE, ifr->ifr_name, &server_duid)) {
                    g_error("%s: failed to get a DUID", __func__);
                    exit(1);
                }

                if (save_duid(DUID_FILE, ifr->ifr_name, &server_duid)) {
                    g_error("%s: failed to save server ID", __func__);
                }
            }

            ifinit(ifr->ifr_name);
            num_device += 1;
        }
    }

    for (i = 0; i < num_device; i++) {
        hints.ai_flags = 0;
        error = getaddrinfo(DH6ADDR_ALLAGENT, DH6PORT_UPSTREAM_SERVICE,
                            &hints, &res2);
        if (error) {
            g_error("%s: getaddrinfo: %s", __func__, gai_strerror(error));
            exit(1);
        }

        memset(&mreq6, 0, sizeof(mreq6));
        mreq6.ipv6mr_interface = ifidx[i];
        memcpy(&mreq6.ipv6mr_multiaddr,
               &((struct sockaddr_in6 *) res2->ai_addr)->sin6_addr,
               sizeof(mreq6.ipv6mr_multiaddr));

        if (setsockopt(iosock, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                       &mreq6, sizeof(mreq6))) {
            g_error("%s: setsockopt(iosock, IPV6_JOIN_GROUP) %s",
                    __func__, strerror(errno));
            exit(1);
        }

        freeaddrinfo(res2);

        hints.ai_flags = 0;
        error = getaddrinfo(DH6ADDR_ALLSERVER, DH6PORT_UPSTREAM_SERVICE,
                            &hints, &res2);

        if (error) {
            g_error("%s: getaddrinfo: %s", __func__, gai_strerror(error));
            exit(1);
        }

        memset(&mreq6, 0, sizeof(mreq6));
        mreq6.ipv6mr_interface = ifidx[i];
        memcpy(&mreq6.ipv6mr_multiaddr,
               &((struct sockaddr_in6 *) res2->ai_addr)->sin6_addr,
               sizeof(mreq6.ipv6mr_multiaddr));

        if (setsockopt(iosock, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                       &mreq6, sizeof(mreq6))) {
            g_error("%s: setsockopt(iosock, IPV6_JOIN_GROUP): %s",
                    __func__, strerror(errno));
            exit(1);
        }

        freeaddrinfo(res2);

        /* set outgoing interface of multicast packets for DHCP reconfig */
        if (setsockopt(iosock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                       &ifidx[i], sizeof(ifidx[i])) < 0) {
            g_error("%s: setsockopt(iosock, IPV6_MULTICAST_IF): %s",
                    __func__, strerror(errno));
            exit(1);
        }
    }

    /* set up sync lease file timer */
    sync_lease_timer = dhcp6_add_timer(_check_lease_file_timo, NULL);
    d = DHCP6_SYNCFILE_TIME;
    timo.tv_sec = (long) d;
    timo.tv_usec = 0;
    g_debug("set timer for syncing file ...");
    dhcp6_set_timer(&timo, sync_lease_timer);
    return;
}

gint main(gint argc, gchar **argv) {
    gchar *progname = basename(argv[0]);
    gint i;
    gchar *conffile = NULL;
    FILE *pidfp = NULL;
    server_interface_t *ifnetwork = NULL;
    log_properties_t log_props;
    GSList *iterator = NULL;
    GError *error = NULL;
    GOptionContext *context = NULL;
    GOptionEntry entries[] = {
        { "conf-file", 'c', 0, G_OPTION_ARG_STRING,
              &conffile,
              "Server configuration file",
              "PATH" },
        { "pid-file", 'p', 0, G_OPTION_ARG_STRING,
              &pidfile,
              "PID file",
              "PATH" },
        { "foreground", 'f', 0, G_OPTION_ARG_NONE,
              &log_props.foreground,
              "Run server in the foreground",
              NULL },
        { "verbose", 'v', 0, G_OPTION_ARG_NONE,
              &log_props.verbose,
              "Verbose log output",
              NULL },
        { "debug", 'd', 0, G_OPTION_ARG_NONE,
              &log_props.debug,
              "Debugging log output (implies -v)",
              NULL },
        { NULL }
    };

    arg_dnsinfo.servers = NULL;
    arg_dnsinfo.domains = NULL;

    random_init();

    context = g_option_context_new("[interface]");
    g_option_context_set_summary(context, "DHCPv6 server daemon");
    g_option_context_set_description(context,
       "PATH is a valid path specification for the system.\n\n"
       "For more details on the dhcp6s program, see the dhcp6s(8) man page.\n\n"
       "Please report bugs at http://fedorahosted.org/dhcpv6/");
    g_option_context_add_main_entries(context, entries, NULL);

    if (!g_option_context_parse(context, &argc, &argv, &error)) {
        g_error("option parsing failed: %s", error->message);
        return EXIT_FAILURE;
    }

    if (conffile == NULL) {
        conffile = DHCP6S_CONF;
    }

    if (pidfile == NULL) {
        pidfile = DHCP6S_PIDFILE;
    }

    i = 1;
    while (i < argc) {
        device[num_device] = argv[i++];
        num_device += 1;
    }

    if (log_props.foreground) {
        if (daemon(0, 0) < 0) {
            err(1, "daemon");
        }
    }

    log_props.pid = getpid();
    setup_logging(progname, &log_props);

    server6_init();

    if ((server6_lease_file = init_leases(PATH_SERVER6_LEASE)) == NULL) {
        g_error("%s: failed to parse lease file", __func__);
        exit(1);
    }

    strcpy(server6_lease_temp, PATH_SERVER6_LEASE);
    strcat(server6_lease_temp, "XXXXXX");
    server6_lease_file =
        sync_leases(server6_lease_file, PATH_SERVER6_LEASE,
                    server6_lease_temp);

    if (server6_lease_file == NULL) {
        exit(1);
    }

    globalgroup = (rootgroup_t *) g_malloc0(sizeof(rootgroup_t));
    if (globalgroup == NULL) {
        g_error("failed to allocate memory %s", strerror(errno));
        exit(1);
    }

    globalgroup->scope.dnsinfo.servers = NULL;

    if ((sfparse(conffile)) != 0) {
        g_error("%s: failed to parse addr configuration file", __func__);
        exit(1);
    }

    iterator = globalgroup->iflist;

    while (iterator) {
        ifnetwork = (server_interface_t *) iterator->data;

        if (!g_slist_length(ifnetwork->linklist)) {
            /* If there was no link defined in the conf file, make an empty
             * one. */
            link_decl_t *link = (link_decl_t *) g_malloc0(sizeof(*subnet));
            if (link == NULL) {
                g_error("failed to allocate memory");
                exit(1);
            }

            link->linkscope.dnsinfo.servers = NULL;
            ifnetwork->linklist = g_slist_append(ifnetwork->linklist, link);
        }

        iterator = g_slist_next(iterator);
    }

    if (signal(SIGHUP, _server6_sighandler) == SIG_ERR) {
        g_warning("%s: failed to set signal: %s", __func__, strerror(errno));
        return -1;
    }

    if (signal(SIGTERM, _server6_sighandler) == SIG_ERR) {
        g_warning("%s: failed to set signal: %s", __func__, strerror(errno));
        return -1;
    }

    if (signal(SIGINT, _server6_sighandler) == SIG_ERR) {
        g_warning("%s: failed to set signal: %s", __func__, strerror(errno));
        return -1;
    }

    /* dump current PID */
    if ((pidfp = fopen(pidfile, "w")) != NULL) {
        fprintf(pidfp, "%d\n", getpid());
        fclose(pidfp);
    } else {
        fprintf(stderr, "Unable to write to %s: %s\n", pidfile,
                strerror(errno));
        fflush(stderr);
        abort();
    }

    _server6_mainloop();
    exit(0);
}

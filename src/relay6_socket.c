/*
 * Copyright (C) NEC Europe Ltd., 2003
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
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <glib.h>

#include "duid.h"
#include "dhcp6.h"
#include "dhcp6r.h"
#include "relay6_socket.h"
#include "relay6_parser.h"
#include "relay6_database.h"
#include "gfunc.h"

#ifndef IPV6_2292PKTINFO
#define IPV6_2292PKTINFO IPV6_PKTINFO
#endif

typedef struct _relay_forw_data_t {
    struct msg_parser *mesg;
    gboolean hit;
} relay_forw_data_t;

/* BEGIN STATIC FUNCTIONS */

static void _send_relay_forw(gpointer data, gpointer user_data) {
    gchar *si = (gchar *) data;
    relay_forw_data_t *relay_forw = (relay_forw_data_t *) user_data;
    struct sockaddr_in6 sin6;
    guint32 count = 0;
    gchar dest_addr[INET6_ADDRSTRLEN];
    gint recvmsglen;
    gchar *recvp = NULL;
    struct cmsghdr *cmsgp = NULL;
    struct in6_pktinfo *in6_pkt = NULL;
    struct msghdr msg;
    struct interface *iface = NULL;
    struct iovec iov[1];

    *(relay_forw->mesg->hc_pointer) = MAXHOPCOUNT;
    memset(&sin6, '\0', sizeof(struct sockaddr_in6));
    sin6.sin6_family = AF_INET6;

    memset(dest_addr, 0, INET6_ADDRSTRLEN);
    g_stpcpy(dest_addr, ALL_DHCP_SERVERS);

    /* destination address */
    if (inet_pton(AF_INET6, dest_addr, &sin6.sin6_addr) <= 0) {
        g_error("%s: inet_pton() failure", __func__);
        return;
    }

    recvmsglen = CMSG_SPACE(sizeof(struct in6_pktinfo));
    recvp = (gchar *) g_malloc0(recvmsglen * sizeof(gchar));

    if (recvp == NULL) {
        g_error("%s: memory allocation error", __func__);
        abort();
    }

    cmsgp = (struct cmsghdr *) recvp;
    cmsgp->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
    cmsgp->cmsg_level = IPPROTO_IPV6;
    cmsgp->cmsg_type = IPV6_2292PKTINFO;
    in6_pkt = (struct in6_pktinfo *) CMSG_DATA(cmsgp);
    msg.msg_control = (void *) recvp;
    msg.msg_controllen = recvmsglen;

    /* destination address */
    if (inet_pton(AF_INET6, dest_addr, &sin6.sin6_addr) <= 0) {
        g_error("%s: inet_pton() failure", __func__);
        return;
    }

    in6_pkt->ipi6_ifindex = if_nametoindex(si);
    sin6.sin6_scope_id = in6_pkt->ipi6_ifindex;

    g_debug("%s: outgoing device index: %d", __func__,
    in6_pkt->ipi6_ifindex);
    iface = get_interface(in6_pkt->ipi6_ifindex);

    if (iface == NULL) {
        g_error("%s: no interface found", __func__);
        exit(0);
    }

    if (inet_pton(AF_INET6, iface->ipv6addr->gaddr,
                  &in6_pkt->ipi6_addr) <= 0) {
        /* source address */
        g_error("%s: inet_pton() failure", __func__);
        abort();
    }

    g_debug("%s: source address: %s", __func__, iface->ipv6addr->gaddr);

    sin6.sin6_port = htons(SERVER_PORT);

    iov[0].iov_base = relay_forw->mesg->buffer;
    iov[0].iov_len = relay_forw->mesg->datalength;
    msg.msg_name = (void *) &sin6;
    msg.msg_namelen = sizeof(sin6);
    msg.msg_iov = &iov[0];
    msg.msg_iovlen = 1;

    if ((count = sendmsg(relaysock->sock_desc, &msg, 0)) < 0) {
        g_error("%s: sendmsg failure: %s", __func__, strerror(errno));
        return;
    }

    if (count > MAX_DHCP_MSG_LENGTH) {
        g_error("%s: sendmsg sent %d bytes while MAX_DHCP_MSG_LENGTH is %d",
                __func__, count, MAX_DHCP_MSG_LENGTH);
    }

    g_debug("%s: => relay_forw, sent to: %s snet_bytes: %d",
            __func__, dest_addr, count);

    free(recvp);
    relay_forw->hit = TRUE;
    return;
}

/* END STATIC FUNCTIONS */

void init_socket(void) {
    relaysock = (struct relay_socket *) g_malloc0(sizeof(struct relay_socket));

    if (relaysock == NULL) {
        g_error("%s: memory allocation error", __func__);
        exit(1);
    }

    relaysock->databuf = (gchar *) g_malloc0(MAX_DHCP_MSG_LENGTH*sizeof(gchar));

    if (relaysock->databuf == NULL) {
        g_error("%s: memory allocation error", __func__);
        exit(1);
    }

    if ((relaysock->sock_desc = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
        g_error("%s: failed to get new socket", __func__);
        exit(0);
    }
}

gint get_recv_data(void) {
    struct cmsghdr *cm;
    struct in6_pktinfo *pi;
    struct sockaddr_in6 dst;

    memset(relaysock->src_addr, 0, sizeof(relaysock->src_addr));

    for (cm = (struct cmsghdr *) CMSG_FIRSTHDR(&relaysock->msg); cm;
         cm = (struct cmsghdr *) CMSG_NXTHDR(&relaysock->msg, cm)) {
        if ((cm->cmsg_level == IPPROTO_IPV6)
            && (cm->cmsg_type == IPV6_2292PKTINFO)
            && (cm->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo)))) {
            pi = (struct in6_pktinfo *) (CMSG_DATA(cm));
            dst.sin6_addr = pi->ipi6_addr;
            relaysock->pkt_interface = pi->ipi6_ifindex;        /* the
                                                                 * interface
                                                                 * index the
                                                                 * packet got
                                                                 * in */

            if (IN6_IS_ADDR_LOOPBACK(&relaysock->from.sin6_addr)) {
                g_error("%s: source address is loopback", __func__);
                return 0;
            }

            if (inet_ntop(AF_INET6, &relaysock->from.sin6_addr,
                          relaysock->src_addr, INET6_ADDRSTRLEN) <= 0) {
                g_error("%s: inet_ntop failure", __func__);
                return 0;
            }

            if (IN6_IS_ADDR_LOOPBACK(&dst.sin6_addr)) {
                relaysock->dst_addr_type = 1;
            } else if (IN6_IS_ADDR_MULTICAST(&dst.sin6_addr)) {
                relaysock->dst_addr_type = 2;

                if (multicast_off == 1) {
                    g_error("%s: received multicast packet is dropped, "
                            "only unicast is allowed", __func__);
                    return 0;
                }
            } else if (IN6_IS_ADDR_LINKLOCAL(&dst.sin6_addr)) {
                relaysock->dst_addr_type = 3;
            } else if (IN6_IS_ADDR_SITELOCAL(&dst.sin6_addr)) {
                relaysock->dst_addr_type = 4;
            }

            return 1;
        }
    }                           /* for */

    return 0;
}

gint check_select(void) {
    gint i = 0;
    gint flag = 0;
    struct timeval tv;

    tv.tv_sec = 0;
    tv.tv_usec = 0;

    FD_ZERO(&readfd);
    /* check the max of them if many desc used */
    fdmax = relaysock->sock_desc;
    FD_SET(fdmax, &readfd);

    if ((i = select(fdmax + 1, &readfd, NULL, NULL, &tv)) == -1) {
        g_error("%s: select() failure", __func__);
        return 0;
    }

    if (FD_ISSET(fdmax, &readfd)) {
        flag = 1;
    } else {
        flag = 0;
    }

    return flag;
}

gint set_sock_opt(void) {
    gint on = 1;
    gint hop_limit;
    struct interface *device;
    gint flag;
    struct ipv6_mreq sock_opt;

    /* If the relay agent relays messages to the All_DHCP_Servers multicast
     * address or other multicast addresses, it sets the Hop Limit field to
     * 32. [RFC3315 Section 20] */
    hop_limit = 32;
    if (setsockopt(relaysock->sock_desc, IPPROTO_IPV6,
                   IPV6_MULTICAST_HOPS, &hop_limit, sizeof(hop_limit)) < 0) {
        g_error("%s: failed to set socket for IPV6_MULTICAST_HOPS", __func__);
        return 0;
    }

    if (setsockopt(relaysock->sock_desc, IPPROTO_IPV6, IPV6_2292PKTINFO,
                   &on, sizeof(on)) < 0) {
        g_error("%s: failed to set socket for IPV6_2292PKTINFO", __func__);
        return 0;
    }

    for (device = interface_list.next; device != &interface_list;
         device = device->next) {
        flag = 0;
        if (g_slist_find_custom(cifaces_list, device->ifname,
                                _find_string) != NULL) {
            flag = 1;
            break;
        }

        if (flag == 0) {
            continue;
        }

        sock_opt.ipv6mr_interface = device->devindex;

        if (inet_pton(AF_INET6, ALL_DHCP_RELAY_AND_SERVERS,
                      &sock_opt.ipv6mr_multiaddr) <= 0) {
            g_error("%s: failed to set struct for multicast receive", __func__);
            return 0;
        }

        if (setsockopt(relaysock->sock_desc, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                       (gchar *) &sock_opt, sizeof(sock_opt)) < 0) {
            g_error("%s: failed to set socket option for IPV6_JOIN_GROUP",
                    __func__);
            return 0;
        }
    }

    g_debug("%s: socket options are set", __func__);
    return 1;
}


gint fill_addr_struct(void) {
    memset((gchar *) &relaysock->from, 0, sizeof(struct sockaddr_in6));

    relaysock->from.sin6_family = AF_INET6;
    relaysock->from.sin6_addr = in6addr_any;
    relaysock->from.sin6_port = htons(SERVER_PORT);

    relaysock->iov[0].iov_base = relaysock->databuf;
    relaysock->iov[0].iov_len = MAX_DHCP_MSG_LENGTH;
    relaysock->msg.msg_name = (void *) &relaysock->from;
    relaysock->msg.msg_namelen = sizeof(relaysock->from);
    relaysock->msg.msg_iov = &relaysock->iov[0];
    relaysock->msg.msg_iovlen = 1;

    relaysock->recvmsglen = CMSG_SPACE(sizeof(struct in6_pktinfo));
    relaysock->recvp = (gchar *) g_malloc0(relaysock->recvmsglen*sizeof(gchar));
    relaysock->msg.msg_control = (void *) relaysock->recvp;
    relaysock->msg.msg_controllen = relaysock->recvmsglen;

    if (bind(relaysock->sock_desc, (struct sockaddr *) &relaysock->from,
             sizeof(relaysock->from)) < 0) {
        perror("bind");
        return 0;
    }

    return 1;
}

gint recv_data(void) {
    gint count = -1;

    memset(relaysock->databuf, 0, (MAX_DHCP_MSG_LENGTH * sizeof(gchar)));

    if ((count = recvmsg(relaysock->sock_desc, &relaysock->msg, 0)) < 0) {
        g_error("%s: failed to receive data with recvmsg()", __func__);
        return -1;
    }

    relaysock->buflength = count;

    return 1;
}

gint get_interface_info(void) {
    FILE *f;
    gchar addr6[40], devname[20];
    struct sockaddr_in6 sap;
    gint plen, scope, dad_status, if_idx;
    gchar addr6p[8][5];
    gchar src_addr[INET6_ADDRSTRLEN];
    struct interface *device = NULL, *next_device;
    gint opaq = OPAQ;
    gint sw = 0;
    struct IPv6_address *ipv6addr;

    if ((f = fopen(INTERFACEINFO, "r")) == NULL) {
        g_error("%s: could not open file", __func__);
        return 0;
    }

    while (fscanf(f, "%4s%4s%4s%4s%4s%4s%4s%4s %02x %02x %02x %02x %20s\n",
                  addr6p[0], addr6p[1], addr6p[2], addr6p[3], addr6p[4],
                  addr6p[5], addr6p[6], addr6p[7], &if_idx, &plen, &scope,
                  &dad_status, devname) != EOF) {
        memset(src_addr, 0, INET6_ADDRSTRLEN);
        sprintf(addr6, "%s:%s:%s:%s:%s:%s:%s:%s", addr6p[0], addr6p[1],
                addr6p[2], addr6p[3], addr6p[4], addr6p[5], addr6p[6],
                addr6p[7]);
        sap.sin6_family = AF_INET6;
        sap.sin6_port = 0;

        if (inet_pton(AF_INET6, addr6, sap.sin6_addr.s6_addr) <= 0) {
            return 0;
        }

        if (inet_ntop(AF_INET6, &sap.sin6_addr, src_addr,
                      sizeof(src_addr)) <= 0) {
            return 0;
        }

        if (IN6_IS_ADDR_LOOPBACK(&sap.sin6_addr)) {
            continue;
        }

        sw = 0;
        for (device = interface_list.next; device != &interface_list;
             device = device->next) {
            if (device->devindex == if_idx) {
                sw = 1;
                break;
            }
        }

        if (sw == 0) {
            opaq += 10;
            device = (struct interface *) g_malloc0(sizeof(struct interface));

            if (device == NULL) {
                g_error("%s: memory allocation error", __func__);
                exit(1);
            }

            device->opaq = opaq;
            device->ifname = strdup(devname);
            device->devindex = if_idx;
            device->ipv6addr = NULL;
            device->prev = &interface_list;
            device->next = interface_list.next;
            device->prev->next = device;
            device->next->prev = device;
            nr_of_devices += 1;
        }

        if (IN6_IS_ADDR_LINKLOCAL(&sap.sin6_addr)) {
            device->link_local = strdup(src_addr);
            g_debug("%s: devname: %s, index: %d, link local addr: %s",
                    __func__, devname, if_idx, src_addr);
        } else {
            ipv6addr = (struct IPv6_address *)
                g_malloc0(sizeof(struct IPv6_address));

            if (ipv6addr == NULL) {
                g_error("%s: memory allocation error", __func__);
                exit(1);
            }

            ipv6addr->gaddr = strdup(src_addr);
            ipv6addr->next = NULL;

            if (device->ipv6addr != NULL) {
                ipv6addr->next = device->ipv6addr;
            }

            device->ipv6addr = ipv6addr;
        }
    }                           /* while */

    for (device = interface_list.next; device != &interface_list;) {
        next_device = device->next;

        if (device->ipv6addr == NULL) {
            g_debug("%s: remove interface %s as it does not have any "
                    "global address", __func__, device->ifname);
            nr_of_devices--;
            device->prev->next = device->next;
            device->next->prev = device->prev;
            free(device->ifname);

            if (device->link_local != NULL) {
                free(device->link_local);
            }

            free(device);
        }

        device = next_device;
    }

    fclose(f);
    return 1;
}

gint send_message(void) {
    struct sockaddr_in6 sin6;   /* my address information */
    struct msghdr msg;
    guint32 count = 0;
    struct in6_pktinfo *in6_pkt;
    struct cmsghdr *cmsgp;
    gchar dest_addr[INET6_ADDRSTRLEN];
    struct IPv6_uniaddr *ipv6uni;
    struct interface *iface;
    struct iovec iov[1];
    gint recvmsglen;
    gchar *recvp;
    struct server *uservers;
    relay_forw_data_t relay_forw;

    relay_forw.hit = FALSE;

    if ((relay_forw.mesg = get_send_messages_out()) == NULL) {
        return 0;
    }

    if (relay_forw.mesg->sent == 1) {
        return 0;
    }

    memset(&sin6, '\0', sizeof(struct sockaddr_in6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_flowinfo = 0;
    sin6.sin6_scope_id = 0;

    if (relay_forw.mesg->msg_type == DH6_RELAY_REPL) {
        memset(dest_addr, 0, INET6_ADDRSTRLEN);
        memcpy(dest_addr, relay_forw.mesg->peer_addr, INET6_ADDRSTRLEN);

        recvmsglen = CMSG_SPACE(sizeof(struct in6_pktinfo));
        recvp = (gchar *) g_malloc0(recvmsglen * sizeof(gchar));

        if (recvp == NULL) {
            g_error("%s: memory allocation error", __func__);
            exit(1);
        }

        cmsgp = (struct cmsghdr *) recvp;
        cmsgp->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
        cmsgp->cmsg_level = IPPROTO_IPV6;
        cmsgp->cmsg_type = IPV6_2292PKTINFO;
        in6_pkt = (struct in6_pktinfo *) CMSG_DATA(cmsgp);
        msg.msg_control = (void *) recvp;
        msg.msg_controllen = recvmsglen;

        /* destination address */
        if (inet_pton(AF_INET6, dest_addr, &sin6.sin6_addr) <= 0) {
            g_error("%s: inet_pton() failure", __func__);
            exit(1);
        }

        sin6.sin6_scope_id = relay_forw.mesg->if_index;

        if (relay_forw.mesg->hop > 0) {
            sin6.sin6_port = htons(SERVER_PORT);
        } else {
            sin6.sin6_port = htons(CLIENT_PORT);
        }

        iface = get_interface(relay_forw.mesg->if_index);

        if (iface != NULL) {
            gchar *src_addr;

            if (IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr)) {
                src_addr = iface->link_local;
            } else {
                src_addr = iface->ipv6addr->gaddr;
            }

            if (inet_pton(AF_INET6, src_addr, &in6_pkt->ipi6_addr) <= 0) {
                /* source address */
                g_error("%s: inet_pton() failure", __func__);
                exit(1);
            }

            g_debug("%s: source address: %s", __func__, src_addr);
        } else {
            /* the kernel will choose the source address */
            memset(&in6_pkt->ipi6_addr, 0, sizeof(in6_pkt->ipi6_addr));
        }

        /* OUTGOING DEVICE FOR RELAY_REPLY MSG */
        in6_pkt->ipi6_ifindex = relay_forw.mesg->if_index;
        g_debug("%s: outgoing device index: %d", __func__,
                in6_pkt->ipi6_ifindex);
        g_debug("%s: destination port: %d", __func__,
              ntohs(sin6.sin6_port));

        iov[0].iov_base = relay_forw.mesg->buffer;
        iov[0].iov_len = relay_forw.mesg->datalength;
        msg.msg_name = (void *) &sin6;
        msg.msg_namelen = sizeof(sin6);
        msg.msg_iov = &iov[0];
        msg.msg_iovlen = 1;

        if ((count = sendmsg(relaysock->sock_desc, &msg, 0)) < 0) {
            perror("sendmsg");
            return 0;
        }

        if (count > MAX_DHCP_MSG_LENGTH) {
            perror("bytes in sendmsg");
        }

        g_debug("%s: *> relay_repl, sent to: %s sent_bytes: %d",
                __func__, dest_addr, count);

        free(recvp);

        relay_forw.mesg->sent = 1;
        return 1;
    }

    if (relay_forw.mesg->msg_type == DH6_RELAY_FORW) {
        for (ipv6uni = IPv6_uniaddr_list.next; ipv6uni != &IPv6_uniaddr_list;
             ipv6uni = ipv6uni->next) {
            memset(&sin6, '\0', sizeof(struct sockaddr_in6));
            sin6.sin6_family = AF_INET6;

            memset(dest_addr, 0, INET6_ADDRSTRLEN);
            memcpy(dest_addr, ipv6uni->uniaddr, INET6_ADDRSTRLEN);

            /* destination address */
            if (inet_pton(AF_INET6, dest_addr, &sin6.sin6_addr) <= 0) {
                g_error("%s: inet_pton() failure", __func__);
                return 0;
            }

            recvmsglen = CMSG_SPACE(sizeof(struct in6_pktinfo));
            recvp = (gchar *) g_malloc0(recvmsglen * sizeof(gchar));

            if (recvp == NULL) {
                g_error("%s: memory allocation error", __func__);
                exit(1);
            }

            cmsgp = (struct cmsghdr *) recvp;
            cmsgp->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
            cmsgp->cmsg_level = IPPROTO_IPV6;
            cmsgp->cmsg_type = IPV6_2292PKTINFO;
            in6_pkt = (struct in6_pktinfo *) CMSG_DATA(cmsgp);
            msg.msg_control = (void *) recvp;
            msg.msg_controllen = recvmsglen;

            /* destination address */
            if (inet_pton(AF_INET6, dest_addr, &sin6.sin6_addr) <= 0) {
                g_error("%s: inet_pton() failure", __func__);
                return 0;
            }

            sin6.sin6_scope_id = 0;
            sin6.sin6_port = htons(SERVER_PORT);

            /* the kernel will choose the source address */
            memset(&in6_pkt->ipi6_addr, 0, sizeof(in6_pkt->ipi6_addr));
            /* OUTGOING DEVICE FOR RELAY_REPLY MSG */
            in6_pkt->ipi6_ifindex = 0;

            iov[0].iov_base = relay_forw.mesg->buffer;
            iov[0].iov_len = relay_forw.mesg->datalength;
            msg.msg_name = (void *) &sin6;
            msg.msg_namelen = sizeof(sin6);
            msg.msg_iov = &iov[0];
            msg.msg_iovlen = 1;

            if ((count = sendmsg(relaysock->sock_desc, &msg, 0)) < 0) {
                perror("sendmsg");
                return 0;
            }

            if (count > MAX_DHCP_MSG_LENGTH) {
                perror("bytes sendmsg");
            }

            g_debug("%s: => relay_forw, sent to: %s sent_bytes: %d",
                    __func__, dest_addr, count);
            free(recvp);
            relay_forw.hit = TRUE;
        }                       /* for */

        for (iface = interface_list.next; iface != &interface_list;
             iface = iface->next) {
            uservers = iface->sname;

            while (uservers != NULL) {
                memset(&sin6, '\0', sizeof(struct sockaddr_in6));
                sin6.sin6_family = AF_INET6;

                memset(dest_addr, 0, INET6_ADDRSTRLEN);
                memcpy(dest_addr, uservers->serv, INET6_ADDRSTRLEN);

                /* destination address */
                if (inet_pton(AF_INET6, dest_addr, &sin6.sin6_addr) <= 0) {
                    g_error("%s: inet_pton() failure", __func__);
                    exit(1);
                }

                recvmsglen = CMSG_SPACE(sizeof(struct in6_pktinfo));
                recvp = (gchar *) g_malloc0(recvmsglen * sizeof(gchar));

                if (recvp == NULL) {
                    g_error("%s: memory allocation error", __func__);
                    exit(1);
                }

                cmsgp = (struct cmsghdr *) recvp;
                cmsgp->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
                cmsgp->cmsg_level = IPPROTO_IPV6;
                cmsgp->cmsg_type = IPV6_2292PKTINFO;
                in6_pkt = (struct in6_pktinfo *) CMSG_DATA(cmsgp);
                msg.msg_control = (void *) recvp;
                msg.msg_controllen = recvmsglen;

                /* destination address */
                if (inet_pton(AF_INET6, dest_addr, &sin6.sin6_addr) <= 0) {
                    g_error("%s: inet_pton() failure", __func__);
                    return 0;
                }

                in6_pkt->ipi6_ifindex = iface->devindex;
                sin6.sin6_scope_id = in6_pkt->ipi6_ifindex;

                g_debug("%s: outgoing device index: %d", __func__,
                        in6_pkt->ipi6_ifindex);
                if (inet_pton(AF_INET6, iface->ipv6addr->gaddr,
                              &in6_pkt->ipi6_addr) <= 0) {
                    /* source address */
                    g_error("%s: inet_pton() failure", __func__);
                    exit(1);
                }

                g_debug("%s: source address: %s", __func__,
                        iface->ipv6addr->gaddr);

                sin6.sin6_port = htons(SERVER_PORT);

                iov[0].iov_base = relay_forw.mesg->buffer;
                iov[0].iov_len = relay_forw.mesg->datalength;
                msg.msg_name = (void *) &sin6;
                msg.msg_namelen = sizeof(sin6);
                msg.msg_iov = &iov[0];
                msg.msg_iovlen = 1;

                if ((count = sendmsg(relaysock->sock_desc, &msg, 0)) < 0) {
                    perror("sendmsg");
                    return 0;
                }

                if (count > MAX_DHCP_MSG_LENGTH) {
                    perror("bytes sendmsg");
                }

                g_debug("%s: => relay_forw, sent to: %s sent_bytes: %d",
                        __func__, dest_addr, count);
                free(recvp);
                uservers = uservers->next;
                relay_forw.hit = TRUE;
            }                   /* while */
        }                       /* Interfaces */

        g_slist_foreach(sifaces_list, _send_relay_forw, (gpointer) &relay_forw);

        if (relay_forw.hit) {
            for (iface = interface_list.next; iface != &interface_list;
                 iface = iface->next) {
                if (relay_forw.mesg->interface_in == iface->devindex) {
                    continue;
                }

                *(relay_forw.mesg->hc_pointer) = MAXHOPCOUNT;
                memset(&sin6, '\0', sizeof(struct sockaddr_in6));
                sin6.sin6_family = AF_INET6;

                memset(dest_addr, 0, INET6_ADDRSTRLEN);
                strcpy(dest_addr, ALL_DHCP_SERVERS);

                /* destination address */
                if (inet_pton(AF_INET6, dest_addr, &sin6.sin6_addr) <= 0) {
                    g_error("%s: inet_pton() failure", __func__);
                    return 0;
                }

                recvmsglen = CMSG_SPACE(sizeof(struct in6_pktinfo));
                recvp = (gchar *) g_malloc0(recvmsglen * sizeof(gchar));

                if (recvp == NULL) {
                    g_error("%s: memory allocation error", __func__);
                    exit(1);
                }

                cmsgp = (struct cmsghdr *) recvp;
                cmsgp->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
                cmsgp->cmsg_level = IPPROTO_IPV6;
                cmsgp->cmsg_type = IPV6_2292PKTINFO;
                in6_pkt = (struct in6_pktinfo *) CMSG_DATA(cmsgp);
                msg.msg_control = (void *) recvp;
                msg.msg_controllen = recvmsglen;

                /* destination address */
                if (inet_pton(AF_INET6, dest_addr, &sin6.sin6_addr) <= 0) {
                    g_error("%s: inet_pton() failure", __func__);
                    return 0;
                }

                sin6.sin6_port = htons(SERVER_PORT);

                in6_pkt->ipi6_ifindex = iface->devindex;
                sin6.sin6_scope_id = in6_pkt->ipi6_ifindex;

                g_debug("%s: outgoing device index: %d", __func__,
                        in6_pkt->ipi6_ifindex);

                if (inet_pton(AF_INET6, iface->ipv6addr->gaddr,
                              &in6_pkt->ipi6_addr) <= 0) {
                    /* source address */
                    g_error("%s: inet_pton() failure", __func__);
                    exit(1);
                }

                g_debug("%s: source address: %s", __func__,
                        iface->ipv6addr->gaddr);

                iov[0].iov_base = relay_forw.mesg->buffer;
                iov[0].iov_len = relay_forw.mesg->datalength;
                msg.msg_name = (void *) &sin6;
                msg.msg_namelen = sizeof(sin6);
                msg.msg_iov = &iov[0];
                msg.msg_iovlen = 1;

                if ((count = sendmsg(relaysock->sock_desc, &msg, 0)) < 0) {
                    perror("sendmsg");
                    return 0;
                }

                if (count > MAX_DHCP_MSG_LENGTH) {
                    perror("sendmsg");
                }

                g_debug("%s: => relay_forw, sent to: %s sent_bytes: %d",
                        __func__, dest_addr, count);
                free(recvp);
            }                   /* for */
        }
    }

    relay_forw.mesg->sent = 1;
    return 1;

    g_error("%s: no message type to send", __func__);
    exit(1);
}

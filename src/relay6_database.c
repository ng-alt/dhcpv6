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

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>

#include <glib.h>

#include "relay6_database.h"

void init_relay(void) {
    nr_of_uni_addr = 0;
    multicast_off = 0;
    nr_of_devices = 0;
    max_count = 0;

    relay_server_list = NULL;
    IPv6_address_list = NULL;
    IPv6_uniaddr_list = NULL;
    relay_interface_list = NULL;
    relay_msg_parser_list = NULL;
    return;
}

gint check_interface_semafor(gint index) {
    relay_interface_t *device = NULL;

    device = get_interface(index);
    if (device == NULL) {
        g_error("%s: fatal error", __func__);
        exit(1);
    }

    if (g_slist_find_custom(cifaces_list, device->ifname,
                            _find_string) != NULL) {
        return 1;
    }

    return 0;
}

relay_interface_t *get_interface(gint if_index) {
    relay_interface_t *deviface = NULL;
    GSList *iterator = relay_interface_list;

    while (iterator) {
        deviface = (relay_interface_t *) iterator->data;

        if (deviface->devindex == if_index) {
            return deviface;
        }

        iterator = g_slist_next(iterator);
    }

    return NULL;
}

relay_interface_t *get_interface_s(gchar *s) {
    relay_interface_t *deviface = NULL;
    GSList *iterator = relay_interface_list;

    while (iterator) {
        deviface = (relay_interface_t *) iterator->data;

        if (g_strcmp0(s, deviface->ifname) == 0) {
            return deviface;
        }

        iterator = g_slist_next(iterator);
    }

    return NULL;
}

relay_msg_parser_t *get_send_messages_out(void) {
    relay_msg_parser_t *msg = NULL;
    GSList *iterator = relay_msg_parser_list;

    while (iterator) {
        msg = (relay_msg_parser_t *) iterator->data;

        if (msg->sent == 0) {
            return msg;
        }

        iterator = g_slist_next(iterator);
    }

    return NULL;
}

gint process_RELAY_FORW(relay_msg_parser_t *msg) {
    uint8_t *head = (uint8_t *) g_malloc0(HEAD_SIZE * sizeof(uint8_t));
    uint8_t *newbuff =
        (uint8_t *) g_malloc0(MAX_DHCP_MSG_LENGTH * sizeof(uint8_t));
    uint8_t *pointer;
    relay_interface_t *device = NULL;
    struct sockaddr_in6 sap;
    gint check = 0;
    uint16_t *p16, *optl;
    uint32_t *p32;
    gint len, hop;

    if ((head == NULL) || (newbuff == NULL)) {
        g_error("%s: memory allocation error", __func__);
        exit(1);
    }

    pointer = head;

    if (msg->isRF == 1) {
        /* got message from a relay agent to be
         * relayed */
        (*pointer) = DH6_RELAY_FORW;
        pointer += 1;
        (*pointer) = msg->hop_count + 1;        /* increased hop-count */
        msg->hc_pointer = pointer;

        if (max_count == 1) {
            (*pointer) = MAXHOPCOUNT;
            hop = (int) (*pointer);
            g_debug("%s: hopcount: %d", __func__, hop);
        }

        pointer += 1;
    } else {
        /* got message from a client to be relayed */
        (*pointer) = DH6_RELAY_FORW;
        pointer += 1;
        (*pointer) = 0;         /* hop-count */
        msg->hc_pointer = pointer;

        if (max_count == 1) {
            (*pointer) = MAXHOPCOUNT;
            hop = (int) (*pointer);
            g_debug("%s: hopcount: %d", __func__, hop);
        }

        pointer += 1;
    }

    msg->msg_type = DH6_RELAY_FORW;
    device = get_interface(msg->interface_in);

    if (device == NULL) {
        g_error("%s: no interface found", __func__);
        exit(1);
    }

    /* fill in link-address */

    if (inet_pton(AF_INET6, msg->src_addr, &sap.sin6_addr) <= 0) {
        g_error("%s: inet_pton() failure", __func__);
        exit(1);
    }

    if ((!IN6_IS_ADDR_LINKLOCAL(&sap.sin6_addr)) && (nr_of_devices == 1)) {
        memset(&sap.sin6_addr, 0, sizeof(sap.sin6_addr));
        memcpy(pointer, &sap.sin6_addr, sizeof(sap.sin6_addr));
        pointer += sizeof(sap.sin6_addr);
    } else {
        check = 0;
        memset(&sap.sin6_addr, 0, sizeof(sap.sin6_addr));

        if (inet_pton(AF_INET6, (gchar *) device->ipv6addr->data,
                      &sap.sin6_addr) <= 0) {
            g_error("%s: inet_pton() failure", __func__);
            exit(1);
        }

        memcpy(pointer, &sap.sin6_addr, sizeof(sap.sin6_addr));
        pointer += sizeof(sap.sin6_addr);
    }

    /* fill in peer-addrees */
    memset(&sap.sin6_addr, 0, sizeof(sap.sin6_addr));

    if (inet_pton(AF_INET6, msg->src_addr, &sap.sin6_addr) <= 0) {
        g_error("%s: inet_pton() failure", __func__);
        exit(1);
    }

    memcpy(pointer, &sap.sin6_addr, sizeof(sap.sin6_addr));
    pointer += sizeof(sap.sin6_addr);

    /* Insert Interface_ID option to identify the interface */
    p16 = (uint16_t *) pointer;
    *p16 = htons(DH6OPT_INTERFACE_ID);
    pointer += 2;
    p16 = (uint16_t *) pointer;
    *p16 = htons(4);            /* 4 octeti length */
    pointer += 2;
    p32 = (uint32_t *) pointer;
    *p32 = htonl(device->opaq);
    pointer += 4;

    p16 = (uint16_t *) pointer;
    *p16 = htons(DH6OPT_RELAY_MSG);
    pointer += 2;
    optl = (uint16_t *) pointer;
    pointer += 2;
    *optl = htons(msg->datalength);

    len = (pointer - head);
    g_debug("%s: RELAY_FORW header length: %d", __func__, len);
    g_debug("%s: original message length: %d", __func__, msg->datalength);

    if ((len + msg->datalength) > MAX_DHCP_MSG_LENGTH) {
        g_error("%s: fragmentation will occur if sent, dropping packet",
                __func__);
        return 0;
    }

    pointer = newbuff;
    memset(pointer, 0, MAX_DHCP_MSG_LENGTH);
    memcpy(pointer, head, len);
    pointer += len;
    memcpy(pointer, msg->buffer, msg->datalength);
    msg->datalength += len;     /* final length for sending */

    g_free(msg->buffer);
    msg->buffer = NULL;

    g_free(head);
    head = NULL;

    msg->buffer = newbuff;

    return 1;
}

gint process_RELAY_REPL(relay_msg_parser_t *msg) {
    guint8 *newbuff = (guint8 *) g_malloc(MAX_DHCP_MSG_LENGTH * sizeof(guint8));
    guint8 *pointer, *pstart, *psp;
    relay_interface_t *device = NULL;
    struct sockaddr_in6 sap;
    gint check = 0;
    guint16 *p16, option, opaqlen, msglen;
    guint32 *p32;
    gint len, opaq;
    gchar *s = NULL;
    GSList *iterator = NULL;

    if (newbuff == NULL) {
        g_error("%s: memory allocation error", __func__);
        exit(1);
    }

    pointer = msg->buffer;
    pstart = pointer;

    if (msg->datalength < MESSAGE_HEADER_LENGTH) {
        g_debug("%s: opt_length has 0 value for message header length, "
                "dropping", __func__);
        return 0;
    }

    if (*pointer != DH6_RELAY_REPL) {
        return 0;
    }

    pointer += 1;               /* RELAY_FORW */
    msg->hop = *pointer;
    pointer += 1;               /* hop-count */
    msg->msg_type = DH6_RELAY_REPL;

    if (msg->datalength - (pointer - pstart) < (2 * sizeof(sap.sin6_addr))) {
        g_debug("%s: opt_length has 0 value for %lu, dropping",
                __func__, sizeof(sap.sin6_addr));
        return 0;
    }

    /* extract link_address */
    memset(msg->link_addr, 0, INET6_ADDRSTRLEN);
    memset(&sap.sin6_addr, 0, sizeof(sap.sin6_addr));
    memcpy(&sap.sin6_addr, pointer, sizeof(sap.sin6_addr));
    pointer += sizeof(sap.sin6_addr);

    if (inet_ntop(AF_INET6, &sap.sin6_addr, msg->link_addr,
                  INET6_ADDRSTRLEN) <= 0) {
        g_error("%s: inet_ntop() failure", __func__);
        exit(1);
    }

    /* extract peer address */
    memset(msg->peer_addr, 0, INET6_ADDRSTRLEN);
    memset(&sap.sin6_addr, 0, sizeof(sap.sin6_addr));
    memcpy(&sap.sin6_addr, pointer, sizeof(sap.sin6_addr));
    pointer += sizeof(sap.sin6_addr);

    if (inet_ntop(AF_INET6, &sap.sin6_addr, msg->peer_addr,
                  INET6_ADDRSTRLEN) <= 0) {
        g_error("%s: inet_ntop() failure", __func__);
        exit(1);
    }

    if (msg->datalength - (pointer - pstart) < MESSAGE_HEADER_LENGTH) {
        g_debug("%s: opt_length has 0 value for message header length, "
                "dropping", __func__);
        return 0;
    }

    p16 = (uint16_t *) pointer;
    option = ntohs(*p16);

    if (option == DH6OPT_INTERFACE_ID) {
        pointer += 2;
        p16 = (uint16_t *) pointer;
        opaqlen = ntohs(*p16);
        pointer += 2;

        if (msg->datalength - (pointer - pstart) < opaqlen) {
            g_debug("%s: opt_length has 0 value for opaqlen, dropping",
                    __func__);
            return 0;
        }

        p32 = (uint32_t *) pointer;
        opaq = ntohl(*p32);
        pointer += opaqlen;

        if (msg->datalength - (pointer - pstart) < MESSAGE_HEADER_LENGTH) {
            g_debug("%s: opt_length has 0 value for message header length, "
                    "dropping", __func__);
            return 0;
        }

        p16 = (uint16_t *) pointer;
        option = ntohs(*p16);

        if (option == DH6OPT_RELAY_MSG) {
            pointer += 2;
            p16 = (uint16_t *) pointer;
            msglen = ntohs(*p16);
            pointer += 2;
            if (msg->datalength - (pointer - pstart) < msglen) {
                g_debug("%s: opt_length has 0 value for msglen, dropping",
                        __func__);
                return 0;
            }

            if (*pointer == DH6_RELAY_FORW) {
                /* is the job of the server to set to RELAY_REPL? */
                *pointer = DH6_RELAY_REPL;
            }

            iterator = relay_interface_list;
            while (iterator) {
                device = (relay_interface_t *) iterator->data;

                if (device->opaq == opaq) {
                    break;
                }

                iterator = g_slist_next(iterator);
            }

            if (iterator != relay_interface_list) {
                msg->if_index = device->devindex;
                memset(newbuff, 0, MAX_DHCP_MSG_LENGTH);
                len = (pointer - msg->buffer);
                len = (msg->datalength - len);
                memcpy(newbuff, pointer, len);
                msg->datalength = len;
                g_free(msg->buffer);
                msg->buffer = newbuff;
                return 1;
            } else {
                s = msg->link_addr;
                iterator = relay_interface_list;

                while (iterator) {
                    device = (relay_interface_t *) iterator->data;
                    GSList *addr_iterator = device->ipv6addr;

                    while (addr_iterator) {
                        gchar *gaddr = (gchar *) addr_iterator->data;

                        if (g_strcmp0(s, gaddr) == 0) {
                            msg->if_index = device->devindex;
                            check = 1;
                            break;
                        }

                        addr_iterator = g_slist_next(addr_iterator);
                    }

                    if (check == 1) {
                        break;
                    }

                    iterator = g_slist_next(iterator);
                }

                if (check == 0) {
                    g_error("%s: no interface found", __func__);
                    return 0;
                }

                memset(newbuff, 0, MAX_DHCP_MSG_LENGTH);
                len = (pointer - msg->buffer);
                len = (msg->datalength - len);
                memcpy(newbuff, pointer, len);
                msg->datalength = len;
                g_free(msg->buffer);
                msg->buffer = newbuff;
                return 1;
            }
        } else {
            /* DH6OPT_RELAY_MSG */
            g_debug("%s: message is malformed, no option relay message found, "
                    "dropping", __func__);
            return 0;
        }
    }

    /* DH6OPT_INTERFACE_ID */
    if (option == DH6OPT_RELAY_MSG) {
        pointer += 2;
        p16 = (uint16_t *) pointer;
        msglen = ntohs(*p16);
        pointer += 2;

        if (msg->datalength - (pointer - pstart) < msglen) {
            g_debug("%s: opt_length has 0 value for msglen, dropping",
                    __func__);
            return 0;
        }

        opaq = 0;
        psp = (pointer + msglen);       /* jump over message, seek for
                                         * DH6OPT_INTERFACE_ID */

        p16 = (uint16_t *) psp;
        option = ntohs(*p16);

        if (msg->datalength - (psp - pstart) >= MESSAGE_HEADER_LENGTH) {
            if (option == DH6OPT_INTERFACE_ID) {
                psp += 2;
                p16 = (uint16_t *) psp;
                opaqlen = ntohs(*p16);
                psp += 2;

                if (msg->datalength - (psp - pstart) < opaqlen) {
                    g_debug("%s: opt_length has 0 value for opaqlen, dropping",
                            __func__);
                    return 0;
                }

                p32 = (uint32_t *) psp;
                opaq = ntohl(*p32);
                psp += opaqlen;
            }
        }

        if (*pointer == DH6_RELAY_FORW) {
            /* is the job of the server to set to RELAY_REPL? */
            *pointer = DH6_RELAY_REPL;
        }

        iterator = relay_interface_list;
        while (iterator) {
            device = (relay_interface_t *) iterator->data;

            if (device->opaq == opaq) {
                break;
            }

            iterator = g_slist_next(iterator);
        }

        if (iterator != relay_interface_list) {
            msg->if_index = device->devindex;
            memset(newbuff, 0, MAX_DHCP_MSG_LENGTH);
            memcpy(newbuff, pointer, msglen);
            msg->datalength = msglen;
            g_free(msg->buffer);
            msg->buffer = newbuff;
            return 1;
        } else {
            s = msg->link_addr;
            iterator = relay_interface_list;

            while (iterator) {
                device = (relay_interface_t *) iterator->data;
                GSList *addr_iterator = device->ipv6addr;

                while (addr_iterator) {
                    gchar *gaddr = (gchar *) addr_iterator->data;

                    if (g_strcmp0(s, gaddr) == 0) {
                        msg->if_index = device->devindex;
                        check = 1;
                        break;
                    }

                    addr_iterator = g_slist_next(addr_iterator);
                }

                if (check == 1) {
                    break;
                }

                iterator = g_slist_next(iterator);
            }

            if (check == 0) {
                g_error("%s: no interface found", __func__);
                return 0;
            }

            memset(newbuff, 0, MAX_DHCP_MSG_LENGTH);
            memcpy(newbuff, pointer, msglen);
            msg->datalength = msglen;
            g_free(msg->buffer);
            msg->buffer = newbuff;
            return 1;
        }
    } else {
        /* DH6OPT_RELAY_MSG */
        g_debug("%s: message is malformed, no option relay message found, "
                "dropping", __func__);
        return 0;
    }

    return 1;
}

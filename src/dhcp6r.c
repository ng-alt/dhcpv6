/*
 * dhcp6r.c
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
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/param.h>
#include <errno.h>

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# include <time.h>
#endif

#include <glib.h>

#include "dhcp6r.h"

static gchar *pidfile = NULL;

GSList *cifaces_list;
GSList *sifaces_list;

GSList *relay_server_list;
GSList *IPv6_address_list;
GSList *IPv6_uniaddr_list;
GSList *relay_interface_list;

gint nr_of_devices;
gint max_count;
gboolean multicast;

/* BEGIN STATIC FUNCTIONS */

static void _get_multicast_ifaces(gchar *multicast, GSList *list, gchar *log) {
    gchar **ifaces = NULL, **iterator = NULL;

    if (!multicast || !log) {
        return;
    }

    ifaces = g_strsplit_set(multicast, "\" ", -1);
    iterator = ifaces;

    while (*iterator) {
        if (!g_strcmp0(*iterator, "")) {
            iterator++;
            continue;
        }

        if (get_interface_s(*iterator)) {
            gchar *iface = g_strdup(*iterator);
            list = g_slist_append(list, iface);
            g_debug("%s: setting up %s interface: %s", __func__, log, iface);
        }

        iterator++;
    }

    g_strfreev(ifaces);
    g_free(multicast);
    return;
}

static void _get_server_unicast(gchar *unicast, GSList *list) {
    gchar **fields = NULL, **iterator = NULL;

    if (!unicast) {
        return;
    }

    fields = g_strsplit_set(unicast, "\" ", -1);
    iterator = fields;

    while (*iterator) {
        struct sockaddr_in6 sin6;
        gchar *addr = NULL;

        if (!g_strcmp0(*iterator, "")) {
            iterator++;
            continue;
        }

        memset(&sin6, 0, sizeof(sin6));

        /* destination address */
        if (inet_pton(AF_INET6, *iterator, &sin6.sin6_addr) <= 0) {
            g_error("%s: malformed address: %s", __func__, *iterator);
            iterator++;
            continue;
        }

        if (IN6_IS_ADDR_UNSPECIFIED(&sin6.sin6_addr)) {
            g_error("%s: malformed address: %s", __func__, *iterator);
            iterator++;
            continue;
        }

        addr = g_strdup(*iterator);
        list = g_slist_append(list, addr);
        g_debug("%s: setting up server address: %s", __func__, addr);
        iterator++;
    }

    g_strfreev(fields);
    g_free(unicast);
    return;
}

static void _get_forward(gchar *forward) {
    gchar **fields = NULL, **iterator = NULL;

    if (!forward) {
        return;
    }

    fields = g_strsplit_set(forward, "\" ", -1);
    iterator = fields;

    while (*iterator) {
        gchar **parts = NULL, **subpart = NULL;
        gchar *eth = NULL, *addr = NULL;
        struct sockaddr_in6 sin6;
        relay_interface_t *iface = NULL;

        if (!g_strcmp0(*iterator, "")) {
            iterator++;
            continue;
        }

        parts = g_strsplit_set(*iterator, "+", -1);
        subpart = parts;

        eth = *subpart;
        subpart++;
        addr = *subpart;

        if (eth == NULL || addr == NULL) {
            g_error("%s: option %s not recognized", __func__, *iterator);
            g_strfreev(parts);
            iterator++;
            continue;
        }

        memset(&sin6, 0, sizeof(sin6));

        /* destination address */
        if (inet_pton(AF_INET6, addr, &sin6.sin6_addr) <= 0) {
            g_error("%s: malformed address: %s", __func__, *iterator);
            g_strfreev(parts);
            iterator++;
            continue;
        }

        if (IN6_IS_ADDR_UNSPECIFIED(&sin6.sin6_addr)) {
            g_error("%s: malformed address: %s", __func__, *iterator);
            g_strfreev(parts);
            iterator++;
            continue;
        }

        if ((iface = get_interface_s(eth)) != NULL) {
            gchar *sa = g_strdup(addr);
            iface->sname = g_slist_append(iface->sname, sa);
            g_debug("%s: setting up server address: %s for interface: %s",
                    __func__, addr, eth);
        } else {
            g_error("%s: interface %s not found", __func__, eth);
            g_strfreev(parts);
            iterator++;
            continue;
        }

        g_strfreev(parts);
        iterator++;
    }

    g_strfreev(fields);
    g_free(forward);
    return;
}

/* END STATIC FUNCTIONS */

gchar *dhcp6r_clock(void) {
    time_t tim;
    gchar *s, *p;

    time(&tim);
    s = ctime(&tim);

    p = s;
    do {
        p = strstr(p, " ");

        if (p != NULL) {
            if (*(p - 1) == '/') {
                *p = '0';
            } else {
                *p = '/';
            }
        }
    } while (p != NULL);

    p = strstr(s, "\n");
    if (p != NULL) {
        *p = '\0';
    }

    return s;
}

void handler(gint signo) {
    close(relaysock->sock_desc);
    g_debug("%s: relay agent stopping", __func__);
    unlink(pidfile);

    exit(EXIT_SUCCESS);
}

gint main(gint argc, gchar **argv) {
    gchar *progname = basename(argv[0]);
    relay_msg_parser_t *mesg = NULL;
    FILE *pidfp = NULL;
    log_properties_t log_props;
    gboolean unicast;
    gchar *client_multicast = NULL, *forward = NULL;
    gchar *server_unicast = NULL, *server_multicast = NULL;
    GError *error = NULL;
    GOptionContext *context = NULL;
    GOptionEntry entries[] = {
        { "pid-file", 'p', 0, G_OPTION_ARG_STRING,
              &pidfile,
              "PID file",
              "PATH" },
        { "client-unicast", 'c', 0, G_OPTION_ARG_NONE,
              &unicast,
              "Receive client messages by unicast only",
              NULL },
        { "client-multicast", 'C', 0, G_OPTION_ARG_STRING,
              &client_multicast,
              "Receive client messages by multicast on specific interfaces",
              "INTERFACE" },
        { "server-unicast", 's', 0, G_OPTION_ARG_STRING,
              &server_unicast,
              "Forward client messages by unicast to named address(es)",
              "ADDRESS(ES)" },
        { "server-multicast", 'S', 0, G_OPTION_ARG_STRING,
              &server_multicast,
              "Forward client messages by multicast on named interface(s)",
              "INTERFACE(S)" },
        { "forward", 'F', 0, G_OPTION_ARG_STRING,
              &forward,
              "Forward all messages by unicast to address via interface",
              "INTERFACE+ADDRESS" },
        { "foreground", 'f', 0, G_OPTION_ARG_NONE,
              &log_props.foreground,
              "Run relay server in the foreground",
              NULL },
        { NULL }
    };

    context = g_option_context_new(NULL);
    g_option_context_set_summary(context, "DHCPv6 relay agent");
    g_option_context_set_description(context,
        "PATH is a valid path specification for the system.  ADDRESS is a "
        "valid IPv6\naddress specification in human readable format (e.g., "
        "47::1:2::31/64).\nINTERFACE is a valid network interface name "
        "(e.g., eth0).\n\n"
        "Multiple ADDRESS, INTERFACE, and INTERFACE+ADDRESS parameters may "
        "specified for\nthe appropriate option.  To specify more than one, "
        "enclose the values in double\nquotes and separate them by spaces.\n\n"
        "For more details on the dhcp6r program, see the dhcp6r(8) man "
        "page.\n\n"
        "Please report bugs at http://fedorahosted.org/dhcpv6/");

    g_option_context_add_main_entries(context, entries, NULL);

    if (!g_option_context_parse(context, &argc, &argv, &error)) {
        g_error("option parsing failed: %s", error->message);
        return EXIT_FAILURE;
    }

    g_option_context_free(context);

    if (unicast) {
        multicast = FALSE;
    }

    if (pidfile == NULL) {
        pidfile = DHCP6R_PIDFILE;
    };

    if (client_multicast) {
        _get_multicast_ifaces(client_multicast, cifaces_list, "client");
        multicast = TRUE;
    }

    if (server_multicast) {
        _get_multicast_ifaces(server_multicast, sifaces_list, "server");
    }

    if (server_unicast) {
        _get_server_unicast(server_unicast, IPv6_uniaddr_list);
    }

    if (forward) {
        _get_forward(forward);
    }

    signal(SIGINT, handler);
    signal(SIGTERM, handler);
    signal(SIGHUP, handler);
    init_relay();

    if (!get_interface_info()) {
        abort();
    }

    init_socket();

    if (!set_sock_opt()) {
        abort();
    }

    if (!fill_addr_struct()) {
        abort();
    }

    if (!log_props.foreground) {
        if (daemon(0, 0) < 0) {
            g_error("error backgrounding %s", progname);
            abort();
        }
    }

    if ((pidfp = fopen(pidfile, "w")) != NULL) {
        fprintf(pidfp, "%d\n", getpid());
        fclose(pidfp);
    } else {
        fprintf(stderr, "Unable to write to %s: %s\n", pidfile,
                strerror(errno));
        fflush(stderr);
        abort();
    }

    while (1) {
        if (check_select() == 1) {
            if (recv_data() == 1) {
                if (get_recv_data() == 1) {
                    mesg = create_parser_obj();
                    if (put_msg_in_store(mesg) == 0) {
                        mesg->sent = 1; /* mark it for deletion */
                    }
                }
            }
        }

        send_message();
        g_slist_free(relay_msg_parser_list);
        relay_msg_parser_list = NULL;
    }

    return EXIT_SUCCESS;
}

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
#include "relay6_parser.h"
#include "relay6_socket.h"
#include "relay6_database.h"

#define DHCP6R_PIDFILE PID_FILE_PATH"/dhcp6r.pid"

static gchar pidfile[MAXPATHLEN];

gint main(gint argc, gchar **argv) {
    gint err = 0, i;
    gint sw = 0;
    gint du = 0;
    struct interface *iface;
    struct sockaddr_in6 sin6;
    gchar *sf, *eth, *addr;
    struct IPv6_uniaddr *unia;
    struct server *sa;
    struct msg_parser *mesg;
    FILE *pidfp = NULL;

    memset(&pidfile, '\0', sizeof(pidfile));
    strcpy(pidfile, DHCP6R_PIDFILE);

    signal(SIGINT, handler);
    signal(SIGTERM, handler);
    signal(SIGHUP, handler);
    init_relay();

    /* Specify a file stream for logging */
    if (argc > 1) {
        for (i = 1; i < argc; ++i) {
            if (strcmp(argv[i], "-d") == 0) {
                du = 1;
            }
        }
    }

    if (get_interface_info() == 0) {
        goto ERROR;
    }

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-d") == 0) {
            continue;
        } else if (strcmp(argv[i], "-p") == 0) {
            i++;

            if (i < argc) {
                if (strlen(argv[i]) >= MAXPATHLEN) {
                    g_error("%s: pid filename is too long", __func__);
                    exit(1);
                }

                memset(&pidfile, '\0', sizeof(pidfile));
                strcpy(pidfile, argv[i]);
            } else {
                command_text();
            }
        } else if (strcmp(argv[i], "-cm") == 0) {
            i++;

            if (get_interface_s(argv[i]) == NULL) {
                err = 5;
                goto ERROR;
            }

            sw = 1;
            cifaces_list = g_slist_append(cifaces_list, g_strdup(argv[i]));
            g_debug("%s: setting up client interface: %s", __func__, argv[i]);
            continue;
        } else if (strcmp(argv[i], "-cu") == 0) {
            multicast_off = 1;
        } else if (strcmp(argv[i], "-sm") == 0) {
            i++;

            if (get_interface_s(argv[i]) == NULL) {
                err = 5;
                goto ERROR;
            }

            sifaces_list = g_slist_append(sifaces_list, g_strdup(argv[i]));
            g_debug("%s: setting up server interface: %s", __func__, argv[i]);
            continue;
        } else if (strcmp(argv[i], "-su") == 0) {
            i++;

            /* destination address */
            if (inet_pton(AF_INET6, argv[i], &sin6.sin6_addr) <= 0) {
                err = 3;
                goto ERROR;
            }

            if (IN6_IS_ADDR_UNSPECIFIED(&sin6.sin6_addr)) {
                err = 3;
                goto ERROR;
            }

            unia = (struct IPv6_uniaddr *)
                g_malloc0(sizeof(struct IPv6_uniaddr));

            if (unia == NULL) {
                g_error("%s: memory allocation error", __func__);
                exit(1);
            }

            unia->uniaddr = strdup(argv[i]);
            unia->next = IPv6_uniaddr_list.next;
            IPv6_uniaddr_list.next = unia;

            g_debug("%s: setting up server address: %s", __func__, argv[i]);
            nr_of_uni_addr += 1;

            continue;
        } else if (strcmp(argv[i], "-sf") == 0) {
            i++;
            sf = strdup(argv[i]);
            eth = strtok(sf, "+");

            if (eth == NULL) {
                err = 4;
                goto ERROR;
            }

            addr = strtok((sf + strlen(eth) + 1), "\0");

            if (addr == NULL) {
                err = 4;
                goto ERROR;
            }

            /* destination address */
            if (inet_pton(AF_INET6, addr, &sin6.sin6_addr) <= 0) {
                err = 3;
                goto ERROR;
            }

            if (IN6_IS_ADDR_UNSPECIFIED(&sin6.sin6_addr)) {
                err = 3;
                goto ERROR;
            }

            if ((iface = get_interface_s(eth)) != NULL) {
                sa = (struct server *) g_malloc0(sizeof(struct server));

                if (sa == NULL) {
                    g_error("%s: memory allocation error", __func__);
                    exit(1);
                }

                sa->serv = strdup(addr);
                sa->next = NULL;

                if (iface->sname != NULL) {
                    sa->next = iface->sname;
                }

                iface->sname = sa;
                g_debug("%s: setting up server address: %s for interface: %s",
                        __func__, addr, eth);
                free(sf);
            } else {
                err = 5;
                goto ERROR;
            }

            continue;
        } else if ((strcmp(argv[i], "-h") == 0) ||
                   (strcmp(argv[i], "--help") == 0)) {
            command_text();
        } else {
            err = 4;
            goto ERROR;
        }
    }

    if (sw == 1) {
        multicast_off = 0;
    }

    init_socket();

    if (set_sock_opt() == 0) {
        goto ERROR;
    }

    if (fill_addr_struct() == 0) {
        goto ERROR;
    }

    if (du == 0) {
        switch (fork()) {
            case 0:
                break;
            case -1:
                perror("fork");
                exit(1);
            default:
                exit(0);
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
        delete_messages();
    }

ERROR:

    if (err == 3) {
        g_error("%s: malformed address: %s", __func__, argv[i]);
        exit(1);
    }

    if (err == 4) {
        g_error("%s: option %s not recognized", __func__, argv[i]);
        exit(1);
    }

    if (err == 5) {
        g_error("%s: interface %s not found", __func__, argv[i]);
        exit(1);
    }

    exit(1);
}

void command_text(void) {
    printf("Usage:\n");
    printf
        ("       dhcp6r [-p pidfile] [-d] [-cu] [-cm <interface>] [-sm <interface>] "
         "[-su <address>] [-sf <interface>+<address>] \n");
    exit(1);
}

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

    exit(0);
}

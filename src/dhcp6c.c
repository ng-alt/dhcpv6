/* ported from KAME: dhcp6c.c,v 1.97 2002/09/24 14:20:49 itojun Exp */

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

#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <libgen.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <err.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <resolv.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# include <time.h>
#endif

#ifdef HAVE_SYS_TIMEB_H
# include <sys/timeb.h>
#endif

#ifdef HAVE_LINUX_SOCKIOS_H
# include <linux/sockios.h>
#endif

#ifdef HAVE_NET_IF_VAR_H
# include <net/if_var.h>
#endif

#ifdef HAVE_NETINET6_IN6_VAR_H
# include <netinet6/in6_var.h>
#endif

#include <linux/netlink.h>
#include <netlink/socket.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/route.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>

#include <glib.h>

#include "dhcp6.h"
#include "confdata.h"
#include "common.h"
#include "timer.h"
#include "lease.h"

/* External globals */
extern gchar *raproc_file;
extern gchar *ifproc_file;
extern FILE *client6_lease_file;
extern struct dhcp6_iaidaddr client6_iaidaddr;

/* External prototypes */
extern gint client6_ifaddrconf(ifaddrconf_cmd_t, struct dhcp6_addr *);
extern struct dhcp6_timer *syncfile_timo(void *);
extern gint dad_parse(const gchar *, struct dhcp6_list *);

/* Globals */
const dhcp6_mode_t dhcp6_mode = DHCP6_MODE_CLIENT;
gint iosock = -1;                /* inbound/outbound udp port */
gint nlsock = -1;
FILE *dhcp6_resolv_file;
gchar client6_lease_temp[256];
struct dhcp6_list request_list;
gchar *script = NULL;

/* Static globals */
static u_long sig_flags = 0;
static gchar *device = NULL;
static gint num_device = 0;
static struct iaid_table iaidtab[MAX_DEVICE];
static guint8 client6_request_flag = 0;
static const struct sockaddr_in6 *sa6_allagent;
static socklen_t sa6_alen;
static struct duid client_duid;
static gint pid;
static gchar leasename[MAXPATHLEN];
static gchar *path_client6_lease = PATH_CLIENT6_LEASE;
static gchar *pidfile = DHCP6C_PIDFILE;
static gchar *duidfile = DHCP6C_DUID_FILE;

/* Prototypes */
struct dhcp6_timer *client6_timo(void *);
void run_script(struct dhcp6_if *, gint, gint, guint32);
gint client6_send_newstate(struct dhcp6_if *, gint);
void free_servers(struct dhcp6_if *);
void client6_send(struct dhcp6_event *);
gint get_if_rainfo(struct dhcp6_if *);
gint client6_init(gchar *);

/* BEGIN STATIC FUNCTIONS */

static void _usage(gchar *name) {
    fprintf(stdout, "Usage: %s [options] interface\n", name);
    fprintf(stdout, "Options:\n");
    fprintf(stdout,
            "    -c PATH        Configuration file\n"
            "                       (default: %s)\n", DHCP6C_CONF);
    fprintf(stdout, "    -p PATH        PID file name\n"
                    "                       (default: %s)\n",
            DHCP6C_PIDFILE);
    fprintf(stdout,
            "    -r ADDR...     Release the specified addresses (either \"all\" or\n                    named addresses)\n");
    fprintf(stdout,
            "    -R ADDR...     Request the specified IANA address(es)\n");
    fprintf(stdout,
            "    -P ADDR...     Request the specified IAPD address(es)\n");
    fprintf(stdout,
            "    -s PATH        Script executed on state changes to which "
                                "configuration\n                   is "
                                "delegated\n");
    fprintf(stdout,
            "    -l PATH        Path to lease database\n"
            "                       (default: %s)\n",
            path_client6_lease);
    fprintf(stdout,
            "    -d PATH        Path to client DUID file\n"
            "                       (default: %s)\n",
            duidfile);
    fprintf(stdout,
            "    -I             Request only information from the server\n");
    fprintf(stdout,
            "    -f             Run client as a foreground process\n");
    fprintf(stdout, "    -v             Verbose log output (include debug messages)\n");
    fprintf(stdout, "    -?             Display this screen\n");
    fprintf(stdout, "IANA is identiy association named address.\n");
    fprintf(stdout, "IAPD is identiy association prefix delegation.\n");
    fflush(stdout);
    return;
}

static void _ev_set_state(struct dhcp6_event *ev, gint new_state) {
    gint old_state = ev->state;

    g_debug("%s event %p xid %d state change %d -> %d",
            FNAME, ev, ev->xid, ev->state, new_state);
    ev->state = new_state;
    run_script(ev->ifp, old_state, new_state, ev->uuid);
    return;
}

static struct dhcp6_serverinfo *_find_server(struct dhcp6_if *ifp,
                                             struct duid *duid) {
    struct dhcp6_serverinfo *s;

    for (s = ifp->servers; s; s = s->next) {
        if (duidcmp(&s->optinfo.serverID, duid) == 0) {
            return s;
        }
    }

    return NULL;
}

static void _setup_check_timer(struct dhcp6_if *ifp) {
    gdouble d;
    struct timeval timo;

    d = DHCP6_CHECKLINK_TIME_UPCASE;
    timo.tv_sec = (long) d;
    timo.tv_usec = 0;
    g_debug("set timer for checking link ...");
    dhcp6_set_timer(&timo, ifp->link_timer);

    if (ifp->dad_timer != NULL) {
        d = DHCP6_CHECKDAD_TIME;
        timo.tv_sec = (long) d;
        timo.tv_usec = 0;
        g_debug("set timer for checking DAD ...");
        dhcp6_set_timer(&timo, ifp->dad_timer);
    }

    d = DHCP6_SYNCFILE_TIME;
    timo.tv_sec = (long) d;
    timo.tv_usec = 0;
    g_debug("set timer for syncing file ...");
    dhcp6_set_timer(&timo, ifp->sync_timer);
    return;
}

static struct dhcp6_timer *_info_refresh_timo(void *arg) {
    struct dhcp6_if *ifp = (struct dhcp6_if *) arg;

    g_debug("%s information is refreshing...", FNAME);
    dhcp6_remove_timer(ifp->info_refresh_timer);
    ifp->info_refresh_timer = NULL;
    client6_send_newstate(ifp, DHCP6S_INFOREQ);
    return NULL;
}

static gint _set_info_refresh_timer(struct dhcp6_if *ifp, guint32 offered_irt) {
    gint irt;
    struct timeval timo;
    gdouble rval;

    if (offered_irt == 0) {
        irt = ifp->default_irt;
    } else if (offered_irt < IRT_MINIMUM) {
        irt = IRT_MINIMUM;
    } else if (offered_irt > ifp->maximum_irt) {
        irt = ifp->maximum_irt;
    } else {
        irt = offered_irt;
    }

    if (irt == DHCP6_DURATITION_INFINITE) {
        g_debug("%s information would not be refreshed any more", FNAME);
        return 0;
    }

    if ((ifp->info_refresh_timer =
         dhcp6_add_timer(_info_refresh_timo, ifp)) == NULL) {
        g_error("%s failed to add a timer for %s", FNAME, ifp->ifname);
        return -1;
    }

    /*
     * the client MUST delay sending the first Information-Request by
     * a random amount of time between 0 and INF_MAX_DELAY
     * [RFC4242 3.2.]
     */
    rval = (gdouble) random() / RAND_MAX * INF_MAX_DELAY * 1000;
    timo.tv_sec = irt + (long) (rval / 1000000);
    timo.tv_usec = (long) rval % 1000000;
    dhcp6_set_timer(&timo, ifp->info_refresh_timer);
    g_debug("%s information will be refreshed in %ld.%06ld [sec]",
            FNAME, timo.tv_sec, timo.tv_usec);

    return 0;
}

static gint _create_request_list(gint reboot) {
    struct dhcp6_lease *cl;
    struct dhcp6_listval *lv;

    /* create an address list for release all/confirm */
    for (cl = TAILQ_FIRST(&client6_iaidaddr.lease_list); cl;
         cl = TAILQ_NEXT(cl, link)) {
        /* IANA, IAPD */
        if ((lv = malloc(sizeof(*lv))) == NULL) {
            g_error("%s failed to allocate memory for an ipv6 addr", FNAME);
            exit(1);
        }

        memcpy(&lv->val_dhcp6addr, &cl->lease_addr,
               sizeof(lv->val_dhcp6addr));
        lv->val_dhcp6addr.status_code = DH6OPT_STCODE_UNDEFINE;
        TAILQ_INSERT_TAIL(&request_list, lv, link);

        /* config the interface for reboot */
        if (reboot && client6_iaidaddr.client6_info.type != IAPD &&
            (client6_request_flag & CLIENT6_CONFIRM_ADDR)) {
            if (client6_ifaddrconf(IFADDRCONF_ADD, &cl->lease_addr) != 0) {
                g_message("config address failed: %s",
                          in6addr2str(&cl->lease_addr.addr, 0));
                return -1;
            }
        }
    }

    return 0;
}

static struct dhcp6_timer *_check_link_timo(void *arg) {
    struct dhcp6_if *ifp = (struct dhcp6_if *) arg;
    struct ifreq ifr;
    struct timeval timo;
    static long d = DHCP6_CHECKLINK_TIME_UPCASE;
    gint newstate;
    struct dhcp6_list dad_list;
    struct dhcp6_listval *lv;

    g_debug("enter checking link ...");
    strncpy(ifr.ifr_name, dhcp6_if->ifname, IFNAMSIZ);

    if (ioctl(nlsock, SIOCGIFFLAGS, &ifr) < 0) {
        g_debug("ioctl SIOCGIFFLAGS failed");
        goto settimer;
    }

    if (ifr.ifr_flags & IFF_RUNNING) {
        /* check previous flag set current flag UP */
        if (ifp->link_flag & IFF_RUNNING) {
            goto settimer;
        }

        switch (client6_iaidaddr.client6_info.type) {
            case IAPD:
                newstate = DHCP6S_REBIND;
                break;
            default:
                /* check DAD status of the link-local address */
                TAILQ_INIT(&dad_list);

                if (dad_parse("/proc/net/if_inet6", &dad_list) < 0) {
                    g_error("parse /proc/net/if_inet6 failed");
                    goto settimer;
                }

                for (lv = TAILQ_FIRST(&dad_list);
                     lv; lv = TAILQ_NEXT(lv, link)) {
                    if (IN6_ARE_ADDR_EQUAL(&lv->val_dhcp6addr.addr,
                                           &ifp->linklocal)) {
                        g_debug("wait for the DAD completion");
                        dhcp6_clear_list(&dad_list);
                        goto settimer;
                    }
                }

                dhcp6_clear_list(&dad_list);
                newstate = DHCP6S_CONFIRM;
                break;
        }

        /* check current state ACTIVE */
        if (client6_iaidaddr.state == ACTIVE) {
            /* remove timer for renew/rebind send confirm for ipv6address or
             * rebind for prefix delegation */
            dhcp6_remove_timer(client6_iaidaddr.timer);
            client6_request_flag |= CLIENT6_CONFIRM_ADDR;
            _create_request_list(1);
            client6_send_newstate(ifp, newstate);
        }

        g_message("interface is from down to up");
        ifp->link_flag |= IFF_RUNNING;
        d = DHCP6_CHECKLINK_TIME_UPCASE;
    } else {
        g_message("interface is down");
        /* set flag_prev flag DOWN */
        ifp->link_flag &= ~IFF_RUNNING;
        d = DHCP6_CHECKLINK_TIME_DOWNCASE;
    }

settimer:
    timo.tv_sec = d;
    timo.tv_usec = 0;
    dhcp6_set_timer(&timo, ifp->link_timer);
    return ifp->link_timer;
}

static struct dhcp6_timer *_check_lease_file_timo(void *arg) {
    struct dhcp6_if *ifp = (struct dhcp6_if *) arg;
    gdouble d;
    struct timeval timo;
    struct stat buf;
    FILE *file;

    stat(leasename, &buf);
    strcpy(client6_lease_temp, leasename);
    strcat(client6_lease_temp, "XXXXXX");

    if (buf.st_size > MAX_FILE_SIZE) {
        file = sync_leases(client6_lease_file, leasename, client6_lease_temp);
        if (file != NULL) {
            client6_lease_file = file;
        }
    }

    d = DHCP6_SYNCFILE_TIME;
    timo.tv_sec = (long) d;
    timo.tv_usec = 0;
    dhcp6_set_timer(&timo, ifp->sync_timer);
    return ifp->sync_timer;
}

static struct dhcp6_timer *_check_dad_timo(void *arg) {
    struct dhcp6_if *ifp = (struct dhcp6_if *) arg;
    gint newstate;
    struct dhcp6_list dad_list;
    struct dhcp6_lease *cl;
    struct dhcp6_listval *lv;

    if (client6_iaidaddr.client6_info.type == IAPD) {
        goto end;
    }

    g_debug("enter checking dad ...");
    TAILQ_INIT(&dad_list);

    if (dad_parse("/proc/net/if_inet6", &dad_list) < 0) {
        g_error("parse /proc/net/if_inet6 failed");
        goto end;
    }

    for (lv = TAILQ_FIRST(&dad_list); lv; lv = TAILQ_NEXT(lv, link)) {
        for (cl = TAILQ_FIRST(&client6_iaidaddr.lease_list);
             cl; cl = TAILQ_NEXT(cl, link)) {
            if (cl->lease_addr.type != IAPD &&
                IN6_ARE_ADDR_EQUAL(&cl->lease_addr.addr,
                                   &lv->val_dhcp6addr.addr)) {
                /* deconfigure the interface's the address assgined by dhcpv6 
                 */
                if (dhcp6_remove_lease(cl) != 0) {
                    g_error("remove duplicated address failed: %s",
                            in6addr2str(&cl->lease_addr.addr, 0));
                } else {
                    TAILQ_REMOVE(&dad_list, lv, link);
                    TAILQ_INSERT_TAIL(&request_list, lv, link);
                }

                break;
            }
        }
    }

    dhcp6_clear_list(&dad_list);

    if (TAILQ_EMPTY(&request_list)) {
        goto end;
    }

    /* remove RENEW timer for client6_iaidaddr */
    if (client6_iaidaddr.timer != NULL) {
        dhcp6_remove_timer(client6_iaidaddr.timer);
    }

    newstate = DHCP6S_DECLINE;
    client6_send_newstate(ifp, newstate);

end:
    /* one time check for DAD */
    dhcp6_remove_timer(ifp->dad_timer);
    ifp->dad_timer = NULL;
    return NULL;
}

static gint _client6_ifinit(gchar *device) {
    gint err = 0;
    struct dhcp6_if *ifp = dhcp6_if;
    struct dhcp6_event *ev;
    gchar iaidstr[20];

    dhcp6_init_iaidaddr();
    /* get iaid for each interface */
    if (num_device == 0) {
        if ((num_device = create_iaid(&iaidtab[0], num_device)) < 0) {
            return -1;
        }

        if (ifp->iaidinfo.iaid == 0) {
            ifp->iaidinfo.iaid = get_iaid(ifp->ifname, &iaidtab[0],
                                          num_device);
        }

        if (ifp->iaidinfo.iaid == 0) {
            g_debug("%s interface %s iaid failed to be created",
                    FNAME, ifp->ifname);
            return -1;
        }

        g_debug("%s interface %s iaid is %u", FNAME, ifp->ifname,
                ifp->iaidinfo.iaid);
    }

    client6_iaidaddr.ifp = ifp;
    memcpy(&client6_iaidaddr.client6_info.iaidinfo, &ifp->iaidinfo,
           sizeof(client6_iaidaddr.client6_info.iaidinfo));
    duidcpy(&client6_iaidaddr.client6_info.clientid, &client_duid);
    save_duid(duidfile, device, &client_duid);

    if (!(ifp->send_flags & DHCIFF_INFO_ONLY) &&
        !(client6_request_flag & CLIENT6_INFO_REQ) &&
        ((ifp->ra_flag & IF_RA_MANAGED) ||
         !(ifp->ra_flag & IF_RA_OTHERCONF))) {
        /* parse the lease file */
        memset(&leasename, '\0', sizeof(leasename));
        strcpy(leasename, path_client6_lease);
        sprintf(iaidstr, "%u", ifp->iaidinfo.iaid);
        strcat(leasename, iaidstr);

        if ((client6_lease_file = init_leases(leasename)) == NULL) {
            g_error("%s failed to parse lease file", FNAME);
            return -1;
        }

        strcpy(client6_lease_temp, leasename);
        strcat(client6_lease_temp, "XXXXXX");
        client6_lease_file = sync_leases(client6_lease_file,
                                         leasename, client6_lease_temp);

        if (client6_lease_file == NULL) {
            return -1;
        }

        if (!TAILQ_EMPTY(&client6_iaidaddr.lease_list)) {
            struct dhcp6_listval *lv;

            if (!(client6_request_flag & CLIENT6_REQUEST_ADDR) &&
                !(client6_request_flag & CLIENT6_RELEASE_ADDR)) {
                client6_request_flag |= CLIENT6_CONFIRM_ADDR;
            }

            if (TAILQ_EMPTY(&request_list)) {
                if (_create_request_list(1) < 0) {
                    return -1;
                }
            } else if (client6_request_flag & CLIENT6_RELEASE_ADDR) {
                for (lv = TAILQ_FIRST(&request_list); lv;
                     lv = TAILQ_NEXT(lv, link)) {
                    if (dhcp6_find_lease(&client6_iaidaddr,
                                         &lv->val_dhcp6addr) == NULL) {
                        g_message("this address %s is not leased by "
                                  "this client",
                                  in6addr2str(&lv->val_dhcp6addr.addr, 0));
                        return -1;
                    }
                }
            }
        } else if (client6_request_flag & CLIENT6_RELEASE_ADDR) {
            g_message("no ipv6 addresses are leased by client");
            return -1;
        }
    }

    ifp->link_flag |= IFF_RUNNING;

    /* get addrconf prefix from kernel */
    err = get_if_rainfo(ifp);
    if (err) {
        g_error("failed to get interface info via libnl: %d", err);
        return -1;
    }

    /* set up check link timer and sync file timer */
    if ((ifp->link_timer = dhcp6_add_timer(_check_link_timo, ifp)) < 0) {
        g_error("%s failed to create a timer", FNAME);
        return -1;
    }

    if ((ifp->sync_timer = dhcp6_add_timer(_check_lease_file_timo, ifp)) < 0) {
        g_error("%s failed to create a timer", FNAME);
        return -1;
    }

    /* DAD timer set up after getting the address */
    ifp->dad_timer = NULL;

    /* create an event for the initial delay */
    if ((ev = dhcp6_create_event(ifp, DHCP6S_INIT)) == NULL) {
        g_error("%s failed to create an event", FNAME);
        return -1;
    }

    run_script(ifp, DHCP6S_INIT, ev->state, ev->uuid);

    ifp->servers = NULL;
    ev->ifp->current_server = NULL;
    TAILQ_INSERT_TAIL(&ifp->event_list, ev, link);

    if ((ev->timer = dhcp6_add_timer(client6_timo, ev)) == NULL) {
        g_error("%s failed to add a timer for %s", FNAME, ifp->ifname);
        return -1;
    }

    dhcp6_reset_timer(ev);
    return 0;
}

static iatype_t _iatype_of_if(struct dhcp6_if *ifp) {
    if (ifp->send_flags & DHCIFF_PREFIX_DELEGATION) {
        return IAPD;
    } else if (ifp->send_flags & DHCIFF_TEMP_ADDRS) {
        return IATA;
    } else {
        return IANA;
    }
}

static void _free_resources(struct dhcp6_if *ifp) {
    struct dhcp6_event *ev, *ev_next;
    struct dhcp6_lease *sp, *sp_next;
    struct stat buf;

    for (sp = TAILQ_FIRST(&client6_iaidaddr.lease_list); sp; sp = sp_next) {
        sp_next = TAILQ_NEXT(sp, link);
        if (client6_ifaddrconf(IFADDRCONF_REMOVE, &sp->lease_addr) != 0)
            g_message("%s deconfiging address %s failed",
                      FNAME, in6addr2str(&sp->lease_addr.addr, 0));
    }

    g_debug("%s remove all events on interface", FNAME);

    /* cancel all outstanding events for each interface */
    for (ev = TAILQ_FIRST(&ifp->event_list); ev; ev = ev_next) {
        ev_next = TAILQ_NEXT(ev, link);
        dhcp6_remove_event(ev);
    }

    /* restore /etc/resolv.conf.dhcpv6.bak back to /etc/resolv.conf */
    if (!lstat(RESOLV_CONF_BAK_FILE, &buf)) {
        if (rename(RESOLV_CONF_BAK_FILE, _PATH_RESCONF)) {
            g_error("%s failed to backup resolv.conf", FNAME);
        }
    }

    free_servers(ifp);
}

static void _process_signals(void) {
    if ((sig_flags & SIGF_TERM)) {
        g_message("%s exiting", FNAME);
        _free_resources(dhcp6_if);
        unlink(pidfile);
        exit(0);
    }

    if ((sig_flags & SIGF_HUP)) {
        g_message("%s restarting", FNAME);
        _free_resources(dhcp6_if);
        _client6_ifinit(device);
    }

    if ((sig_flags & SIGF_CLEAN)) {
        _free_resources(dhcp6_if);
        unlink(pidfile);
        exit(0);
    }

    sig_flags = 0;
    return;
}

static struct dhcp6_event *_find_event_withid(struct dhcp6_if *ifp,
                                             guint32 xid) {
    struct dhcp6_event *ev;

    for (ev = TAILQ_FIRST(&ifp->event_list); ev; ev = TAILQ_NEXT(ev, link)) {
        g_debug("%s ifp %p event %p id is %x", FNAME, ifp, ev, ev->xid);
        if (ev->xid == xid)
            return ev;
    }

    return NULL;
}

static struct dhcp6_serverinfo *_allocate_newserver(struct dhcp6_if *ifp,
                                                    struct dhcp6_optinfo
                                                    *optinfo) {
    struct dhcp6_serverinfo *newserver, **sp;

    /* keep the server */
    if ((newserver = malloc(sizeof(*newserver))) == NULL) {
        g_error("%s memory allocation failed for server", FNAME);
        return NULL;
    }

    memset(newserver, 0, sizeof(*newserver));
    dhcp6_init_options(&newserver->optinfo);

    if (dhcp6_copy_options(&newserver->optinfo, optinfo)) {
        g_error("%s failed to copy options", FNAME);
        free(newserver);
        return NULL;
    }

    g_debug("%s new server DUID %s, len %d ",
            FNAME, duidstr(&newserver->optinfo.serverID),
            newserver->optinfo.serverID.duid_len);

    if (optinfo->pref != DH6OPT_PREF_UNDEF) {
        newserver->pref = optinfo->pref;
    }

    if (optinfo->flags & DHCIFF_UNICAST) {
        memcpy(&newserver->server_addr, &optinfo->server_addr,
               sizeof(newserver->server_addr));
    }

    newserver->active = 1;
    for (sp = &ifp->servers; *sp; sp = &(*sp)->next) {
        if ((*sp)->pref != DH6OPT_PREF_MAX && (*sp)->pref < newserver->pref) {
            break;
        }
    }

    newserver->next = *sp;
    *sp = newserver;
    return newserver;
}

static gint _client6_recvreply(struct dhcp6_if *ifp, struct dhcp6 *dh6,
                               ssize_t len, struct dhcp6_optinfo *optinfo) {
    struct ia_listval *ia;
    struct dhcp6_event *ev;
    struct dhcp6_serverinfo *newserver;
    gint newstate = 0;
    gint err = 0;
    gint prevstate = 0;

    /* find the corresponding event based on the received xid */
    g_debug("%s reply message XID is (%x)",
            FNAME, ntohl(dh6->dh6_xid) & DH6_XIDMASK);
    ev = _find_event_withid(ifp, ntohl(dh6->dh6_xid) & DH6_XIDMASK);

    if (ev == NULL) {
        g_message("%s XID mismatch", FNAME);
        return -1;
    }

    if (!(DHCP6S_VALID_REPLY(ev->state)) &&
        (ev->state != DHCP6S_SOLICIT ||
         !(optinfo->flags & DHCIFF_RAPID_COMMIT))) {
        g_message("%s unexpected reply", FNAME);
        return -1;
    }

    /* A Reply message must contain a Server ID option */
    if (optinfo->serverID.duid_len == 0) {
        g_message("%s no server ID option", FNAME);
        return -1;
    }

    g_debug("%s serverID is %s len is %d", FNAME,
            duidstr(&optinfo->serverID), optinfo->serverID.duid_len);

    /* get current server */
    switch (ev->state) {
        case DHCP6S_SOLICIT:
        case DHCP6S_CONFIRM:
        case DHCP6S_REBIND:
            newserver = _allocate_newserver(ifp, optinfo);

            if (newserver == NULL) {
                return -1;
            }

            ifp->current_server = newserver;
            duidcpy(&client6_iaidaddr.client6_info.serverid,
                    &ifp->current_server->optinfo.serverID);
            break;
        default:
            break;
    }

    /*
     * DUID in the Client ID option (which must be contained for our
     * client implementation) must match ours.
     */
    if (optinfo->clientID.duid_len == 0) {
        g_message("%s no client ID option", FNAME);
        return -1;
    }

    if (duidcmp(&optinfo->clientID, &client_duid)) {
        g_message("%s client DUID mismatch", FNAME);
        return -1;
    }

    if (!TAILQ_EMPTY(&optinfo->dns_list.addrlist) ||
        optinfo->dns_list.domainlist != NULL) {
        resolv_parse(&optinfo->dns_list);
    }

    /*
     * The client MAY choose to report any status code or message from the
     * status code option in the Reply message.
     * [dhcpv6-26 Section 18.1.8]
     */
    if (optinfo->status_code != DH6OPT_STCODE_UNDEFINE) {
        g_message("%s status code of message: %s",
                  FNAME, dhcp6_stcodestr(optinfo->status_code));
    }

    ia = ia_find_listval(&optinfo->ia_list,
                         _iatype_of_if(ifp), ifp->iaidinfo.iaid);

    if (ia == NULL) {
        g_message("%s no IA option", FNAME);
    } else if (ia->status_code != DH6OPT_STCODE_UNDEFINE) {
        g_message("%s status code of IA: %s",
                  FNAME, dhcp6_stcodestr(ia->status_code));
    }

    switch (optinfo->status_code) {
        case DH6OPT_STCODE_UNSPECFAIL:
        case DH6OPT_STCODE_USEMULTICAST:
            /* retransmit the message with multicast address */
            /* how many time allow the retransmission with error status code? 
             */
            return -1;
    }

    /*
     * Update configuration information to be renewed or rebound
     * declined, confirmed, released.
     * Note that the returned list may be empty, in which case
     * the waiting information should be removed.
     */
    switch (ev->state) {
        case DHCP6S_SOLICIT:
            if (ia == NULL) {
                break;
            } else if (!(optinfo->flags & DHCIFF_RAPID_COMMIT)) {
                newstate = DHCP6S_REQUEST;
                break;
            }
        case DHCP6S_REQUEST:
            if (ia == NULL) {
                break;
            }

            /* NotOnLink: 1. SOLICIT NoAddrAvail: Information Request */
            switch (ia->status_code) {
                case DH6OPT_STCODE_NOTONLINK:
                    g_debug("%s got a NotOnLink reply for request/rapid commit,"
                            " sending solicit.", FNAME);
                    newstate = DHCP6S_SOLICIT;
                    break;
                case DH6OPT_STCODE_NOADDRAVAIL:
                case DH6OPT_STCODE_NOPREFIXAVAIL:
                    g_debug("%s got a NoAddrAvail reply for request/rapid "
                            "commit, sending inforeq.", FNAME);
                    ia = NULL;
                    newstate = DHCP6S_INFOREQ;
                    break;
                case DH6OPT_STCODE_SUCCESS:
                case DH6OPT_STCODE_UNDEFINE:
                default:
                    if (!TAILQ_EMPTY(&ia->addr_list)) {
                        err = get_if_rainfo(ifp);
                        if (err) {
                            g_error("failed to get interface info via "
                                    "libnl: %d", err);
                            return -1;
                        }

                        dhcp6_add_iaidaddr(optinfo, ia);

                        if (ifp->dad_timer == NULL &&
                            (ifp->dad_timer = dhcp6_add_timer(_check_dad_timo,
                                                              ifp)) < 0) {
                            g_message("%s failed to create a timer for DAD",
                                      FNAME);
                        }

                        _setup_check_timer(ifp);
                    }

                    break;
            }

            break;
        case DHCP6S_RENEW:
        case DHCP6S_REBIND:
            if (ia == NULL) {
                newstate = ev->state;
                break;
            }

            if (client6_request_flag & CLIENT6_CONFIRM_ADDR) {
                goto rebind_confirm;
            }

            /* NoBinding for RENEW, REBIND, send REQUEST */
            switch (ia->status_code) {
                case DH6OPT_STCODE_NOBINDING:
                    newstate = DHCP6S_REQUEST;
                    g_debug("%s got a NoBinding reply, sending request.",
                            FNAME);
                    dhcp6_remove_iaidaddr(&client6_iaidaddr);
                    break;
                case DH6OPT_STCODE_NOADDRAVAIL:
                case DH6OPT_STCODE_NOPREFIXAVAIL:
                case DH6OPT_STCODE_UNSPECFAIL:
                    break;
                case DH6OPT_STCODE_SUCCESS:
                case DH6OPT_STCODE_UNDEFINE:
                default:
                    dhcp6_update_iaidaddr(optinfo, ia, ADDR_UPDATE);
                    break;
            }

            break;
        case DHCP6S_CONFIRM:
            /* NOtOnLink for a Confirm, send SOLICIT message */
          rebind_confirm:
            client6_request_flag &= ~CLIENT6_CONFIRM_ADDR;

            switch (optinfo->status_code) {
                    struct timeb now;

                    struct timeval timo;

                    time_t offset;

                case DH6OPT_STCODE_NOTONLINK:
                case DH6OPT_STCODE_NOBINDING:
                case DH6OPT_STCODE_NOADDRAVAIL:
                    g_debug("%s got a NotOnLink reply for confirm, "
                            "sending solicit.", FNAME);
                    /* remove event data list */
                    free_servers(ifp);
                    /* remove the address which is judged NotOnLink */
                    dhcp6_remove_iaidaddr(&client6_iaidaddr);
                    newstate = DHCP6S_SOLICIT;
                    break;
                case DH6OPT_STCODE_SUCCESS:
                case DH6OPT_STCODE_UNDEFINE:
                    /* XXX: set up renew/rebind timer */
                    g_debug("%s got an expected reply for confirm", FNAME);
                    ftime(&now);
                    client6_iaidaddr.state = ACTIVE;

                    if ((client6_iaidaddr.timer =
                         dhcp6_add_timer(dhcp6_iaidaddr_timo,
                                         &client6_iaidaddr)) == NULL) {
                        g_error("%s failed to add a timer for iaid %u", FNAME,
                                client6_iaidaddr.client6_info.  iaidinfo.iaid);
                        return -1;
                    }

                    if (client6_iaidaddr.client6_info.iaidinfo.renewtime == 0) {
                        client6_iaidaddr.client6_info.iaidinfo.renewtime
                            = get_min_preferlifetime(&client6_iaidaddr) / 2;
                    }

                    if (client6_iaidaddr.client6_info.iaidinfo.rebindtime ==
                        0) {
                        client6_iaidaddr.client6_info.iaidinfo.rebindtime =
                            (get_min_preferlifetime(&client6_iaidaddr) * 4) /
                            5;
                    }

                    offset = now.time - client6_iaidaddr.start_date;

                    if (offset >
                        client6_iaidaddr.client6_info.iaidinfo.renewtime) {
                        timo.tv_sec = 0;
                    } else {
                        timo.tv_sec =
                            client6_iaidaddr.client6_info.iaidinfo.renewtime -
                            offset;
                    }

                    timo.tv_usec = 0;
                    dhcp6_set_timer(&timo, client6_iaidaddr.timer);

                    /* check DAD */
                    if (client6_iaidaddr.client6_info.type != IAPD &&
                        ifp->dad_timer == NULL &&
                        (ifp->dad_timer =
                         dhcp6_add_timer(_check_dad_timo, ifp)) < 0) {
                        g_message("%s failed to create a timer for  DAD",
                                  FNAME);
                    }

                    _setup_check_timer(ifp);

                    break;
                default:
                    break;
            }

            break;
        case DHCP6S_DECLINE:
            /* send REQUEST message to server with none decline address */
            g_debug("%s got an expected reply for decline, sending request.",
                    FNAME);
            _create_request_list(0);

            /* remove event data list */
            newstate = DHCP6S_REQUEST;
            break;
        case DHCP6S_RELEASE:
            g_message("%s got an expected release, exit.", FNAME);
            dhcp6_remove_event(ev);
            exit(0);
        case DHCP6S_INFOREQ:
            _set_info_refresh_timer(ifp, optinfo->irt);
            break;
        default:
            break;
    }

    prevstate = ev->state;
    dhcp6_remove_event(ev);

    if (newstate) {
        client6_send_newstate(ifp, newstate);
    } else {
        g_debug("%s got an expected reply, sleeping.", FNAME);
    }

    dhcp6_clear_list(&request_list);
    TAILQ_INIT(&request_list);
    return 0;
}

static gint _client6_recvadvert(struct dhcp6_if *ifp, struct dhcp6 *dh6,
                                ssize_t len, struct dhcp6_optinfo *optinfo0) {
    struct ia_listval *ia;
    struct dhcp6_serverinfo *newserver;
    struct dhcp6_event *ev;

    /* find the corresponding event based on the received xid */
    ev = _find_event_withid(ifp, ntohl(dh6->dh6_xid) & DH6_XIDMASK);
    if (ev == NULL) {
        g_message("%s XID mismatch", FNAME);
        return -1;
    }

    /* if server policy doesn't allow rapid commit if (ev->state !=
     * DHCP6S_SOLICIT || (ifp->send_flags & DHCIFF_RAPID_COMMIT)) { */
    if (ev->state != DHCP6S_SOLICIT) {
        g_message("%s unexpected advertise", FNAME);
        return -1;
    }

    /* packet validation based on Section 15.3 of dhcpv6-26. */
    if (optinfo0->serverID.duid_len == 0) {
        g_message("%s no server ID option", FNAME);
        return -1;
    } else {
        g_debug("%s server ID: %s, pref=%2x", FNAME,
                duidstr(&optinfo0->serverID), optinfo0->pref);
    }

    if (optinfo0->clientID.duid_len == 0) {
        g_message("%s no client ID option", FNAME);
        return -1;
    }

    if (duidcmp(&optinfo0->clientID, &client_duid)) {
        g_message("%s client DUID mismatch", FNAME);
        return -1;
    }

    /*
     * The client MUST ignore any Advertise message that includes a Status
     * Code option containing any error.
     */
    g_message("%s status code: %s", FNAME,
              dhcp6_stcodestr(optinfo0->status_code));
    if (optinfo0->status_code != DH6OPT_STCODE_SUCCESS &&
        optinfo0->status_code != DH6OPT_STCODE_UNDEFINE) {
        return -1;
    }

    /* ignore the server if it is known */
    if (_find_server(ifp, &optinfo0->serverID)) {
        g_message("%s duplicated server (ID: %s)",
                  FNAME, duidstr(&optinfo0->serverID));
        return -1;
    }

    newserver = _allocate_newserver(ifp, optinfo0);

    if (newserver == NULL) {
        return -1;
    }

    /* if the server has an extremely high preference, just use it. */
    if (newserver->pref == DH6OPT_PREF_MAX) {
        ev->timeouts = 0;
        _ev_set_state(ev, DHCP6S_REQUEST);
        ifp->current_server = newserver;
        dhcp6_set_timeoparam(ev);
        dhcp6_reset_timer(ev);
        client6_send(ev);
    } else if (ifp->servers->next == NULL) {
        struct timeval *rest, elapsed, tv_rt, tv_irt, timo;

        /* 
         * If this is the first advertise, adjust the timer so that
         * the client can collect other servers until IRT elapses.
         * XXX: we did not want to do such "low level" timer
         *      calculation here.
         */
        rest = dhcp6_timer_rest(ev->timer);
        tv_rt.tv_sec = (ev->retrans * 1000) / 1000000;
        tv_rt.tv_usec = (ev->retrans * 1000) % 1000000;
        tv_irt.tv_sec = (ev->init_retrans * 1000) / 1000000;
        tv_irt.tv_usec = (ev->init_retrans * 1000) % 1000000;
        timeval_sub(&tv_rt, rest, &elapsed);

        if (TIMEVAL_LEQ(elapsed, tv_irt)) {
            timeval_sub(&tv_irt, &elapsed, &timo);
        } else {
            timo.tv_sec = timo.tv_usec = 0;
        }

        g_debug("%s reset timer for %s to %d.%06d", FNAME, ifp->ifname,
                (gint) timo.tv_sec, (gint) timo.tv_usec);

        dhcp6_set_timer(&timo, ev->timer);
    }

    /* if the client send preferred addresses reqeust in SOLICIT */
    /* XXX: client might have some local policy to select the addresses */
    if ((ia = ia_find_listval(&optinfo0->ia_list,
                              _iatype_of_if(ifp),
                              ifp->iaidinfo.iaid)) != NULL) {
        dhcp6_copy_list(&request_list, &ia->addr_list);
    }

    return 0;
}

static void _client6_recv(void) {
    gchar rbuf[BUFSIZ], cmsgbuf[BUFSIZ];
    struct msghdr mhdr;
    struct iovec iov;
    struct sockaddr_storage from;
    struct dhcp6_if *ifp;
    struct dhcp6opt *p, *ep;
    struct dhcp6_optinfo optinfo;
    ssize_t len;
    struct dhcp6 *dh6;
    struct cmsghdr *cm;
    struct in6_pktinfo *pi = NULL;

    memset(&iov, 0, sizeof(iov));
    memset(&mhdr, 0, sizeof(mhdr));

    iov.iov_base = (caddr_t) rbuf;
    iov.iov_len = sizeof(rbuf);
    mhdr.msg_name = (caddr_t) & from;
    mhdr.msg_namelen = sizeof(from);
    mhdr.msg_iov = &iov;
    mhdr.msg_iovlen = 1;
    mhdr.msg_control = (caddr_t) cmsgbuf;
    mhdr.msg_controllen = sizeof(cmsgbuf);

    if ((len = recvmsg(iosock, &mhdr, 0)) < 0) {
        g_error("%s recvmsg: %s", FNAME, strerror(errno));
        return;
    }

    /* detect receiving interface */
    for (cm = (struct cmsghdr *) CMSG_FIRSTHDR(&mhdr); cm;
         cm = (struct cmsghdr *) CMSG_NXTHDR(&mhdr, cm)) {
        if (cm->cmsg_level == IPPROTO_IPV6 &&
            cm->cmsg_type == IPV6_PKTINFO &&
            cm->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) {
            pi = (struct in6_pktinfo *) (CMSG_DATA(cm));
        }
    }

    if (pi == NULL) {
        g_message("%s failed to get packet info", FNAME);
        return;
    }

    if ((ifp = find_ifconfbyid(pi->ipi6_ifindex)) == NULL) {
        g_message("%s unexpected interface (%d)", FNAME,
                  (guint) pi->ipi6_ifindex);
        return;
    }

    g_debug("receive packet info ifname %s, addr is %s scope id is %d",
            ifp->ifname, in6addr2str(&pi->ipi6_addr, 0), pi->ipi6_ifindex);
    dh6 = (struct dhcp6 *) rbuf;
    g_debug("%s receive %s from %s scope id %d %s", FNAME,
            dhcp6msgstr(dh6->dh6_msgtype),
            addr2str((struct sockaddr *) &from, sizeof(from)),
            ((struct sockaddr_in6 *) &from)->sin6_scope_id, ifp->ifname);

    /* get options */
    dhcp6_init_options(&optinfo);
    p = (struct dhcp6opt *) (dh6 + 1);
    ep = (struct dhcp6opt *) ((gchar *) dh6 + len);

    if (dhcp6_get_options(p, ep, &optinfo) < 0) {
        g_message("%s failed to parse options", FNAME);
    }

    switch (dh6->dh6_msgtype) {
        case DH6_ADVERTISE:
            (void) _client6_recvadvert(ifp, dh6, len, &optinfo);
            break;
        case DH6_REPLY:
            (void) _client6_recvreply(ifp, dh6, len, &optinfo);
            break;
        default:
            g_message("%s received an unexpected message (%s) from %s",
                      FNAME, dhcp6msgstr(dh6->dh6_msgtype),
                      addr2str((struct sockaddr *) &from, sizeof(from)));
            break;
    }

    dhcp6_clear_options(&optinfo);
    return;
}

static void _client6_mainloop(void) {
    struct timeval *w;
    gint ret;
    fd_set r;

    while (1) {
        if (sig_flags) {
            _process_signals();
        }

        w = dhcp6_check_timer();

        FD_ZERO(&r);
        FD_SET(iosock, &r);

        ret = select(iosock + 1, &r, NULL, NULL, w);
        switch (ret) {
            case -1:
                if (errno != EINTR) {
                    g_error("%s select: %s", FNAME, strerror(errno));
                    return;
                }

                break;
            case 0:            /* timeout */
                break;          /* dhcp6_check_timer() will treat the case */
            default:           /* received a packet */
                _client6_recv();
        }
    }

    return;
}

static struct dhcp6_serverinfo *_select_server(struct dhcp6_if *ifp) {
    struct dhcp6_serverinfo *s;

    /*
     * pick the best server according to dhcpv6-26 Section 17.1.3
     * XXX: we currently just choose the one that is active and has the
     * highest preference.
     */
    for (s = ifp->servers; s; s = s->next) {
        if (s->active) {
            g_debug("%s picked a server (ID: %s)",
                    FNAME, duidstr(&s->optinfo.serverID));
            return s;
        }
    }

    return NULL;
}

static void _client6_signal(gint sig) {
    g_message("%s received a signal (%d)", FNAME, sig);

    switch (sig) {
        case SIGTERM:
            sig_flags |= SIGF_TERM;
            break;
        case SIGHUP:
            sig_flags |= SIGF_HUP;
            break;
        case SIGINT:
        case SIGKILL:
            sig_flags |= SIGF_CLEAN;
            break;
        default:
            break;
    }
}

static void _setup_interface(gchar *ifname) {
    struct ifreq ifr;
    gint retries = 0;

    /* check the interface */

    /* open a socket to watch the off-on link for confirm messages */
    if ((nlsock == -1) && ((nlsock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)) {
        g_error("%s open a socket: %s", FNAME, strerror(errno));
        return;
    }

    memset(&ifr, '\0', sizeof(struct ifreq));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(nlsock, SIOCGIFFLAGS, &ifr) < 0) {
        g_error("ioctl SIOCGIFFLAGS failed");
        return;
    }

    while ((ifr.ifr_flags & (IFF_UP | IFF_RUNNING)) != (IFF_UP | IFF_RUNNING)) {
        if (retries++ > 1) {
            g_message("NIC is not connected to the network, please connect it.");
            return;
        }

        ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
        if (ioctl(nlsock, SIOCSIFFLAGS, &ifr) < 0) {
            g_error("ioctl SIOCSIFFLAGS failed");
            return;
        }

        /*
         * give kernel time to assign link local address and to find/respond
         * to IPv6 routers...
         */
        sleep(2);

        memset(&ifr, '\0', sizeof(struct ifreq));
        strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

        if (ioctl(nlsock, SIOCGIFFLAGS, &ifr) < 0) {
            g_error("ioctl SIOCGIFFLAGS failed");
            return;
        }
    }

    return;
}

void _unset_env_var(gpointer data, gpointer user_data) {
    const gchar *envvar = (const gchar *) data;
    g_unsetenv(envvar);
    return;
}

/* END STATIC FUNCTIONS */

gint client6_init(gchar *device) {
    struct addrinfo hints, *res;
    static struct sockaddr_in6 sa6_allagent_storage;
    gint error, on = 1;
    struct dhcp6_if *ifp;
    gint ifidx;
    gchar linklocal[64];
    struct in6_addr lladdr;
    time_t retry, now;
    gint bound;

    ifidx = if_nametoindex(device);
    if (ifidx == 0) {
        g_error("if_nametoindex(%s)", device);
        return -1;
    }

    /* get our DUID */
    if (get_duid(duidfile, device, &client_duid)) {
        g_error("%s failed to get a DUID", FNAME);
        return -1;
    }

    if (get_linklocal(device, &lladdr) < 0) {
        return -1;
    }

    if (inet_ntop(AF_INET6, &lladdr, linklocal, sizeof(linklocal)) < 0) {
        return -1;
    }

    g_debug("link local addr is %s", linklocal);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_INET6;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = 0;
    error = getaddrinfo(linklocal, DH6PORT_DOWNSTREAM, &hints, &res);

    if (error) {
        g_error("%s getaddrinfo: %s", FNAME, strerror(error));
        return -1;
    }

    iosock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (iosock < 0) {
        g_error("%s socket", FNAME);
        return -1;
    }
#ifdef IPV6_RECVPKTINFO
    if (setsockopt(iosock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on,
                   sizeof(on)) < 0) {
        g_error("%s setsockopt(inbound, IPV6_RECVPKTINFO): %s",
                FNAME, strerror(errno));
        return -1;
    }
#else
    if (setsockopt(iosock, IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof(on)) < 0) {
        g_error("%s setsockopt(inbound, IPV6_PKTINFO): %s",
                FNAME, strerror(errno));
        return -1;
    }
#endif

    ((struct sockaddr_in6 *) (res->ai_addr))->sin6_scope_id = ifidx;
    g_debug("res addr is %s/%d", addr2str(res->ai_addr, res->ai_addrlen),
            res->ai_addrlen);

    /* 
     * If the interface has JUST been brought up, the kernel may not have
     * enough time to allow the bind to the linklocal address - it will
     * then return EADDRNOTAVAIL. The bind will succeed if we try again.
     */
    retry = now = time(0);
    bound = 0;
    do {
        if (bind(iosock, res->ai_addr, res->ai_addrlen) < 0) {
            bound = -errno;
            retry = time(0);

            if ((bound != -EADDRNOTAVAIL) || ((retry - now) > 5)) {
                break;
            }

            struct timespec tv = { 0, 200000000 };
            nanosleep(&tv, 0);
        } else {
            bound = 1;
            break;
        }
    } while ((retry - now) < 5);

    if (bound < 0) {
        g_error("%s bind: %s", FNAME, strerror(-bound));
        return -1;
    }

    freeaddrinfo(res);

    /* initiallize socket address structure for outbound packets */
    hints.ai_flags = 0;
    error = getaddrinfo(linklocal, DH6PORT_UPSTREAM, &hints, &res);

    if (error) {
        g_error("%s getaddrinfo: %s", FNAME, gai_strerror(error));
        return -1;
    }

    if (setsockopt(iosock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                   &ifidx, sizeof(ifidx)) < 0) {
        g_error("%s setsockopt(iosock, IPV6_MULTICAST_IF): %s",
                FNAME, strerror(errno));
        return -1;
    }

    ((struct sockaddr_in6 *) (res->ai_addr))->sin6_scope_id = ifidx;
    freeaddrinfo(res);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_INET6;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    error = getaddrinfo(DH6ADDR_ALLAGENT, DH6PORT_UPSTREAM, &hints, &res);

    if (error) {
        g_error("%s getaddrinfo: %s", FNAME, gai_strerror(error));
        return -1;
    }

    memcpy(&sa6_allagent_storage, res->ai_addr, res->ai_addrlen);
    sa6_allagent = (const struct sockaddr_in6 *) &sa6_allagent_storage;
    sa6_alen = res->ai_addrlen;
    freeaddrinfo(res);

    /* client interface configuration */
    if ((ifp = find_ifconfbyname(device)) == NULL) {
        g_error("%s interface %s not configured", FNAME, device);
        return -1;
    }

    ifp->outsock = iosock;

    if (signal(SIGHUP, _client6_signal) == SIG_ERR) {
        g_warning("%s failed to set signal: %s", FNAME, strerror(errno));
        return -1;
    }

    if (signal(SIGTERM | SIGKILL, _client6_signal) == SIG_ERR) {
        g_warning("%s failed to set signal: %s", FNAME, strerror(errno));
        return -1;
    }

    if (signal(SIGINT, _client6_signal) == SIG_ERR) {
        g_warning("%s failed to set signal: %s", FNAME, strerror(errno));
        return -1;
    }

    return 0;
}

/*
 * Call libnl and collect information about the current state of the interface.
 */
gint get_if_rainfo(struct dhcp6_if *ifp) {
    struct nl_handle *handle = NULL;
    struct nl_cache *cache = NULL;
    struct nl_object *obj = NULL;
    struct rtnl_addr *raddr = NULL;
    struct rtnl_link *link = NULL;
    struct nl_addr *addr = NULL;
    gchar buf[INET6_ADDRSTRLEN + 1];
    struct in6_addr *tmpaddr = NULL;
    struct ra_info *rainfo = NULL, *ra = NULL, *ra_prev = NULL;

    memset(&buf, '\0', sizeof(buf));

    if ((handle = nl_handle_alloc()) == NULL) {
        return 1;
    }

    if (nl_connect(handle, NETLINK_ROUTE)) {
        nl_handle_destroy(handle);
        return 2;
    }

    if ((cache = rtnl_addr_alloc_cache(handle)) == NULL) {
        nl_close(handle);
        nl_handle_destroy(handle);
        return 3;
    }

    if ((obj = nl_cache_get_first(cache)) == NULL) {
        nl_close(handle);
        nl_handle_destroy(handle);
        return 4;
    }

    do {
        raddr = (struct rtnl_addr *) obj;

        /*
         * Copy IPv6 prefix addresses and associated values in to our
         * ifp->ralist array.
         */
        if ((rtnl_addr_get_ifindex(raddr) == ifp->ifid) &&
            (rtnl_addr_get_family(raddr) == AF_INET6) &&
            (rtnl_addr_get_scope(raddr) & RT_SCOPE_SITE)) {
            /* found a prefix address, add it to the list */
            addr = rtnl_addr_get_local(raddr);
            tmpaddr = (struct in6_addr *) nl_addr_get_binary_addr(addr);

            /* create a new rainfo struct and add it to the list of addresses 
             */
            rainfo = (struct ra_info *) malloc(sizeof(*rainfo));
            if (rainfo == NULL) {
                nl_addr_destroy(addr);
                rtnl_addr_put(raddr);
                nl_close(handle);
                nl_handle_destroy(handle);
                return 5;
            }

            memset(rainfo, 0, sizeof(rainfo));
            memcpy((&rainfo->prefix), tmpaddr, sizeof(struct in6_addr));
            rainfo->plen = rtnl_addr_get_prefixlen(raddr);

            if (inet_ntop(AF_INET6, &(rainfo->prefix), buf, INET6_ADDRSTRLEN)
                == NULL) {
                nl_addr_destroy(addr);
                rtnl_addr_put(raddr);
                nl_close(handle);
                nl_handle_destroy(handle);
                return 6;
            }

            g_debug("get prefix address %s", buf);
            g_debug("get prefix plen %d", rainfo->plen);

            if (ifp->ralist == NULL) {
                ifp->ralist = rainfo;
                rainfo->next = NULL;
            } else {
                ra_prev = ifp->ralist;

                for (ra = ifp->ralist; ra; ra = ra->next) {
                    if (rainfo->plen >= ra->plen) {
                        if (ra_prev == ra) {
                            ifp->ralist = rainfo;
                            rainfo->next = ra;
                        } else {
                            ra_prev->next = rainfo;
                            rainfo->next = ra;
                        }

                        break;
                    } else {
                        if (ra->next == NULL) {
                            ra->next = rainfo;
                            rainfo->next = NULL;
                            break;
                        } else {
                            ra_prev = ra;
                            continue;
                        }
                    }
                }
            }

            nl_addr_destroy(addr);

            /* gather flags */
            if ((cache = rtnl_addr_alloc_cache(handle)) == NULL) {
                rtnl_addr_put(raddr);
                nl_close(handle);
                nl_handle_destroy(handle);
                return 7;
            }

            link = rtnl_link_get(cache, rtnl_addr_get_ifindex(raddr));

            if (link) {
                ifp->ra_flag = rtnl_link_get_flags(link);
                rtnl_link_put(link);
                rtnl_addr_put(raddr);
            }
        }
    } while ((obj = nl_cache_get_next(obj)) != NULL);

    nl_close(handle);
    nl_handle_destroy(handle);
    return 0;
}

void client6_send(struct dhcp6_event *ev) {
    struct dhcp6_if *ifp;
    gchar buf[BUFSIZ];
    struct sockaddr_in6 dst;
    struct dhcp6 *dh6;
    struct dhcp6_optinfo optinfo;
    struct ia_listval *ia;
    ssize_t optlen, len;
    struct timeval duration, now;
    socklen_t salen;

    ifp = ev->ifp;
    dh6 = (struct dhcp6 *) buf;
    memset(dh6, 0, sizeof(*dh6));

    switch (ev->state) {
        case DHCP6S_SOLICIT:
            dh6->dh6_msgtype = DH6_SOLICIT;
            break;
        case DHCP6S_REQUEST:
            if (ifp->current_server == NULL) {
                g_error("%s assumption failure", FNAME);
                return;
            }

            dh6->dh6_msgtype = DH6_REQUEST;
            break;
        case DHCP6S_RENEW:
            if (ifp->current_server == NULL) {
                g_error("%s assumption failure", FNAME);
                return;
            }

            dh6->dh6_msgtype = DH6_RENEW;
            break;
        case DHCP6S_DECLINE:
            if (ifp->current_server == NULL) {
                g_error("%s assumption failure", FNAME);
                return;
            }

            dh6->dh6_msgtype = DH6_DECLINE;
            break;
        case DHCP6S_INFOREQ:
            dh6->dh6_msgtype = DH6_INFORM_REQ;
            break;
        case DHCP6S_REBIND:
            dh6->dh6_msgtype = DH6_REBIND;
            break;
        case DHCP6S_CONFIRM:
            dh6->dh6_msgtype = DH6_CONFIRM;
            break;
        case DHCP6S_RELEASE:
            dh6->dh6_msgtype = DH6_RELEASE;
            break;
        default:
            g_error("%s unexpected state %d", FNAME, ev->state);
            return;
    }

    /*
     * construct options
     */
    dhcp6_init_options(&optinfo);

    if ((ia = ia_create_listval()) == NULL) {
        goto end;
    }

    TAILQ_INSERT_TAIL(&optinfo.ia_list, ia, link);

    if (ev->timeouts == 0) {
        gettimeofday(&ev->start_time, NULL);
        optinfo.elapsed_time = 0;
        /* 
         * A client SHOULD generate a random number that cannot easily
         * be guessed or predicted to use as the transaction ID for
         * each new message it sends.
         *
         * A client MUST leave the transaction-ID unchanged in
         * retransmissions of a message. [dhcpv6-26 15.1]
         */
        ev->xid = random() & DH6_XIDMASK;
        g_debug("%s ifp %p event %p a new XID (%x) is generated",
                FNAME, ifp, ev, ev->xid);
    } else {
        guint etime;

        gettimeofday(&now, NULL);
        timeval_sub(&now, &(ev->start_time), &duration);
        etime = (duration.tv_sec) * 100 + (duration.tv_usec) / 10000;

        if (etime > DHCP6_ELAPSEDTIME_MAX) {
            etime = DHCP6_ELAPSEDTIME_MAX;
        }

        optinfo.elapsed_time = htons((uint16_t) etime);
    }

    dh6->dh6_xid &= ~ntohl(DH6_XIDMASK);
    dh6->dh6_xid |= htonl(ev->xid);
    len = sizeof(*dh6);

    /* server ID */
    switch (ev->state) {
        case DHCP6S_REQUEST:
        case DHCP6S_RENEW:
        case DHCP6S_DECLINE:
            if (&ifp->current_server->optinfo == NULL) {
                return;
            }

            g_debug("current server ID %s",
                    duidstr(&ifp->current_server->optinfo.serverID));

            if (duidcpy(&optinfo.serverID,
                        &ifp->current_server->optinfo.serverID)) {
                g_error("%s failed to copy server ID", FNAME);
                goto end;
            }

            break;
        case DHCP6S_RELEASE:
            if (duidcpy(&optinfo.serverID,
                        &client6_iaidaddr.client6_info.serverid)) {
                g_error("%s failed to copy server ID", FNAME);
                goto end;
            }

            break;
    }

    /* client ID */
    if (duidcpy(&optinfo.clientID, &client_duid)) {
        g_error("%s failed to copy client ID", FNAME);
        goto end;
    }

    /* save DUID now for persistent DUID (e.g., if client reboots) */
    if (save_duid(duidfile, device, &client_duid)) {
        g_error("%s failed to save client ID", FNAME);
        goto end;
    }

    /* option request options */
    if (dhcp6_copy_list(&optinfo.reqopt_list, &ifp->reqopt_list)) {
        g_error("%s failed to copy requested options", FNAME);
        goto end;
    }

    if (ifp->send_flags & DHCIFF_INFO_ONLY) {   /* RFC4242 */
        gint opttype = DH6OPT_INFO_REFRESH_TIME;

        if (dhcp6_add_listval(&optinfo.reqopt_list, &opttype,
                              DHCP6_LISTVAL_NUM) == NULL) {
            g_error("%s failed to copy infomation refresh time option", FNAME);
            goto end;
        }
    }

    switch (ev->state) {
        case DHCP6S_SOLICIT:
            /* rapid commit */
            if (ifp->send_flags & DHCIFF_RAPID_COMMIT) {
                optinfo.flags |= DHCIFF_RAPID_COMMIT;
            }

            if (!(ifp->send_flags & DHCIFF_INFO_ONLY) ||
                (client6_request_flag & CLIENT6_REQUEST_ADDR)) {
                memcpy(&ia->iaidinfo, &client6_iaidaddr.client6_info.iaidinfo,
                       sizeof(ia->iaidinfo));
                ia->type = _iatype_of_if(ifp);
            }

            /* support for client preferred ipv6 address */
            if (client6_request_flag & CLIENT6_REQUEST_ADDR) {
                if (dhcp6_copy_list(&ia->addr_list, &request_list)) {
                    goto end;
                }
            }

            break;
        case DHCP6S_REQUEST:
            if (!(ifp->send_flags & DHCIFF_INFO_ONLY)) {
                memcpy(&ia->iaidinfo, &client6_iaidaddr.client6_info.iaidinfo,
                       sizeof(ia->iaidinfo));
                g_debug("%s IAID is %u", FNAME, ia->iaidinfo.iaid);
                ia->type = _iatype_of_if(ifp);
            }

            /* 
             * Windows 2008 interoperability fix
             * If IA address is included in the DHCPv6 ADVERTISE (which is
             * what Windows 2008 does), put the IA address into the DHCPv6
             * REQUEST.  Windows 2008 will check for the IA address it has
             * given in the ADVERTISE, if it doesn't see it, the REQUEST
             * will be ignored).
             */
            if (!TAILQ_EMPTY(&request_list)) {
                dhcp6_copy_list(&ia->addr_list, &request_list);
            }

            break;
        case DHCP6S_RENEW:
        case DHCP6S_REBIND:
        case DHCP6S_RELEASE:
        case DHCP6S_CONFIRM:
        case DHCP6S_DECLINE:
            memcpy(&ia->iaidinfo, &client6_iaidaddr.client6_info.iaidinfo,
                   sizeof(ia->iaidinfo));
            ia->type = client6_iaidaddr.client6_info.type;

            if (ev->state == DHCP6S_CONFIRM) {
                ia->iaidinfo.renewtime = 0;
                ia->iaidinfo.rebindtime = 0;
            }

            if (!TAILQ_EMPTY(&request_list)) {
                /* XXX: ToDo: seperate to prefix list and address list */
                if (dhcp6_copy_list(&ia->addr_list, &request_list)) {
                    goto end;
                }
            } else {
                if (ev->state == DHCP6S_RELEASE) {
                    g_message("release empty address list");
                    return;
                }
                /* XXX: allow the other emtpy list ?? */
            }

            if (client6_request_flag & CLIENT6_RELEASE_ADDR) {
                if (dhcp6_update_iaidaddr(&optinfo, ia, ADDR_REMOVE)) {
                    g_message("client release failed");
                    return;
                }
            }

            break;
        default:
            break;
    }

    /* set options in the message */
    if ((optlen = dhcp6_set_options((struct dhcp6opt *) (dh6 + 1),
                                    (struct dhcp6opt *) (buf + sizeof(buf)),
                                    &optinfo)) < 0) {
        g_message("%s failed to construct options", FNAME);
        goto end;
    }

    len += optlen;

    /* 
     * Unless otherwise specified, a client sends DHCP messages to the
     * All_DHCP_Relay_Agents_and_Servers or the DHCP_Anycast address.
     * [dhcpv6-26 Section 13.]
     * Our current implementation always follows the case.
     */
    switch (ev->state) {
        case DHCP6S_REQUEST:
        case DHCP6S_RENEW:
        case DHCP6S_DECLINE:
        case DHCP6S_RELEASE:
            if (ifp->current_server &&
                !IN6_IS_ADDR_UNSPECIFIED(&ifp->current_server->server_addr)) {
                struct addrinfo hints, *res;
                gint error;

                memset(&hints, 0, sizeof(hints));
                hints.ai_family = PF_INET6;
                hints.ai_socktype = SOCK_DGRAM;
                hints.ai_protocol = IPPROTO_UDP;
                error =
                    getaddrinfo(in6addr2str
                                (&ifp->current_server->server_addr, 0),
                                DH6PORT_UPSTREAM, &hints, &res);

                if (error) {
                    g_error("%s getaddrinfo: %s", FNAME, gai_strerror(error));
                    return;
                }

                memcpy(&dst, res->ai_addr, res->ai_addrlen);
                salen = res->ai_addrlen;
                break;
            }
        default:
            if (sa6_allagent != NULL) {
                dst = *sa6_allagent;
            }

            salen = sa6_alen;
            break;
    }

    dst.sin6_scope_id = ifp->linkid;
    g_debug("send dst if %s addr is %s scope id is %d",
            ifp->ifname, addr2str((struct sockaddr *) &dst, salen),
            ifp->linkid);

    if (sendto(ifp->outsock, buf, len, MSG_DONTROUTE,
               (struct sockaddr *) &dst, sizeof(dst)) == -1) {
        g_error("%s transmit failed: %s", FNAME, strerror(errno));
        goto end;
    }

    g_debug("%s send %s to %s", FNAME, dhcp6msgstr(dh6->dh6_msgtype),
            addr2str((struct sockaddr *) &dst, salen));

end:
    dhcp6_clear_options(&optinfo);
    return;
}

void free_servers(struct dhcp6_if *ifp) {
    struct dhcp6_serverinfo *sp, *sp_next;

    /* free all servers we've seen so far */
    for (sp = ifp->servers; sp; sp = sp_next) {
        sp_next = sp->next;
        g_debug("%s removing server (ID: %s)",
                FNAME, duidstr(&sp->optinfo.serverID));
        dhcp6_clear_options(&sp->optinfo);
        free(sp);
    }

    ifp->servers = NULL;
    ifp->current_server = NULL;
    return;
}

gint client6_send_newstate(struct dhcp6_if *ifp, gint state) {
    struct dhcp6_event *ev;

    if ((ev = dhcp6_create_event(ifp, state)) == NULL) {
        g_error("%s failed to create an event", FNAME);
        return -1;
    }

    run_script(ifp, state, ev->state, ev->uuid);

    if ((ev->timer = dhcp6_add_timer(client6_timo, ev)) == NULL) {
        g_error("%s failed to add a timer for %s", FNAME, ifp->ifname);
        free(ev);
        return -1;
    }

    TAILQ_INSERT_TAIL(&ifp->event_list, ev, link);
    ev->timeouts = 0;
    dhcp6_set_timeoparam(ev);
    dhcp6_reset_timer(ev);
    client6_send(ev);

    return 0;
}

void run_script(struct dhcp6_if *ifp, gint old_state, gint new_state,
                guint32 uuid) {
    GString *tmp = NULL;
    gchar tmpaddr[INET6_ADDRSTRLEN];
    gboolean fail = FALSE;
    gchar *argv[] = { script, NULL };
    GSpawnFlags flags = 0;
    gint status = 0;
    GError *error = NULL;
    GSList *envvars = NULL;

    if (script == NULL) {
        return;
    }

    /* set environment variables for the program we are calling */

    /* dhcpv6_old_state */
    if (!g_setenv(OLD_STATE, dhcp6msgstr(old_state), TRUE)) {
        g_error("could not set %s environment variable", OLD_STATE);
    } else {
        envvars = g_slist_append(envvars, OLD_STATE);
    }

    /* dhcpv6_new_state */
    if (!g_setenv(NEW_STATE, dhcp6msgstr(new_state), TRUE)) {
        g_error("could not set %s environment variable", NEW_STATE);
    } else {
        envvars = g_slist_append(envvars, NEW_STATE);
    }

    /* dhcpv6_interface_name */
    if (!g_setenv(IFACE_NAME, ifp->ifname, TRUE)) {
        g_error("could not set %s environment variable", IFACE_NAME);
    } else {
        envvars = g_slist_append(envvars, IFACE_NAME);
    }

    /* dhcpv6_interface_index */
    tmp = g_string_new(NULL);
    g_string_printf(tmp, "%u", ifp->ifid);

    if (!g_setenv(IFACE_INDEX, tmp->str, TRUE)) {
        g_error("could not set %s environment variable", IFACE_INDEX);
    } else {
        envvars = g_slist_append(envvars, IFACE_INDEX);
    }

    if (g_string_free(tmp, TRUE) != NULL) {
        g_error("erroring releasing temporary GString");
    }

    /* dhcpv6_linklocal_address */
    memset(&tmpaddr, '\0', sizeof(tmpaddr));
    inet_ntop(AF_INET6, &ifp->linklocal, tmpaddr, sizeof(ifp->linklocal));
    if (tmpaddr == NULL) {
        g_error("%s line %d: %s", __func__, __LINE__, strerror(errno));
    } else {
        if (!g_setenv(LINKLOCAL_ADDR, tmpaddr, TRUE)) {
            g_error("could not set %s environment variable", LINKLOCAL_ADDR);
        } else {
            envvars = g_slist_append(envvars, LINKLOCAL_ADDR);
        }
    }

    /* dhcpv6_requested_options */
    tmp = dhcp6_options2str(&ifp->reqopt_list);

    if (!g_setenv(REQUESTED_OPTIONS, tmp->str, TRUE)) {
        g_error("could not set %s environment variable", REQUESTED_OPTIONS);
    } else {
        envvars = g_slist_append(envvars, REQUESTED_OPTIONS);
    }

    if (g_string_free(tmp, TRUE) != NULL) {
        g_error("erroring releasing temporary GString");
    }

    /*
     * set the following information in env vars:
     *
     * what we got from the server:
     *     address list (struct dhcp6_list addr_list)
     *     prefix list (struct dhcp6_list prefix_list)
     *     option list (struct dhcp6_option_list option_list)
     *
     * error code (where the hell is this?)
     */


    /*
     * use old_ and new_ variable naming based on the state we're in
     */



    /* run script */
    flags = G_SPAWN_FILE_AND_ARGV_ZERO;
    if (!g_spawn_sync(NULL, argv, NULL, flags, NULL, NULL, NULL, NULL,
                      &status, &error)) {
        /* error occurred */
        fail = TRUE;
    }

    if (fail) {
        g_error("error running %s", script);
        fail = FALSE;
    }

    /* unset all environment variables we added */
    g_slist_foreach(envvars, _unset_env_var, NULL);
    g_slist_free(envvars);

    return;
}

struct dhcp6_timer *client6_timo(void *arg) {
    struct dhcp6_event *ev = (struct dhcp6_event *) arg;
    struct dhcp6_if *ifp;
    struct timeval now;

    ifp = ev->ifp;
    ev->timeouts++;
    gettimeofday(&now, NULL);

    if ((ev->max_retrans_cnt && ev->timeouts >= ev->max_retrans_cnt) ||
        (ev->max_retrans_dur && (now.tv_sec - ev->start_time.tv_sec)
         >= ev->max_retrans_dur)) {
        /* XXX: check up the duration time for renew & rebind */
        g_message("%s no responses were received", FNAME);
        dhcp6_remove_event(ev); /* XXX: should free event data? */
        return NULL;
    }

    switch (ev->state) {
        case DHCP6S_INIT:
            /* From INIT state client could go to CONFIRM state if the client 
             * reboots; go to RELEASE state if the client issues a release;
             * go to INFOREQ state if the client requests info-only; go to
             * SOLICIT state if the client requests addresses; */
            ev->timeouts = 0;   /* indicate to generate a new XID. */

            /* 
             * three cases client send information request:
             * 1. configuration file includes information-only
             * 2. command line includes -I
             * 3. check interface flags if managed bit isn't set and
             *    if otherconf bit set by RA
             *    and information-only, conmand line -I are not set.
             */
            if ((ifp->send_flags & DHCIFF_INFO_ONLY) ||
                (client6_request_flag & CLIENT6_INFO_REQ) ||
                (!(ifp->ra_flag & IF_RA_MANAGED) &&
                 (ifp->ra_flag & IF_RA_OTHERCONF))) {
                _ev_set_state(ev, DHCP6S_INFOREQ);
            } else if (client6_request_flag & CLIENT6_RELEASE_ADDR) {
                /* do release */
                _ev_set_state(ev, DHCP6S_RELEASE);
            } else if (client6_request_flag & CLIENT6_CONFIRM_ADDR) {
                struct dhcp6_listval *lv;

                /* do confirm for reboot for IANA, IATA */
                if (client6_iaidaddr.client6_info.type == IAPD) {
                    _ev_set_state(ev, DHCP6S_REBIND);
                } else {
                    _ev_set_state(ev, DHCP6S_CONFIRM);
                }

                for (lv = TAILQ_FIRST(&request_list); lv;
                     lv = TAILQ_NEXT(lv, link)) {
                    lv->val_dhcp6addr.preferlifetime = 0;
                    lv->val_dhcp6addr.validlifetime = 0;
                }
            } else {
                _ev_set_state(ev, DHCP6S_SOLICIT);
            }

            dhcp6_set_timeoparam(ev);
        case DHCP6S_SOLICIT:
            if (ifp->servers) {
                ifp->current_server = _select_server(ifp);

                if (ifp->current_server == NULL) {
                    /* this should not happen! */
                    g_error("%s can't find a server", FNAME);
                    return NULL;
                }

                /* if get the address assginment break */
                if (!TAILQ_EMPTY(&client6_iaidaddr.lease_list)) {
                    dhcp6_remove_event(ev);
                    return NULL;
                }

                ev->timeouts = 0;
                _ev_set_state(ev, DHCP6S_REQUEST);
                dhcp6_set_timeoparam(ev);
            }
        case DHCP6S_INFOREQ:
        case DHCP6S_REQUEST:
            client6_send(ev);
            break;
        case DHCP6S_RELEASE:
        case DHCP6S_DECLINE:
        case DHCP6S_CONFIRM:
        case DHCP6S_RENEW:
        case DHCP6S_REBIND:
            if (!TAILQ_EMPTY(&request_list)) {
                client6_send(ev);
            } else {
                g_message("%s all information to be updated were canceled",
                          FNAME);
                dhcp6_remove_event(ev);
                return NULL;
            }

            break;
        default:
            break;
    }

    dhcp6_reset_timer(ev);
    return ev->timer;
}

gint main(gint argc, gchar **argv, gchar **envp) {
    gint ch;
    gchar *progname = basename(argv[0]);
    gchar *conffile = DHCP6C_CONF;
    FILE *pidfp;
    gchar *addr;
    gboolean verbose = FALSE;
    log_properties_t log_props;

    pid = getpid();
    srandom(time(NULL) & pid);

    TAILQ_INIT(&request_list);
    while ((ch = getopt(argc, argv, "c:r:R:P:vfIp:l:s:d:?")) != -1) {
        switch (ch) {
            case 'p':
                if (strlen(optarg) >= MAXPATHLEN) {
                    g_error("pid filename is too long");
                    exit(1);
                }

                pidfile = optarg;
                break;
            case 'c':
                if (strlen(optarg) >= MAXPATHLEN) {
                    g_error("configuration filename is too long");
                    exit(1);
                }

                conffile = optarg;
                break;
            case 'P':
                client6_request_flag |= CLIENT6_REQUEST_ADDR;

                for (addr = strtok(optarg, " "); addr;
                     addr = strtok(NULL, " ")) {
                    struct dhcp6_listval *lv;

                    if ((lv = (struct dhcp6_listval *) malloc(sizeof(*lv)))
                        == NULL) {
                        g_error("failed to allocate memory");
                        exit(1);
                    }

                    memset(lv, 0, sizeof(*lv));

                    if (inet_pton(AF_INET6, strtok(addr, "/"),
                                  &lv->val_dhcp6addr.addr) < 1) {
                        g_error("invalid ipv6address for release");
                        _usage(progname);
                        exit(1);
                    }

                    lv->val_dhcp6addr.type = IAPD;
                    lv->val_dhcp6addr.status_code = DH6OPT_STCODE_UNDEFINE;

                    errno = 0;
                    lv->val_dhcp6addr.plen = strtol(strtok(NULL, "/"),
                                                    NULL, 10);
                    if ((errno == ERANGE &&
                        (lv->val_dhcp6addr.plen == LONG_MIN ||
                         lv->val_dhcp6addr.plen == LONG_MAX)) ||
                        (errno != 0 && lv->val_dhcp6addr.plen == 0)) {
                        g_error("invalid ipv6 prefix length");
                        _usage(progname);
                        exit(1);
                    }

                    TAILQ_INSERT_TAIL(&request_list, lv, link);
                }

                break;
            case 'R':
                client6_request_flag |= CLIENT6_REQUEST_ADDR;

                for (addr = strtok(optarg, " "); addr;
                     addr = strtok(NULL, " ")) {
                    struct dhcp6_listval *lv;

                    if ((lv = (struct dhcp6_listval *) malloc(sizeof(*lv)))
                        == NULL) {
                        g_error("failed to allocate memory");
                        exit(1);
                    }

                    memset(lv, 0, sizeof(*lv));

                    if (inet_pton(AF_INET6, addr, &lv->val_dhcp6addr.addr) <
                        1) {
                        g_error("invalid ipv6address for release");
                        _usage(progname);
                        exit(1);
                    }

                    lv->val_dhcp6addr.type = IANA;
                    lv->val_dhcp6addr.status_code = DH6OPT_STCODE_UNDEFINE;
                    TAILQ_INSERT_TAIL(&request_list, lv, link);
                }

                break;
            case 'r':
                client6_request_flag |= CLIENT6_RELEASE_ADDR;

                if (strcmp(optarg, "all")) {
                    for (addr = strtok(optarg, " "); addr;
                         addr = strtok(NULL, " ")) {
                        struct dhcp6_listval *lv;

                        if ((lv =
                             (struct dhcp6_listval *) malloc(sizeof(*lv)))
                            == NULL) {
                            g_error("failed to allocate memory");
                            exit(1);
                        }

                        memset(lv, 0, sizeof(*lv));

                        if (inet_pton(AF_INET6, addr,
                                      &lv->val_dhcp6addr.addr) < 1) {
                            g_error("invalid ipv6address for release");
                            _usage(progname);
                            exit(1);
                        }

                        lv->val_dhcp6addr.type = IANA;
                        TAILQ_INSERT_TAIL(&request_list, lv, link);
                    }
                }

                break;
            case 'I':
                client6_request_flag |= CLIENT6_INFO_REQ;
                break;
            case 'l':
                if (strlen(optarg) >= MAXPATHLEN) {
                    g_error("lease database filename is too long");
                    exit(1);
                }

                path_client6_lease = optarg;
                break;
            case 's':
                if (strlen(optarg) >= MAXPATHLEN) {
                    g_error("script filename is too long");
                    exit(1);
                }

                script = optarg;
                break;
            case 'd':
                if (strlen(optarg) >= MAXPATHLEN) {
                    g_error("DUID filename is too long");
                    exit(1);
                }

                duidfile = optarg;
                break;
            case 'v':
                verbose = TRUE;
                break;
            case 'f':
                log_props.foreground = TRUE;
                break;
            case '?':
            default:
                _usage(progname);
                exit(0);
        }
    }

    argc -= optind;
    argv += optind;

    if (argc != 1) {
        _usage(progname);
        exit(0);
    }

    device = argv[0];

    log_props.pid = pid;
    setup_logging(progname, verbose, &log_props);

    /* dump current PID */
    if ((pidfp = fopen(pidfile, "w")) != NULL) {
        fprintf(pidfp, "%d\n", pid);
        fclose(pidfp);
    } else {
        fprintf(stderr, "Unable to write to %s: %s\n", pidfile,
                strerror(errno));
        fflush(stderr);
        abort();
    }

    ifinit(device);
    _setup_interface(device);

    if ((cfparse(conffile)) != 0) {
        g_error("%s failed to parse configuration file", FNAME);
        exit(1);
    }

    if (client6_init(device)) {
        return -1;
    }

    if (_client6_ifinit(device)) {
        return -1;
    }

    _client6_mainloop();

    return 0;
}

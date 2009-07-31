/* ported from KAME: config.h,v 1.18 2002/06/14 15:32:55 jinmei Exp */

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

#ifndef __CONFDATA_H_DEFINED
#define __CONFDATA_H_DEFINED

#define MAX_DEVICE 100

typedef struct _hardware_t {
    guint16 type;
    guint8 len;
    guchar data[6];
} hardware_t;

typedef struct _iaid_table_t {
    /* so far we support ethernet cards only */
    hardware_t hwaddr;
    guint32 iaid;
} iaid_table_t;

typedef struct _ra_info_t {
    struct in6_addr prefix;
    gint plen;
    gint flags;
} ra_info_t;

typedef struct _dhcp6_option_t {
    gint type;
    gint len;
    void *val;
} dhcp6_option_t;

typedef struct _dhcp6_serverinfo_t {
    struct _dhcp6_serverinfo_t *next;

    /* option information provided in the advertisement */
    dhcp6_optinfo_t optinfo;
    struct in6_addr server_addr;
    guint8 pref;                 /* preference */
    gint active;                 /* bool; if this server is active or not */
    /* TODO: remember available information from the server */
} dhcp6_serverinfo_t;

/* per-interface information */
typedef struct _dhcp6_if_t {
    struct _dhcp6_if_t *next;

    gint outsock;

    /* timer for the interface to sync file every 5 mins */
    dhcp6_timer_t *sync_timer;
#define DHCP6_SYNCFILE_TIME 60
    /* timer to check interface off->on link to send confirm message */
    dhcp6_timer_t *link_timer;
#define DHCP6_CHECKLINK_TIME_UPCASE 5
#define DHCP6_CHECKLINK_TIME_DOWNCASE 1
    dhcp6_timer_t *dad_timer;
#define DHCP6_CHECKDAD_TIME 5
    /* timer to refresh information */
    dhcp6_timer_t *info_refresh_timer;
    /* event queue */
    GSList *event_list;

    /* static parameters of the interface */
    gchar *ifname;
    guint ifid;
    GSList *ralist;
    dns_info_t dnsinfo;
    guint32 linkid;           /* to send link-local packets */
    dhcp6_iaid_info_t iaidinfo;

    guint16 ra_flag;
    guint16 link_flag;
    /* configuration parameters */
    gulong send_flags;
    gulong allow_flags;

#define DHCIFF_INFO_ONLY 0x1
#define DHCIFF_RAPID_COMMIT 0x2
#define DHCIFF_TEMP_ADDRS 0x4
#define DHCIFF_PREFIX_DELEGATION 0x8
#define DHCIFF_UNICAST 0x10

    struct in6_addr linklocal;
    gint server_pref;            /* server preference (server only) */
    guint32 default_irt;  /* default information refresh time (client only) */
    guint32 maximum_irt;  /* maximum information refresh time (client only) */
    GSList *reqopt_list;
    /* request specific addresses list from client */
    GSList *addr_list;
    GSList *prefix_list;
    GSList *option_list;
    dhcp6_serverinfo_t *current_server;
    dhcp6_serverinfo_t *servers;
} dhcp6_if_t;

typedef struct _client6_if_t {
    iatype_t type;
    dhcp6_iaid_info_t iaidinfo;
    duid_t clientid;
    duid_t serverid;
} client6_if_t;

typedef struct _dhcp6_iaidaddr_t {
    client6_if_t client6_info;
    time_t start_date;
    state_t state;
    dhcp6_if_t *ifp;
    dhcp6_timer_t *timer;
    /* list of client leases */
    GSList *lease_list;
} dhcp6_iaidaddr_t;

typedef struct _dhcp6_lease_t {
    gchar hostname[1024];
    struct in6_addr linklocal;
    dhcp6_addr_t lease_addr;
    iatype_t addr_type;
    state_t state;
    dhcp6_iaidaddr_t *iaidaddr;
    time_t start_date;
    /* address assigned on the interface */
    dhcp6_timer_t *timer;
} dhcp6_lease_t;

typedef struct _dhcp6_value_t {
    union {
        gint uv_num;
        struct in6_addr uv_addr6;
        dhcp6_addr_t uv_dhcp6_addr;
        dhcp6_lease_t uv_dhcp6_lease;
    } uv;
} dhcp6_value_t;

#define val_num uv.uv_num
#define val_addr6 uv.uv_addr6
#define val_dhcp6addr uv.uv_dhcp6_addr
#define val_dhcp6lease uv.uv_dhcp6_lease

typedef struct _dhcp6_event_t {
    dhcp6_if_t *ifp;
    dhcp6_timer_t *timer;

    duid_t serverid;

    /* internal timer parameters */
    struct timeval start_time;
    glong retrans;
    glong init_retrans;
    glong max_retrans_cnt;
    glong max_retrans_time;
    glong max_retrans_dur;
    gint timeouts;               /* number of timeouts */

    guint32 xid;              /* current transaction ID */
    guint32 uuid;             /* unique ID of this event */
    gint state;

    GSList *data_list;
} dhcp6_event_t;

typedef enum {
    DHCP6_DATA_PREFIX,
    DHCP6_DATA_ADDR
} dhcp6_eventdata_type;

typedef struct _dhcp6_eventdata_t {
    dhcp6_event_t *event;
    dhcp6_eventdata_type type;
    void *data;
} dhcp6_eventdata_t;

/* client status code */
enum {
    DHCP6S_INIT,
    DHCP6S_SOLICIT,
    DHCP6S_INFOREQ,
    DHCP6S_REQUEST,
    DHCP6S_RENEW,
    DHCP6S_REBIND,
    DHCP6S_CONFIRM,
    DHCP6S_DECLINE,
    DHCP6S_RELEASE,
    DHCP6S_IDLE
};

struct dhcp6_ifconf {
    struct dhcp6_ifconf *next;

    gchar *ifname;

    /* configuration flags */
    gulong send_flags;
    gulong allow_flags;

    gint server_pref;     /* server preference (server only) */
    guint32 default_irt;  /* default information refresh time (client only) */
    guint32 maximum_irt;  /* maximum information refresh time (client only) */
    dhcp6_iaid_info_t iaidinfo;

    GSList *prefix_list;
    GSList *addr_list;
    GSList *reqopt_list;

    GSList *option_list;
};

typedef struct _prefix_ifconf_t {
    gchar *ifname;               /* interface name such as eth0 */
    gint sla_len;                /* SLA ID length in bits */
    guint32 sla_id;              /* need more than 32bits? */
    gint ifid_len;               /* interface ID length in bits */
    gint ifid_type;              /* EUI-64 and manual (unused?) */
    gchar ifid[16];              /* Interface ID, up to 128bits */
} prefix_ifconf_t;

#define IFID_LEN_DEFAULT 64
#define SLA_LEN_DEFAULT 16

/* per-host configuration */
struct host_conf {
    struct host_conf *next;

    gchar *name;                 /* host name to identify the host */
    duid_t duid;                 /* DUID for the host */
    dhcp6_iaid_info_t iaidinfo;
    struct in6_addr linklocal;
    /* delegated prefixes for the host: */
    GSList *prefix_list;

    /* bindings of delegated prefixes */
    GSList *prefix_binding_list;

    GSList *addr_list;
    GSList *addr_binding_list;
};

/* structures and definitions used in the config file parser */
struct cf_namelist {
    struct cf_namelist *next;
    gchar *name;
    gint line;                   /* the line number of the config file */
    struct cf_list *params;
};

struct cf_list {
    struct cf_list *next;
    struct cf_list *tail;
    gint type;
    gint line;                   /* the line number of the config file */

    /* type dependent values: */
    long long num;
    struct cf_list *list;
    void *ptr;
};

/* Some systems define thes in in.h */
#ifndef IN6_IS_ADDR_UNSPECIFIED
#define IN6_IS_ADDR_UNSPECIFIED(a)           \
    (((__const guint32 *) (a))[0] == 0     \
     && ((__const guint32 *) (a))[1] == 0  \
     && ((__const guint32 *) (a))[2] == 0  \
     && ((__const guint32 *) (a))[3] == 0)
#endif

#ifndef IN6_IS_ADDR_LOOPBACK
#define IN6_IS_ADDR_LOOPBACK(a)                      \
    (((__const guint32 *) (a))[0] == 0             \
     && ((__const guint32 *) (a))[1] == 0          \
     && ((__const guint32 *) (a))[2] == 0          \
     && ((__const guint32 *) (a))[3] == htonl (1))
#endif

#ifndef IN6_IS_ADDR_MULTICAST
#define IN6_IS_ADDR_MULTICAST(a) (((__const guint8 *) (a))[0] == 0xff)
#endif

#ifndef IN6_IS_ADDR_LINKLOCAL
#define IN6_IS_ADDR_LINKLOCAL(a) \
    ((((__const guint32 *) (a))[0] & htonl(0xffc00000)) == htonl(0xfe800000))
#endif

#ifndef IN6_IS_ADDR_SITELOCAL
#define IN6_IS_ADDR_SITELOCAL(a) \
    ((((__const guint32 *) (a))[0] & htonl(0xffc00000)) == htonl(0xfec00000))
#endif

#ifndef IN6_ARE_ADDR_EQUAL
#define IN6_ARE_ADDR_EQUAL(a,b)                                             \
    ((((__const guint32 *) (a))[0] == ((__const guint32 *) (b))[0])     \
     && (((__const guint32 *) (a))[1] == ((__const guint32 *) (b))[1])  \
     && (((__const guint32 *) (a))[2] == ((__const guint32 *) (b))[2])  \
     && (((__const guint32 *) (a))[3] == ((__const guint32 *) (b))[3]))
#endif

#ifndef IN6_IS_ADDR_RESERVED
#define IN6_IS_ADDR_RESERVED(a)                            \
    IN6_IS_ADDR_MULTICAST(a) || IN6_IS_ADDR_LOOPBACK(a) || \
    IN6_IS_ADDR_UNSPECIFIED(a)
#endif

/* ANYCAST later */

enum {
    DECL_SEND,
    DECL_ALLOW,
    DECL_INFO_ONLY,
    DECL_TEMP_ADDR,
    DECL_REQUEST,
    DECL_DUID,
    DECL_PREFIX,
    DECL_PREFERENCE,
    DECL_IAID,
    DECL_RENEWTIME,
    DECL_REBINDTIME,
    DECL_ADDRESS,
    DECL_LINKLOCAL,
    DECL_PREFIX_INFO,
    DECL_PREFIX_REQ,
    DECL_PREFIX_DELEGATION_INTERFACE,
    DECL_DEFAULT_IRT,
    DECL_MAXIMUM_IRT,
    DHCPOPT_PREFIX_DELEGATION,
    IFPARAM_SLA_ID,
    IFPARAM_SLA_LEN,
    DHCPOPT_RAPID_COMMIT,
    DHCPOPT_DNS,
    ADDRESS_LIST_ENT,
    DHCPOPT_DOMAIN_LIST
};

typedef enum {
    DHCP6_MODE_SERVER,
    DHCP6_MODE_CLIENT,
    DHCP6_MODE_RELAYxi
} dhcp6_mode_t;

extern const dhcp6_mode_t dhcp6_mode;
extern struct cf_list *cf_dns_list;
extern const gchar *configfilename;

extern dhcp6_if_t *dhcp6_if;
extern struct dhcp6_ifconf *dhcp6_iflist;
extern prefix_ifconf_t *prefix_ifconflist;
extern dns_info_t dnsinfo;

gint configure_interface(const struct cf_namelist *);
gint configure_prefix_interface(struct cf_namelist *);
gint configure_host(const struct cf_namelist *);
gint configure_global_option(void);
void configure_cleanup(void);
void configure_commit(void);
gint cfparse(const gchar *);
gint resolv_parse(dns_info_t *);

#endif /* __CONFDATA_H_DEFINED */

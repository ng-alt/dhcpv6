/*
 * types.h
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

#ifndef __TYPES_H_DEFINED
#define __TYPES_H_DEFINED

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

    /* timer to check interface off->on link to send confirm message */
    dhcp6_timer_t *link_timer;

    dhcp6_timer_t *dad_timer;

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

typedef struct _dhcp6_ifconf_t {
    struct _dhcp6_ifconf_t *next;

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
} dhcp6_ifconf_t;

typedef struct _prefix_ifconf_t {
    gchar *ifname;               /* interface name such as eth0 */
    gint sla_len;                /* SLA ID length in bits */
    guint32 sla_id;              /* need more than 32bits? */
    gint ifid_len;               /* interface ID length in bits */
    gint ifid_type;              /* EUI-64 and manual (unused?) */
    gchar ifid[16];              /* Interface ID, up to 128bits */
} prefix_ifconf_t;

/* per-host configuration */
typedef struct _host_conf_t {
    struct _host_conf_t *next;

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
} host_conf_t;

/* structures and definitions used in the config file parser */
typedef struct _cf_list_t {
    struct _cf_list_t *next;
    struct _cf_list_t *tail;
    gint type;
    gint line;                   /* the line number of the config file */

    /* type dependent values: */
    long long num;
    struct _cf_list_t *list;
    void *ptr;
} cf_list_t;

typedef struct _cf_namelist_t {
    struct _cf_namelist_t *next;
    gchar *name;
    gint line;                   /* the line number of the config file */
    cf_list_t *params;
} cf_namelist_t;

typedef enum {
    DHCP6_MODE_SERVER,
    DHCP6_MODE_CLIENT,
    DHCP6_MODE_RELAY
} dhcp6_mode_t;

typedef enum {
    IANA = 1,
    IATA,
    IAPD
} iatype_t;

typedef enum {
    ACTIVE = 1,
    RENEW,
    REBIND,
    EXPIRED,
    INVALID
} state_t;

/* Internal data structures */

typedef struct _dhcp6_timer_t {
    struct timeval tm;
    gint flag;

    struct _dhcp6_timer_t *(*expire)(void *);
    void *expire_data;
} dhcp6_timer_t;

typedef struct _intf_id_t {
    guint16 intf_len;           /* length */
    gchar *intf_id;             /* variable length ID value (must be opaque) */
} intf_id_t;

/* iaid info for the IA_NA */
typedef struct _dhcp6_iaid_info_t {
    guint32 iaid;
    guint32 renewtime;
    guint32 rebindtime;
} dhcp6_iaid_info_t;

/* dhcpv6 addr */
typedef struct _dhcp6_addr_t {
    guint32 validlifetime;
    guint32 preferlifetime;
    struct in6_addr addr;
    guint8 plen;
    iatype_t type;
    guint16 status_code;
    gchar *status_msg;
} dhcp6_addr_t;

typedef enum {
    DHCP6_LISTVAL_NUM,
    DHCP6_LISTVAL_ADDR6,
    DHCP6_LISTVAL_DHCP6ADDR,
    DHCP6_LISTVAL_DHCP6LEASE
} dhcp6_listval_type_t;

/* Store the parameters in an IA option */
typedef struct _ia_t {
    iatype_t type;                      /* type of IA (e.g. IANA) */
    guint8 flags;                       /* flags for temp address */
    dhcp6_iaid_info_t iaidinfo;         /* IAID, renewtime and rebindtime */
    GSList *addr_list;                  /* assigned ipv6 address list */
    guint16 status_code;                /* status code */
    gchar *status_msg;                  /* status message */
} ia_t;

/*
 * DNS information structure.  This structure contains two linked lists,
 * one holding server addresses and one holding domain names to add to the
 * resolver search path.
 */
typedef struct _dns_info_t {
    /*
     * singly linked list of DNS server addresses
     * each element is a (struct in6_addr *)
     */
    GSList *servers;

    /*
     * singly linked list of DNS domain names for the resolver
     * each element is a gchar[MAXDNAME]
     */
    GSList *domains;
} dns_info_t;

typedef struct _dhcp6opt_t {
    guint16 dh6opt_type;
    guint16 dh6opt_len;
    /* type-dependent data follows */
} dhcp6opt_t;

/* DHCP6 relay agent base packet format */
typedef struct _dhcp6_relay_t {
    guint8 dh6_msg_type;
    guint8 dh6_hop_count;
    struct in6_addr link_addr;
    struct in6_addr peer_addr;
    /* options follow */
} dhcp6_relay_t;

typedef struct _relay_t {
    dhcp6_relay_t relay;
    intf_id_t *intf_id;

    /* pointer to the Relay Message option in the RELAY-REPL */
    dhcp6opt_t *option;
} relay_t;

typedef struct _dhcp6_optinfo_t {
    duid_t clientID;               /* DUID */
    duid_t serverID;               /* DUID */
    guint16 elapsed_time;
    GSList *ia_list;               /* list of the IAs in a message */
    guint8 flags;                  /* flags for rapid commit, info only */
    guint8 pref;                   /* server preference */
    guint32 irt;                   /* information refresh time */
    struct in6_addr server_addr;
    GSList *reqopt_list;           /* options in option request */
    dns_info_t dnsinfo;            /* DNS server list */
    GSList *relay_list;            /* list of the relays the message
                                      passed through on to the server */
    guint16 status_code;           /* status code */
    gchar *status_msg;             /* status message */
} dhcp6_optinfo_t;

/* DHCP6 base packet format */
typedef struct _dhcp6_t {
    union {
        guint8 m;
        guint32 x;
    } dh6_msgtypexid;
    /* options follow */
} dhcp6_t;

#define dh6_msgtype dh6_msgtypexid.m
#define dh6_xid     dh6_msgtypexid.x
#define DH6_XIDMASK 0x00ffffff

/* Prefix Information */
typedef struct _dhcp6_prefix_info_t {
    guint16 dh6_pi_type;
    guint16 dh6_pi_len;
    guint32 preferlifetime;
    guint32 validlifetime;
    guint8 plen;
    struct in6_addr prefix;
} dhcp6_prefix_info_t;

/* status code info */
typedef struct _dhcp6_status_info_t {
    guint16 dh6_status_type;
    guint16 dh6_status_len;
    guint16 dh6_status_code;
} dhcp6_status_info_t;

/* IPv6 address info */
typedef struct _dhcp6_addr_info_t {
    guint16 dh6_ai_type;
    guint16 dh6_ai_len;
    struct in6_addr addr;
    guint32 preferlifetime;
    guint32 validlifetime;
} dhcp6_addr_info_t;

typedef struct _duid_t {
    guint8 duid_len;            /* length */
    guchar *duid_id;            /* variable length ID value (must be opaque) */
} duid_t;

/* DUID type 1 */
typedef struct _dhcp6_duid_type1_t {
    guint16 dh6duid1_type;
    guint16 dh6duid1_hwtype;
    guint32 dh6duid1_time;
    /* link-layer address follows */
} dhcp6_duid_type1_t;

typedef enum {
    IFADDRCONF_ADD,
    IFADDRCONF_REMOVE
} ifaddrconf_cmd_t;

typedef struct _log_properties {
    gboolean foreground;
    gboolean verbose;
    gboolean debug;
    GLogLevelFlags threshold;
    gchar *progname;
    pid_t pid;
} log_properties_t;

typedef struct _relay_interface_t {
    GSList *sname;
    GSList *ipv6addr;

    gint got_addr;
    gchar *ifname;
    guint32 devindex;
    gchar *link_local;
    gint opaq;
} relay_interface_t;

typedef struct _relay_msg_parser_t {
    gint if_index;
    guint8 msg_type;
    guint8 hop;
    guint8 *buffer;
    guint8 *ptomsg;
    guint8 *pstart, *pointer_start, *hc_pointer;
    guint32 datalength;        /* the length of the DHCPv6 message */
    gint dst_addr_type;
    gchar src_addr[INET6_ADDRSTRLEN];    /* source address from the UDP packet
                                          */
    gchar peer_addr[INET6_ADDRSTRLEN];
    gchar link_addr[INET6_ADDRSTRLEN];
    gint interface_in, hop_count;
    gint sent;
    gint isRF;
} relay_msg_parser_t;

typedef struct _relay_socket_t {
    struct msghdr msg;
    struct iovec iov[1];
    struct cmsghdr *cmsgp;
    struct sockaddr_in6 sin6;   /* my address information */
    struct sockaddr_in6 from;
    gint recvmsglen;
    gchar *recvp;
    gchar src_addr[INET6_ADDRSTRLEN];
    gint pkt_interface;
    gint buflength;
    gint dst_addr_type;
    gchar *databuf;
    gint sock_desc;
} relay_socket_t;

/* provide common paramters within scopes */
typedef struct _scope_t {
    gint32 prefer_life_time;
    gint32 valid_life_time;
    gint32 renew_time;
    gint32 rebind_time;
    gint32 irt;
    gint8 server_pref;
    guint8 send_flags;
    guint8 allow_flags;
    dns_info_t dnsinfo;
} scope_t;

/* interface network declaration */
/* interface declaration is used to inform DHCPv6 server that the links */
/* and pool declared within it are connected to the same network segment */
typedef struct _server_interface_t {
    gchar name[IFNAMSIZ];
    hardware_t hw_address;
    struct in6_addr primary_v6addr;
    struct in6_addr linklocal;
    GSList *linklist;
    GSList *hostlist;
    scope_t ifscope;
    scope_t *group;
} server_interface_t;

/* host declaration provides information about a particular DHCPv6 client */
typedef struct _host_decl_t {
    gchar name[IFNAMSIZ];
    duid_t cid;
    dhcp6_iaid_info_t iaidinfo;
    GSList *addrlist;
    GSList *prefixlist;
    server_interface_t *network;
    scope_t hostscope;
    scope_t *group;
} host_decl_t;

typedef struct _rootgroup_t {
    scope_t scope;
    scope_t *group;
    GSList *iflist;
} rootgroup_t;

typedef struct _v6addr_t {
    struct in6_addr addr;
    guint8 plen;
} v6addr_t;

/* link declaration */
/* link declaration is used to provide the DHCPv6 server with enough   */
/* information to determin whether a particular IPv6 addresses is on the */

/* link */
typedef struct _link_decl_t {
    gchar name[IFNAMSIZ];
    GSList *relaylist;
    GSList *seglist;
    GSList *prefixlist;
    GSList *poollist;
    server_interface_t *network;
    scope_t linkscope;
    scope_t *group;
} link_decl_t;

/* The pool declaration is used to declare an address pool from which IPv6 */
/* address can be allocated, with its own permit to control client access  */
/* and its own scope in which you can declare pool-specific parameter*/
typedef struct _pool_decl_t {
    server_interface_t *network;
    link_decl_t *link;
    scope_t poolscope;
    scope_t *group;
} pool_decl_t;

typedef struct _v6addrseg_t {
    link_decl_t *link;
    pool_decl_t *pool;
    struct in6_addr min;
    struct in6_addr max;
    struct in6_addr free;
    v6addr_t prefix;
    struct lease *active;
    struct lease *expired;
    struct lease *abandoned;
    scope_t parainfo;
} v6addrseg_t;

typedef struct _v6prefix_t {
    link_decl_t *link;
    pool_decl_t *pool;
    v6addr_t prefix;
    scope_t parainfo;
} v6prefix_t;

typedef struct _ifproc_info_t {
    struct _ifproc_info_t *next;
    struct in6_addr addr;
    gchar name[IF_NAMESIZE];
    gint index;
    gint plen;
    gint scope;
    gint flags;
} ifproc_info_t;

typedef enum {
    DHCP6_CONFINFO_PREFIX,
    DHCP6_CONFINFO_ADDRS
} dhcp6_conftype_t;

typedef struct _dhcp6_binding_t {
    dhcp6_conftype_t type;
    duid_t clientid; 
    void *val;

    guint32 duration;
    dhcp6_timer_t *timer;
} dhcp6_binding_t;

typedef struct _relay_forw_data_t {
    relay_msg_parser_t *mesg;
    gboolean hit;
} relay_forw_data_t;

#endif /* __TYPES_H_DEFINED */

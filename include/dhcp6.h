/* ported from KAME: dhcp6.h,v 1.32 2002/07/04 15:03:19 jinmei Exp */

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

/*
 * draft-ietf-dhc-dhcpv6-26
 */

#ifndef __DHCP6_H_DEFINED
#define __DHCP6_H_DEFINED

/* Error Values */
#define DH6ERR_FAILURE      16
#define DH6ERR_AUTHFAIL     17
#define DH6ERR_POORLYFORMED 18
#define DH6ERR_UNAVAIL      19
#define DH6ERR_OPTUNAVAIL   20

/* Message type */
#define DH6_SOLICIT     1
#define DH6_ADVERTISE   2
#define DH6_REQUEST     3
#define DH6_CONFIRM     4
#define DH6_RENEW       5
#define DH6_REBIND      6
#define DH6_REPLY       7
#define DH6_RELEASE     8
#define DH6_DECLINE     9
#define DH6_RECONFIGURE 10
#define DH6_INFORM_REQ  11
#define DH6_RELAY_FORW  12
#define DH6_RELAY_REPL  13

/* Predefined addresses */
#define DH6ADDR_ALLAGENT   "ff02::1:2"
#define DH6ADDR_ALLSERVER  "ff05::1:3"
#define DH6PORT_DOWNSTREAM "546"
#define DH6PORT_UPSTREAM   "547"

/* Protocol constants */

/* timer parameters (msec, unless explicitly commented) */
#define MIN_SOL_DELAY 500
#define MAX_SOL_DELAY 1000
#define SOL_TIMEOUT   1000
#define SOL_MAX_RT    120000
#define INF_TIMEOUT   1000
#define INF_MAX_DELAY 1000
#define INF_MAX_RT    120000
#define REQ_TIMEOUT   1000
#define REQ_MAX_RT    30000
#define REQ_MAX_RC    10       /* Max Request retry attempts */
#define REN_TIMEOUT   10000    /* 10secs */
#define REN_MAX_RT    600000   /* 600secs */
#define REB_TIMEOUT   10000    /* 10secs */
#define REB_MAX_RT    600000   /* 600secs */
#define DEC_TIMEOUT   1000
#define DEC_MAX_RC    5
#define REL_TIMEOUT   1000
#define REL_MAX_RC    5
#define REC_TIMEOUT   2000
#define REC_MAX_RC    8
#define CNF_TIMEOUT   1000
#define CNF_MAX_RD    10
#define CNF_MAX_RT    4000

#define DHCP6_DURATITION_INFINITE 0xffffffff
#define DHCP6_ELAPSEDTIME_MAX     0xffff

#define IF_RA_OTHERCONF 0x80
#define IF_RA_MANAGED   0x40
#define RTM_F_PREFIX    0x800

#ifndef MAXDNAME
#define MAXDNAME 255
#endif
#define MAXDN 100

#define SIGF_TERM 0x1
#define SIGF_HUP 0x2
#define SIGF_CLEAN 0x4

#define DHCP6S_VALID_REPLY(a)                      \
    (a == DHCP6S_REQUEST || a == DHCP6S_RENEW ||   \
     a == DHCP6S_REBIND || a == DHCP6S_DECLINE ||  \
     a == DHCP6S_RELEASE || a == DHCP6S_CONFIRM || \
     a == DHCP6S_INFOREQ)

#define CLIENT6_RELEASE_ADDR 0x1
#define CLIENT6_CONFIRM_ADDR 0x2
#define CLIENT6_REQUEST_ADDR 0x4
#define CLIENT6_DECLINE_ADDR 0x8
#define CLIENT6_INFO_REQ     0x10

/* Default file paths (can be overridden with command line options) */
#define DHCP6C_PIDFILE PID_FILE_PATH"/dhcp6c.pid"
#define DHCP6C_DUID_FILE DB_FILE_PATH"/dhcp6c_duid"

/* Resolver configuration file (almost always /etc/resolv.conf) */
#define RESOLV_CONF_DHCPV6_FILE DB_FILE_PATH"/resolv.conf.dhcpv6"
#define RESOLV_CONF_BAK_FILE RESOLV_CONF_DHCPV6_FILE".bak"

char resolv_dhcpv6_file[PATH_MAX];

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

/* Internal data structure */

struct intf_id {
    guint16 intf_len;           /* length */
    gchar *intf_id;             /* variable length ID value (must be opaque) */
};

/* iaid info for the IA_NA */
struct dhcp6_iaid_info {
    guint32 iaid;
    guint32 renewtime;
    guint32 rebindtime;
};

/* dhcpv6 addr */
struct dhcp6_addr {
    guint32 validlifetime;
    guint32 preferlifetime;
    struct in6_addr addr;
    guint8 plen;
    iatype_t type;
    guint16 status_code;
    gchar *status_msg;
};

struct client6_if {
    iatype_t type;
    struct dhcp6_iaid_info iaidinfo;
    struct duid clientid;
    struct duid serverid;
};

typedef struct _dhcp6_iaidaddr_t {
    struct client6_if client6_info;
    time_t start_date;
    state_t state;
    struct dhcp6_if *ifp;
    struct dhcp6_timer *timer;
    /* list of client leases */
    GSList *lease_list;
} dhcp6_iaidaddr_t;

typedef struct _dhcp6_lease_t {
    gchar hostname[1024];
    struct in6_addr linklocal;
    struct dhcp6_addr lease_addr;
    iatype_t addr_type;
    state_t state;
    dhcp6_iaidaddr_t *iaidaddr;
    time_t start_date;
    /* address assigned on the interface */
    struct dhcp6_timer *timer;
} dhcp6_lease_t;

typedef struct _dhcp6_value_t {
    union {
        gint uv_num;
        struct in6_addr uv_addr6;
        struct dhcp6_addr uv_dhcp6_addr;
        dhcp6_lease_t uv_dhcp6_lease;
    } uv;
} dhcp6_value_t;

#define val_num uv.uv_num
#define val_addr6 uv.uv_addr6
#define val_dhcp6addr uv.uv_dhcp6_addr
#define val_dhcp6lease uv.uv_dhcp6_lease

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
    struct dhcp6_iaid_info iaidinfo;    /* IAID, renewtime and rebindtime */
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

/* DHCP6 relay agent base packet format */
struct dhcp6_relay {
    guint8 dh6_msg_type;
    guint8 dh6_hop_count;
    struct in6_addr link_addr;
    struct in6_addr peer_addr;
    /* options follow */
};

typedef struct _relay_t {
    struct dhcp6_relay relay;
    struct intf_id *intf_id;

    /* pointer to the Relay Message option in the RELAY-REPL */
    struct dhcp6opt *option;
} relay_t;

struct dhcp6_optinfo {
    struct duid clientID;          /* DUID */
    struct duid serverID;          /* DUID */
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
};

/* DHCP6 base packet format */
struct dhcp6 {
    union {
        guint8 m;
        guint32 x;
    } dh6_msgtypexid;
    /* options follow */
};

#define dh6_msgtype dh6_msgtypexid.m
#define dh6_xid     dh6_msgtypexid.x
#define DH6_XIDMASK 0x00ffffff

/* options */
#define DH6OPT_PREF_UNDEF        0
#define DH6OPT_CLIENTID          1
#define DH6OPT_SERVERID          2
#define DH6OPT_IA_NA             3
#define DH6OPT_IA_TA             4
#define DH6OPT_IADDR             5
#define DH6OPT_ORO               6
#define DH6OPT_PREFERENCE        7
#define DH6OPT_ELAPSED_TIME      8
#define DH6OPT_RELAY_MSG         9
#define DH6OPT_AUTH              11
#define DH6OPT_UNICAST           12
#define DH6OPT_STATUS_CODE       13
#define DH6OPT_RAPID_COMMIT      14
#define DH6OPT_USER_CLASS        15
#define DH6OPT_VENDOR_CLASS      16
#define DH6OPT_VENDOR_OPTS       17
#define DH6OPT_INTERFACE_ID      18
#define DH6OPT_RECONF_MSG        19
#define DH6OPT_RECONF_ACCEPT     20
#define DH6OPT_DNS_SERVERS       23
#define DH6OPT_DOMAIN_LIST       24
#define DH6OPT_IA_PD             25
#define DH6OPT_IAPREFIX          26
#define DH6OPT_INFO_REFRESH_TIME 32
#define DH6OPT_PREF_MAX          255

#define DH6OPT_STCODE_UNDEFINE      0xffff
#define DH6OPT_STCODE_SUCCESS       0
#define DH6OPT_STCODE_UNSPECFAIL    1
#define DH6OPT_STCODE_NOADDRAVAIL   2
#define DH6OPT_STCODE_NOBINDING     3
#define DH6OPT_STCODE_NOTONLINK     4
#define DH6OPT_STCODE_USEMULTICAST  5
#define DH6OPT_STCODE_AUTHFAILED    6
#define DH6OPT_STCODE_ADDRUNAVAIL   7
#define DH6OPT_STCODE_CONFNOMATCH   8
#define DH6OPT_STCODE_NOPREFIXAVAIL 10

#define DEFAULT_VALID_LIFE_TIME 720000
#define DEFAULT_PREFERRED_LIFE_TIME 360000

#define IRT_DEFAULT 86400     /* default refresh time [sec] */
#define IRT_MINIMUM 600       /* minimum value for the refresh time [sec] */

/* environment variable names for run_script() */
#define _ENV_VAR_PREFIX   "dhcpv6_"
#define OLD_STATE         _ENV_VAR_PREFIX"old_state"
#define NEW_STATE         _ENV_VAR_PREFIX"new_state"
#define IFACE_NAME        _ENV_VAR_PREFIX"iface_name"
#define IFACE_INDEX       _ENV_VAR_PREFIX"iface_index"
#define LINKLOCAL_ADDR    _ENV_VAR_PREFIX"linklocal_address"
#define REQUESTED_OPTIONS _ENV_VAR_PREFIX"requested_options"
#define ADDRESS_LIST      _ENV_VAR_PREFIX"address_list"
#define PREFIX_LIST       _ENV_VAR_PREFIX"prefix_list"
#define OPTIONS           _ENV_VAR_PREFIX"options"

struct dhcp6opt {
    guint16 dh6opt_type;
    guint16 dh6opt_len;
    /* type-dependent data follows */
};

/* Prefix Information */
struct dhcp6_prefix_info {
    guint16 dh6_pi_type;
    guint16 dh6_pi_len;
    guint32 preferlifetime;
    guint32 validlifetime;
    guint8 plen;
    struct in6_addr prefix;
};

/* status code info */
struct dhcp6_status_info {
    guint16 dh6_status_type;
    guint16 dh6_status_len;
    guint16 dh6_status_code;
};

/* IPv6 address info */
struct dhcp6_addr_info {
    guint16 dh6_ai_type;
    guint16 dh6_ai_len;
    struct in6_addr addr;
    guint32 preferlifetime;
    guint32 validlifetime;
};

#endif /* __DHCP6_H_DEFINED */

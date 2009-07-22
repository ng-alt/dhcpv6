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

#include "queue.h"
#include <sys/param.h>

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

char resolv_dhcpv6_file[MAXPATHLEN];

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

struct duid {
    u_int8_t duid_len;          /* length */
    unsigned char *duid_id;     /* variable length ID value (must be opaque) */
};

struct intf_id {
    u_int16_t intf_len;         /* length */
    char *intf_id;              /* variable length ID value (must be opaque) */
};

/* iaid info for the IA_NA */
struct dhcp6_iaid_info {
    u_int32_t iaid;
    u_int32_t renewtime;
    u_int32_t rebindtime;
};

/* dhcpv6 addr */
struct dhcp6_addr {
    u_int32_t validlifetime;
    u_int32_t preferlifetime;
    struct in6_addr addr;
    u_int8_t plen;
    iatype_t type;
    u_int16_t status_code;
    char *status_msg;
};

struct dhcp6_lease {
    TAILQ_ENTRY(dhcp6_lease) link;
    char hostname[1024];
    struct in6_addr linklocal;
    struct dhcp6_addr lease_addr;
    iatype_t addr_type;
    state_t state;
    struct dhcp6_iaidaddr *iaidaddr;
    time_t start_date;
    /* address assigned on the interface */
    struct dhcp6_timer *timer;
};

struct dhcp6_listval {
    TAILQ_ENTRY(dhcp6_listval) link;

    union {
        int uv_num;
        struct in6_addr uv_addr6;
        struct dhcp6_addr uv_dhcp6_addr;
        struct dhcp6_lease uv_dhcp6_lease;
    } uv;
};

#define val_num uv.uv_num
#define val_addr6 uv.uv_addr6
#define val_dhcp6addr uv.uv_dhcp6_addr
#define val_dhcp6lease uv.uv_dhcp6_lease

TAILQ_HEAD(dhcp6_list, dhcp6_listval);

typedef enum {
    DHCP6_LISTVAL_NUM,
    DHCP6_LISTVAL_ADDR6,
    DHCP6_LISTVAL_DHCP6ADDR,
    DHCP6_LISTVAL_DHCP6LEASE
} dhcp6_listval_type_t;

/* Store the parameters in an IA option */
struct ia_listval {
    TAILQ_ENTRY(ia_listval) link;

    iatype_t type;                      /* type of IA (e.g. IANA) */
    u_int8_t flags;                     /* flags for temp address */
    struct dhcp6_iaid_info iaidinfo;    /* IAID, renewtime and rebindtime */
    struct dhcp6_list addr_list;        /* assigned ipv6 address list */
    u_int16_t status_code;              /* status code */
    char *status_msg;                   /* status message */
};

TAILQ_HEAD(ia_list, ia_listval);

struct domain_list {
    struct domain_list *next;
    char name[MAXDNAME];
};

struct dns_list {
    struct dhcp6_list addrlist;
    struct domain_list *domainlist;
};

/* DHCP6 relay agent base packet format */
struct dhcp6_relay {
    u_int8_t dh6_msg_type;
    u_int8_t dh6_hop_count;
    struct in6_addr link_addr;
    struct in6_addr peer_addr;
    /* options follow */
};

struct relay_listval {
    TAILQ_ENTRY(relay_listval) link;

    struct dhcp6_relay relay;
    struct intf_id *intf_id;

    /* pointer to the Relay Message option in the RELAY-REPL */
    struct dhcp6opt *option;
};

TAILQ_HEAD(relay_list, relay_listval);

struct dhcp6_optinfo {
    struct duid clientID;          /* DUID */
    struct duid serverID;          /* DUID */
    u_int16_t elapsed_time;
    struct ia_list ia_list;        /* list of the IAs in a message */
    u_int8_t flags;                /* flags for rapid commit, info only */
    u_int8_t pref;                 /* server preference */
    u_int32_t irt;                 /* information refresh time */
    struct in6_addr server_addr;
    struct dhcp6_list reqopt_list; /* options in option request */
    struct dns_list dns_list;      /* DNS server list */
    struct relay_list relay_list;  /* list of the relays the message
                                      passed through on to the server */
    u_int16_t status_code;         /* status code */
    char *status_msg;              /* status message */
};

/* DHCP6 base packet format */
struct dhcp6 {
    union {
        u_int8_t m;
        u_int32_t x;
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
    u_int16_t dh6opt_type;
    u_int16_t dh6opt_len;
    /* type-dependent data follows */
};

/* DUID type 1 */
struct dhcp6_duid_type1 {
    u_int16_t dh6duid1_type;
    u_int16_t dh6duid1_hwtype;
    u_int32_t dh6duid1_time;
    /* link-layer address follows */
};

/* Prefix Information */
struct dhcp6_prefix_info {
    u_int16_t dh6_pi_type;
    u_int16_t dh6_pi_len;
    u_int32_t preferlifetime;
    u_int32_t validlifetime;
    u_int8_t plen;
    struct in6_addr prefix;
};

/* status code info */
struct dhcp6_status_info {
    u_int16_t dh6_status_type;
    u_int16_t dh6_status_len;
    u_int16_t dh6_status_code;
};

/* IPv6 address info */
struct dhcp6_addr_info {
    u_int16_t dh6_ai_type;
    u_int16_t dh6_ai_len;
    struct in6_addr addr;
    u_int32_t preferlifetime;
    u_int32_t validlifetime;

/* u_int8_t plen;
 * struct dhcp6_status_info status;
 */
};

#endif /*__DHCP6_H_DEFINED*/

/*
 * constants.h
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

#ifndef __CONSTANTS_H_DEFINED
#define __CONSTANTS_H_DEFINED

#define MAX_DEVICE 100

#define DHCP6_SYNCFILE_TIME 60
#define DHCP6_CHECKLINK_TIME_UPCASE 5
#define DHCP6_CHECKLINK_TIME_DOWNCASE 1
#define DHCP6_CHECKDAD_TIME 5

#define DHCIFF_INFO_ONLY 0x1
#define DHCIFF_RAPID_COMMIT 0x2
#define DHCIFF_TEMP_ADDRS 0x4
#define DHCIFF_PREFIX_DELEGATION 0x8
#define DHCIFF_UNICAST 0x10

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

/* Predefined addresses, ports, and services*/
#define DH6ADDR_ALLAGENT           "ff02::1:2"      /* relays & servers */
#define DH6ADDR_ALLSERVER          "ff05::1:3"      /* all servers */
#define DH6PORT_DOWNSTREAM_PORT    546
#define DH6PORT_DOWNSTREAM_SERVICE "dhcpv6-client"
#define DH6PORT_UPSTREAM_PORT      547
#define DH6PORT_UPSTREAM_SERVICE   "dhcpv6-server"

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

#define CLIENT6_RELEASE_ADDR 0x1
#define CLIENT6_CONFIRM_ADDR 0x2
#define CLIENT6_REQUEST_ADDR 0x4
#define CLIENT6_DECLINE_ADDR 0x8
#define CLIENT6_INFO_REQ     0x10

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

#define FIRST_DH6OPT             1
#define LAST_DH6OPT              32

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
#define STATUS_CODE       _ENV_VAR_PREFIX"status_code"
#define STATUS_MSG        _ENV_VAR_PREFIX"status_msg"
#define UUID              _ENV_VAR_PREFIX"uuid"

#define MAX_DHCP_MSG_LENGTH        1400
#define MESSAGE_HEADER_LENGTH      4
#define OPAQ                       5000    // opaq value for interface id
#define HEAD_SIZE                  400
#define HOP_COUNT_LIMIT            30
#define MAXHOPCOUNT                32

#define ADDR_UPDATE   0
#define ADDR_REMOVE   1
#define ADDR_VALIDATE 2
#define ADDR_ABANDON  3

#define PREFIX_LEN_NOTINRA 64
#define MAX_FILE_SIZE 512*1024

#define MARK_CLEAR 0x00
#define MARK_REMOVE 0x01

enum {
    DHCPOPTCODE_SEND,
    DHCPOPTCODE_REQUEST,
    DHCPOPTCODE_ALLOW
};

#define DAD_FLAGS 0xC0

#ifndef IPV6_2292PKTINFO
#define IPV6_2292PKTINFO IPV6_PKTINFO
#endif

#define LEASE_ADDR_FLAG 0x01
#define LEASE_DUID_FLAG 0x02
#define LEASE_IAID_FLAG 0x04
#define LEASE_SDATE_FLAG 0x08

#define LEASE_VTIME_FLAG 0x10
#define LEASE_PTIME_FLAG 0x20
#define LEASE_RNTIME_FLAG 0x40
#define LEASE_RBTIME_FLAG 0x80

#define LEASE_HNAME_FLAG 0x100
#define LEASE_LL_FLAG 0x200

/* Paths */
#define INTERFACEINFO "/proc/net/if_inet6"

#define DHCP6C_PIDFILE PID_FILE_PATH"/dhcp6c.pid"
#define DHCP6C_DUID_FILE DB_FILE_PATH"/dhcp6c_duid"

#define RESOLV_CONF_DHCPV6_FILE DB_FILE_PATH"/resolv.conf.dhcpv6"
#define RESOLV_CONF_BAK_FILE RESOLV_CONF_DHCPV6_FILE".bak"

#define PATH_SERVER6_LEASE DB_FILE_PATH"/server6.leases"
#define PATH_CLIENT6_LEASE DB_FILE_PATH"/client6.leases"

#define DHCP6R_PIDFILE PID_FILE_PATH"/dhcp6r.pid"

#define DHCP6S_DUID_FILE DB_FILE_PATH"/dhcp6s_duid"
#define DHCP6S_PIDFILE PID_FILE_PATH"/dhcp6s.pid"

#endif /* __CONSTANTS_H_DEFINED */

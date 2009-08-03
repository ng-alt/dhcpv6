/* ported from KAME: cfparse.y,v 1.16 2002/09/24 14:20:49 itojun Exp */

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

%{
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# include <time.h>
#endif

#include <glib.h>

#include "types.h"

extern gint client6lex (void);

extern gint lineno;
extern gint cfdebug;

extern void cpyywarn(gchar *, ...) __attribute__((__format__(__printf__, 1, 2)));
extern void client6error(gchar *, ...) __attribute__((__format__(__printf__, 1, 2)));

#define MAKE_NAMELIST(l, n, p) \
    do { \
        (l) = (cf_namelist_t *) g_malloc0(sizeof(*(l))); \
        if ((l) == NULL) { \
            cpyywarn("can't allocate memory"); \
            if (p) \
                cleanup_cflist(p); \
            return (-1); \
        } \
        l->line = lineno; \
        l->name = (n); \
        l->params = (p); \
    } while (0)

#define MAKE_CFLIST(l, t, pp, pl) \
    do { \
        (l) = (cf_list_t *) g_malloc0(sizeof(*(l))); \
        if ((l) == NULL) { \
            cpyywarn("can't allocate memory"); \
            if ((pp)) { \
                g_free((pp)); \
            } \
            if ((pl)) \
                cleanup_cflist((pl)); \
            return (-1); \
        } \
        l->line = lineno; \
        l->type = (t); \
        l->ptr = (pp); \
        l->list = (pl); \
    } while (0)

static cf_namelist_t *iflist_head;
cf_list_t *cf_dns_list;

extern gint cpyylex(void);
static void cleanup(void);
static gint add_namelist(cf_namelist_t *, cf_namelist_t **);
static void cleanup_namelist(cf_namelist_t *);
static void cleanup_cflist(cf_list_t *);
%}

%token INTERFACE IFNAME IPV6ADDR REQUEST SEND RAPID_COMMIT PREFIX_DELEGATION
%token DNS_SERVERS DOMAIN_LIST INFO_ONLY TEMP_ADDR ADDRESS PREFIX IAID
%token RENEW_TIME REBIND_TIME V_TIME P_TIME PREFIX_DELEGATION_INTERFACE
%token DEFAULT_IRT MAXIMUM_IRT NUMBER SLASH EOS BCL ECL STRING INFINITY COMMA
%token OPTION

%union {
    long long num;
    gchar* str;
    cf_list_t *list;
    struct in6_addr addr;
    dhcp6_addr_t *v6addr;
}

%type <str> IFNAME STRING
%type <num> NUMBER duration addrvtime addrptime
%type <list> declaration declarations dhcpoption 
%type <v6addr> addrparam addrdecl
%type <addr> IPV6ADDR

%%
statements
    : /* empty */
    | statements statement
    ;

statement
    : interface_statement
    ;

interface_statement
    : INTERFACE IFNAME BCL declarations ECL EOS {
          cf_namelist_t *ifl;

          MAKE_NAMELIST(ifl, $2, $4);

          if (add_namelist(ifl, &iflist_head))
              return (-1);
      }
    ;

declarations
    : { $$ = NULL; }
    | declarations declaration {
          cf_list_t *head;

          if ((head = $1) == NULL) {
              $2->next = NULL;
              $2->tail = $2;
              head = $2;
          } else {
              head->tail->next = $2;
              head->tail = $2;
          }

          $$ = head;
      }
    ;

declaration
    : SEND dhcpoption EOS {
          cf_list_t *l;

          MAKE_CFLIST(l, DECL_SEND, NULL, $2);

          $$ = l;
      }
    | REQUEST dhcpoption EOS {
          cf_list_t *l;

          MAKE_CFLIST(l, DECL_REQUEST, NULL, $2);

          $$ = l;
      }
    | INFO_ONLY EOS {
          cf_list_t *l;

          MAKE_CFLIST(l, DECL_INFO_ONLY, NULL, NULL);
          /* no value */
          $$ = l;
      }
    | DEFAULT_IRT duration EOS {
          cf_list_t *l;

          MAKE_CFLIST(l, DECL_DEFAULT_IRT, NULL, NULL);
          l->num = $2;

          $$ = l;
      }
    | MAXIMUM_IRT duration EOS {
          cf_list_t *l;

          MAKE_CFLIST(l, DECL_MAXIMUM_IRT, NULL, NULL);
          l->num = $2;

          $$ = l;
      }
    | REQUEST TEMP_ADDR EOS {
          cf_list_t *l;

          MAKE_CFLIST(l, DECL_TEMP_ADDR, NULL, NULL);
          /* no value */
          $$ = l;
      }
    | ADDRESS BCL addrdecl ECL EOS {
          cf_list_t *l;

          MAKE_CFLIST(l, DECL_ADDRESS, $3, NULL);

          $$ = l;
      }
    | PREFIX BCL addrdecl ECL EOS {
          cf_list_t *l;

          MAKE_CFLIST(l, DECL_PREFIX, $3, NULL);

          $$ = l;
      }
    | RENEW_TIME duration EOS {
          cf_list_t *l;

          MAKE_CFLIST(l, DECL_RENEWTIME, NULL, NULL);
          l->num = $2;

          $$ = l;

      }
    | REBIND_TIME duration EOS {
          cf_list_t *l;

          MAKE_CFLIST(l, DECL_REBINDTIME, NULL, NULL);
          l->num = $2;

          $$ = l;
      }
    | IAID NUMBER EOS {
          cf_list_t *l;

          MAKE_CFLIST(l, DECL_IAID, NULL, NULL);
          l->num = $2;

          $$ = l;
      }
    ;

dhcpoption
    : RAPID_COMMIT {
          cf_list_t *l;

          MAKE_CFLIST(l, DHCPOPT_RAPID_COMMIT, NULL, NULL);
          /* no value */
          $$ = l;
      }
    | PREFIX_DELEGATION {
          cf_list_t *l;

          MAKE_CFLIST(l, DHCPOPT_PREFIX_DELEGATION, NULL, NULL);
          /* currently no value */
          $$ = l;
      }
    | DNS_SERVERS {
          cf_list_t *l;

          MAKE_CFLIST(l, DHCPOPT_DNS, NULL, NULL);
          /* currently no value */
          $$ = l;
      }
    | DOMAIN_LIST {
          cf_list_t *l;

          MAKE_CFLIST(l, DHCPOPT_DOMAIN_LIST, NULL, NULL);
          /* currently no value */
          $$ = l;
      }
    ;

addrdecl
    : addrparam addrvtime {
          dhcp6_addr_t *addr = (dhcp6_addr_t *) $1;

          addr->validlifetime = (u_int32_t) $2;
          $$ = $1;
      }
    | addrparam addrptime {
          dhcp6_addr_t *addr = (dhcp6_addr_t *) $1;
          addr->preferlifetime = (u_int32_t) $2;
          $$ = $1;
      }
    | addrparam addrvtime addrptime {
          dhcp6_addr_t *addr = (dhcp6_addr_t *) $1;
          addr->validlifetime = (u_int32_t) $2;
          addr->preferlifetime = (u_int32_t) $3;
          $$ = $1;
      }
    | addrparam addrptime addrvtime {
          dhcp6_addr_t *addr = (dhcp6_addr_t *) $1;
          addr->validlifetime = (u_int32_t) $3;
          addr->preferlifetime = (u_int32_t) $2;
          $$ = $1;
      }
    | addrparam {
          $$ = $1;
      }
    ;

addrparam
    : IPV6ADDR SLASH NUMBER EOS {
          dhcp6_addr_t *v6addr = NULL;

          /* validate other parameters later */
          if ($3 < 0 || $3 > 128)
              return (-1);

          if ((v6addr = g_malloc0(sizeof(*v6addr))) == NULL) {
              cpyywarn("can't allocate memory");
              return (-1);
          }

          memcpy(&v6addr->addr, &$1, sizeof(v6addr->addr));
          v6addr->plen = $3;
          $$ = v6addr;
      }
    ;

addrvtime
    : V_TIME duration EOS {
          $$ = $2;
      }
    ;

addrptime
    : P_TIME duration EOS {
          $$ = $2;
      }
    ;

duration
    : INFINITY {
          $$ = -1;
      }
    | NUMBER {
          $$ = $1;
      }
    ;

%%

/* supplement routines for configuration */
static gint add_namelist(cf_namelist_t *new, cf_namelist_t **headp) {
    cf_namelist_t *ifp;

    /* check for duplicated configuration */
    for (ifp = *headp; ifp; ifp = ifp->next) {
        if (g_strcmp0(ifp->name, new->name) == 0) {
            cpyywarn("duplicated interface: %s (ignored)", new->name);
            cleanup_namelist(new);
            return (0);
        }
    }

    new->next = *headp;
    *headp = new;

    return (0);
}

/* free temporary resources */
static void cleanup(void) {
    cleanup_namelist(iflist_head);
}

static void cleanup_namelist(cf_namelist_t *head) {
    cf_namelist_t *ifp, *ifp_next;

    for (ifp = head; ifp; ifp = ifp_next) {
        ifp_next = ifp->next;
        cleanup_cflist(ifp->params);

        g_free(ifp->name);
        ifp->name = NULL;

        g_free(ifp);
        ifp = NULL;
    }

    return;
}

static void cleanup_cflist(cf_list_t *p) {
    cf_list_t *n;

    if (p == NULL) {
        return;
    }

    n = p->next;

    if (p->ptr) {
        g_free(p->ptr);
        p->ptr = NULL;
    }

    if (p->list) {
        cleanup_cflist(p->list);
    }

    g_free(p);
    p = NULL;

    cleanup_cflist(n);
}

#define config_fail() \
    do { \
        cleanup(); \
        configure_cleanup(); \
        return (-1); \
    } while(0)

gint cf_post_config(void) {
    if (configure_interface(iflist_head))
        config_fail();

    if (configure_global_option())
        config_fail();

    configure_commit();
    cleanup();
    return (0);
}
#undef config_fail

void cf_init(void) {
    iflist_head = NULL;
}

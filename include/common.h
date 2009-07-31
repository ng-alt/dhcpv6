/* ported from KAME: common.h,v 1.29 2002/06/11 08:24:34 jinmei Exp */

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

#ifndef COMMON_H_DEFINED

#define COMMON_H_DEFINED 1

#define IN6_IFF_INVALID -1

#define DPRINT_STATUS_CODE(object, num, optp, optlen) \
do { \
    g_message("status code of this %s is: %d - %s", \
              (object), (num), dhcp6_stcodestr((num))); \
    if ((optp) != NULL && (optlen) > sizeof(guint16)) { \
        g_message("status message of this %s is: %-*s", \
                  (object), \
                  (optlen) - (gint) sizeof(guint16), \
                  (gchar *) (optp) + sizeof(guint16)); \
    } \
} while (0)

#define COPY_OPTION(t, l, v, p) do { \
    if ((void *)(ep) - (void *)(p) < (l) + sizeof(dhcp6opt_t)) { \
        g_message("%s: option buffer short for %s", \
                  __func__, dhcp6optstr((t))); \
        goto fail; \
    } \
    opth.dh6opt_type = htons((t)); \
    opth.dh6opt_len = htons((l)); \
    memcpy((p), &opth, sizeof(opth)); \
    if ((l)) \
        memcpy((p) + 1, (v), (l)); \
    (p) = (dhcp6opt_t *)((gchar *)((p) + 1) + (l)); \
    (len) += sizeof(dhcp6opt_t) + (l); \
    g_debug("%s: set %s", __func__, dhcp6optstr((t))); \
} while (0)

/* common.c */
gint dhcp6_copy_list(GSList *, const GSList *);
dhcp6_value_t *dhcp6_find_listval(GSList *, void *, dhcp6_listval_type_t);
dhcp6_value_t *dhcp6_add_listval(GSList *, void *, dhcp6_listval_type_t);
ia_t *ia_create_listval();
void ia_clear_list(GSList *);
gint ia_copy_list(GSList *, GSList *);
ia_t *ia_find_listval(GSList *, iatype_t, guint32);
dhcp6_event_t *dhcp6_create_event(struct dhcp6_if *, gint);
void dhcp6_remove_event(gpointer, gpointer);
gint getifaddr(struct in6_addr *, gchar *, struct in6_addr *, gint, gint, gint);
gint transmit_sa(gint, struct sockaddr_in6 *, gchar *, size_t);
glong random_between(glong, glong);
gint prefix6_mask(struct in6_addr *, gint);
gint sa6_plen2mask(struct sockaddr_in6 *, gint);
const gchar *getdev(struct sockaddr_in6 *);
gint in6_addrscopebyif(struct in6_addr *, gchar *);
gint in6_scope(struct in6_addr *);
void dhcp6_init_options(dhcp6_optinfo_t *);
void dhcp6_clear_options(dhcp6_optinfo_t *);
gint dhcp6_copy_options(dhcp6_optinfo_t *, dhcp6_optinfo_t *);
gint dhcp6_get_options(dhcp6opt_t *, dhcp6opt_t *, dhcp6_optinfo_t *);
gint dhcp6_set_options(dhcp6opt_t *, dhcp6opt_t *, dhcp6_optinfo_t *);
void dhcp6_set_timeoparam(dhcp6_event_t *);
void dhcp6_reset_timer(dhcp6_event_t *);
void ifinit(const gchar *);
struct dhcp6_if *find_ifconfbyname(const gchar *);
struct dhcp6_if *find_ifconfbyid(guint);
prefix_ifconf_t *find_prefixifconf(const gchar *);
struct host_conf *find_hostconf(const duid_t *);

#endif

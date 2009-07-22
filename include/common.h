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

#define IN6_IFF_INVALID -1

/* ANSI __func__ can not be concatantated (C99 std) */
#if defined (HAVE_GCC_FUNCTION)
#define FNAME __FUNCTION__ ":"
#else
#define FNAME ""
#endif

#define DPRINT_STATUS_CODE(object, num, optp, optlen) \
do { \
    dhcpv6_dprintf(LOG_INFO, \
                   "status code of this %s is: %d - %s", \
                   (object), (num), dhcp6_stcodestr((num))); \
    if ((optp) != NULL && (optlen) > sizeof(u_int16_t)) { \
        dhcpv6_dprintf(LOG_INFO, \
                       "status message of this %s is: %-*s", \
                       (object), \
                       (optlen) - (int) sizeof(u_int16_t), \
                       (char *) (optp) + sizeof(u_int16_t)); \
    } \
} while (0)

#define COPY_OPTION(t, l, v, p) do { \
    if ((void *)(ep) - (void *)(p) < (l) + sizeof(struct dhcp6opt)) { \
        dhcpv6_dprintf(LOG_INFO, "%s" "option buffer short for %s", \
                       FNAME, dhcp6optstr((t))); \
        goto fail; \
    } \
    opth.dh6opt_type = htons((t)); \
    opth.dh6opt_len = htons((l)); \
    memcpy((p), &opth, sizeof(opth)); \
    if ((l)) \
        memcpy((p) + 1, (v), (l)); \
    (p) = (struct dhcp6opt *)((char *)((p) + 1) + (l)); \
    (len) += sizeof(struct dhcp6opt) + (l); \
    dhcpv6_dprintf(LOG_DEBUG, "%s" "set %s", FNAME, dhcp6optstr((t))); \
} while (0)

extern gint foreground;
extern gint debug_thresh;

/* common.c */
extern gint dhcp6_copy_list(struct dhcp6_list *, const struct dhcp6_list *);
extern void dhcp6_clear_list(struct dhcp6_list *);
extern gint dhcp6_count_list(struct dhcp6_list *);
extern struct dhcp6_listval *dhcp6_find_listval(struct dhcp6_list *, void *,
                                                dhcp6_listval_type_t);
extern struct dhcp6_listval *dhcp6_add_listval(struct dhcp6_list *, void *,
                                               dhcp6_listval_type_t);
extern struct ia_listval *ia_create_listval();
extern void ia_clear_list(struct ia_list *);
extern gint ia_copy_list(struct ia_list *, struct ia_list *);
extern struct ia_listval *ia_find_listval(struct ia_list *,
                                          iatype_t, guint32);
extern void run_script (struct dhcp6_if *, gint, gint, guint32);
extern struct dhcp6_event *dhcp6_create_event(struct dhcp6_if *, gint);
extern void dhcp6_remove_event(struct dhcp6_event *);
extern gint dhcp6_has_option(struct dhcp6_list * optlist, gint option);
extern gint getifaddr(struct in6_addr *, gchar *, struct in6_addr *,
                      gint, gint, gint);
extern gint transmit_sa(gint, struct sockaddr_in6 *, gchar *, size_t);
extern glong random_between(glong, glong);
extern gint prefix6_mask(struct in6_addr *, gint);
extern gint sa6_plen2mask(struct sockaddr_in6 *, gint);
extern gchar *addr2str(struct sockaddr *, socklen_t);
extern gchar *in6addr2str(struct in6_addr *, gint);
extern const gchar *getdev(struct sockaddr_in6 *);
extern gint in6_addrscopebyif(struct in6_addr *, gchar *);
extern gint in6_scope(struct in6_addr *);
extern void setloglevel(gint);
extern void dhcpv6_dprintf(gint, const char *, ...);
extern gint duid_match_llt(struct duid *, struct duid *);
extern gint get_duid(const gchar *, const gchar *, struct duid *);
extern gint save_duid(const gchar *, const gchar *, struct duid *);
extern guint16 calculate_duid_len(const gchar *, guint16 *);
extern void dhcp6_init_options(struct dhcp6_optinfo *);
extern void dhcp6_clear_options(struct dhcp6_optinfo *);
extern gint dhcp6_copy_options(struct dhcp6_optinfo *, struct dhcp6_optinfo *);
extern gint dhcp6_get_options(struct dhcp6opt *, struct dhcp6opt *,
                              struct dhcp6_optinfo *);
extern gint dhcp6_set_options(struct dhcp6opt *, struct dhcp6opt *,
                              struct dhcp6_optinfo *);
extern void dhcp6_set_timeoparam(struct dhcp6_event *);
extern void dhcp6_reset_timer(struct dhcp6_event *);
extern gchar *dhcp6optstr(gint);
extern gchar *dhcp6msgstr(gint);
extern gchar *dhcp6_stcodestr(gint);
extern gchar *duidstr(const struct duid *);
extern gint duidcpy(struct duid *, const struct duid *);
extern gint duidcmp(const struct duid *, const struct duid *);
extern void duidfree(struct duid *);
extern void relayfree(struct relay_list *);
extern void ifinit(const gchar *);
extern gint configure_duid(const gchar *, struct duid *);
extern struct dhcp6_if *find_ifconfbyname(const gchar *);
extern struct dhcp6_if *find_ifconfbyid(guint);
extern struct prefix_ifconf *find_prefixifconf(const gchar *);
extern struct host_conf *find_hostconf(const struct duid *);
extern ssize_t gethwid(guchar *, gint, const gchar *, guint16 *);

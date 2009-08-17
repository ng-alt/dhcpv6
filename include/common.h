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

#ifndef __COMMON_H_DEFINED
#define __COMMON_H_DEFINED

#include "constants.h"
#include "types.h"
#include "str.h"
#include "duid.h"
#include "timer.h"
#include "lease.h"
#include "log.h"

/* XXX: this is a global that needs to go */
extern const dhcp6_mode_t dhcp6_mode;

dhcp6_if_t *find_ifconfbyname(const gchar *);
dhcp6_if_t *find_ifconfbyid(guint);
host_conf_t *find_hostconf(const duid_t *);
void ifinit(const gchar *);
gint dhcp6_copy_list(GSList *, GSList *);
dhcp6_value_t *dhcp6_find_listval(GSList *, void *, dhcp6_listval_type_t);
dhcp6_value_t *dhcp6_add_listval(GSList *, void *, dhcp6_listval_type_t);
ia_t *ia_create_listval(void);
void ia_clear_list(GSList *);
gint ia_copy_list(GSList *, GSList *);
ia_t *ia_find_listval(GSList *, iatype_t, guint32);
dhcp6_event_t *dhcp6_create_event(dhcp6_if_t *, gint);
void dhcp6_remove_event(gpointer, gpointer);
gint getifaddr(struct in6_addr *, gchar *, struct in6_addr *,
               gint, gint, gint);
gint in6_addrscopebyif(struct in6_addr *, gchar *);
const gchar *getdev(struct sockaddr_in6 *);
gint transmit_sa(gint, struct sockaddr_in6 *, gchar *, size_t);
gint prefix6_mask(struct in6_addr *, gint);
gint sa6_plen2mask(struct sockaddr_in6 *, gint);
gint in6_scope(struct in6_addr *);
void dhcp6_init_options(dhcp6_optinfo_t *);
void dhcp6_clear_options(dhcp6_optinfo_t *);
gint dhcp6_copy_options(dhcp6_optinfo_t *, dhcp6_optinfo_t *);
gint dhcp6_get_options(dhcp6opt_t *, dhcp6opt_t *, dhcp6_optinfo_t *);
gint dhcp6_set_options(dhcp6opt_t *, dhcp6opt_t *, dhcp6_optinfo_t *);
void dhcp6_set_timeoparam(dhcp6_event_t *);
void dhcp6_reset_timer(dhcp6_event_t *);
gint copy_option(gint, guint8, void *, dhcp6opt_t *, dhcp6opt_t *,
                 dhcp6opt_t *);
gboolean is_in6_addr_reserved(struct in6_addr *);
void random_init(void);

#endif /* __COMMON_H_INCLUDE */

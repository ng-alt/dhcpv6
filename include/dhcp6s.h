/*
 * dhcp6s.h
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

#ifndef __DHCP6S_H_DEFINED
#define __DHCP6S_H_DEFINED

#include "constants.h"
#include "types.h"
#include "str.h"
#include "common.h"
#include "server6_addr.h"
#include "duid.h"
#include "gfunc.h"
#include "timer.h"
#include "lease.h"
#include "log.h"

/* XXX: from server6_token.l */
extern gint sfparse(const gchar *);

/* XXX: from common.c */
extern dns_info_t dnsinfo;

void server6_init(void);

#endif /* __DHCP6S_H_DEFINED */

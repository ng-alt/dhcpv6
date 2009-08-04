/*
 * log.c
 * Logging functions for dhcpv6.
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

/* ported from KAME: common.c,v 1.65 2002/12/06 01:41:29 suz Exp */

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

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <net/if.h>
#include <netinet/in.h>
#include <glib.h>

#include "log.h"

void setup_logging(gchar *ident, log_properties_t *props) {
    openlog(ident, LOG_CONS | LOG_NDELAY | LOG_PID, LOG_DAEMON);

    props->threshold = G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL |
                       G_LOG_LEVEL_WARNING;
    props->progname = ident;

    if (props->debug) {
        props->threshold |= G_LOG_LEVEL_MASK;
    } else if (props->verbose) {
        props->threshold |= G_LOG_LEVEL_MESSAGE | G_LOG_LEVEL_INFO;
    }

    g_log_set_handler(NULL, G_LOG_LEVEL_MASK, log_handler, (gpointer) props);

    return;
}

void log_handler(const gchar *log_domain, GLogLevelFlags log_level,
                 const gchar *message, gpointer user_data) {
    log_properties_t *props = (log_properties_t *) user_data;
    GDate *stamp = NULL;
    GTimeVal timeval;
    gchar stampbuf[64];

    if (!(log_level & props->threshold)) {
        return;
    }

    if (props->foreground) {
        stamp = g_date_new();
        g_get_current_time(&timeval);
        g_date_set_time_val(stamp, &timeval);

        memset(&stampbuf, '\0', sizeof(stampbuf));
        g_date_strftime(stampbuf, sizeof(stampbuf), "%Y-%m-%dT%T%z", stamp);
        g_date_free(stamp);

        fprintf(stderr, "%s %s[%d]: %s\n", stampbuf, props->progname,
                props->pid, message);
    } else {
        syslog(log_level, message);
    }

    return;
}

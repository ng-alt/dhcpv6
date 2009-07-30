/*
 * Copyright (C) NEC Europe Ltd., 2003
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

#ifndef __RELAY6_DATABASE_H_DEFINED
#define __RELAY6_DATABASE_H_DEFINED

typedef struct _relay_interface_t {
    GSList *sname;
    GSList *ipv6addr;

    gint got_addr;
    gchar *ifname;
    guint32 devindex;
    gchar *link_local;
    gint opaq;
} relay_interface_t;

GSList *cifaces_list;
GSList *sifaces_list;

GSList *relay_server_list;
GSList *IPv6_address_list;
GSList *IPv6_uniaddr_list;
GSList *relay_interface_list;

gint process_RELAY_FORW(struct msg_parser * msg);
gint process_RELAY_REPL(struct msg_parser * msg);
struct msg_parser *get_send_messages_out(void);
void delete_messages(void);
gint check_interface_semafor(gint index);
relay_interface_t *get_interface(gint if_index);
relay_interface_t *get_interface_s(gchar *s);

gint nr_of_devices;
gint nr_of_uni_addr;
gint max_count;
gint multicast_off;

void init_relay(void);
void command_text(void);

#endif /* __RELAY6_DATABASE_H_DEFINED */

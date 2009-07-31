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

#ifndef __RELAY6_SOCKET_H_DEFINED
#define __RELAY6_SOCKET_H_DEFINED

fd_set readfd;
gint fdmax;

typedef struct _relay_socket_t {
    struct msghdr msg;
    struct iovec iov[1];
    struct cmsghdr *cmsgp;
    struct sockaddr_in6 sin6;   /* my address information */
    struct sockaddr_in6 from;
    gint recvmsglen;
    gchar *recvp;
    gchar src_addr[INET6_ADDRSTRLEN];
    gint pkt_interface;
    gint buflength;
    gint dst_addr_type;
    gchar *databuf;
    gint sock_desc;
} relay_socket_t;

relay_socket_t *relaysock;

gint send_message(void);
gint fill_addr_struct(void);
gint set_sock_opt(void);
gint recv_data(void);
gint check_select(void);
gint get_recv_data(void);
gint get_interface_info(void);
void init_socket(void);

#endif /* __RELAY6_SOCKET_H_DEFINED */

/*	$Id: prefixconf.h,v 1.1.1.1 2003/01/16 15:41:11 root Exp $	*/
/*	ported from KAME: prefixconf.h,v 1.3 2002/06/21 10:23:33 jinmei Exp */

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

typedef enum { PREFIX6S_ACTIVE, PREFIX6S_RENEW,
	       PREFIX6S_REBIND} prefix6state_t;

struct dhcp6_siteprefix {
	TAILQ_ENTRY(dhcp6_siteprefix) link; /* link to next site prefix */

	struct dhcp6_if *ifp;
	struct dhcp6_prefix prefix;
	struct duid serverid;

	prefix6state_t state;
	struct dhcp6_timer *timer;

	struct dhcp6_eventdata *evdata;

	/* list of interface prefixes */
	TAILQ_HEAD(, dhcp6_ifprefix) ifprefix_list;
};

extern void prefix6_init __P((void));
extern void prefix6_remove_all __P((void));
extern int prefix6_add __P((struct dhcp6_if *, struct dhcp6_prefix *,
			       struct duid *));
extern int prefix6_update __P((struct dhcp6_event *, struct dhcp6_list *,
				  struct duid *));

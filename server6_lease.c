/*	$Id: server6_lease.c,v 1.1 2003/01/16 15:41:11 root Exp $	*/

/*
 * Copyright (C) International Business Machines  Corp., 2003
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

/* Author: Elizabeth Kon, beth@us.ibm.com */

#include <stdio.h>
#include <time.h>
#include <syslog.h>
#include <netinet/in.h>
#include <errno.h>
#include "server6_addr.h"
#include "hash.h"

FILE *lease_file;
FILE *sync_file;
struct hash_table **hash_anchors;

extern char *temp_lease;

int 
write_lease(struct server6_lease *lease_ptr, FILE *file) 
{
	int j = 0;
	int i = 0;
	struct tm brokendown_time;
	char addr_str[16];

        gmtime_r(&lease_ptr->start_date, &brokendown_time); 
	inet_ntop(AF_INET6, &lease_ptr->lease_addr, addr_str, sizeof(struct in6_addr));
	
	fprintf(file, "lease %s/%d { \n", addr_str, lease_ptr->plen);

	fprintf(file, "\t start date: %d %d/%d/%d %d:%d:%d UTC;\n",
		     brokendown_time.tm_wday,
		     brokendown_time.tm_year + 1900,
		     brokendown_time.tm_mon + 1,
		     brokendown_time.tm_mday,
		     brokendown_time.tm_hour,
		     brokendown_time.tm_min,
		     brokendown_time.tm_sec);
	fprintf(file, "\t (program use only: start date %ld);\n", lease_ptr->start_date);
	fprintf(file, "\t preferred lifetime: 0x%x;\n",
                             lease_ptr->preferlifetime);
	fprintf(file, "\t valid lifetime: 0x%x;\n",
                             lease_ptr->validlifetime);
        if(1 == lease_ptr->iaidinfo->client_info.client_iatype){
		fprintf(file, "\t IAID: 0x%x temporary;\n",
			lease_ptr->iaidinfo->client_info.client_iaid);
	} else {
		fprintf(file, "\t IAID: 0x%x non-temporary;\n",
			lease_ptr->iaidinfo->client_info.client_iaid);
	}
		
	fprintf(file, "\t DUID string length: %d;\n",
			lease_ptr->iaidinfo->client_info.clientid.duid_len);
	fprintf(file, "\t DUID: %s;\n", duidstr(&lease_ptr->iaidinfo->client_info.clientid));
	inet_ntop(AF_INET6, &lease_ptr->linklocal, addr_str, sizeof(struct in6_addr));
	fprintf(file, "\t linklocal: %s;\n", addr_str);
	fprintf(file, "\t state: %d;\n", lease_ptr->state);
	fprintf(file, "\t hostname: %s;\n",lease_ptr->hostname);
	fprintf(file, "}\n");
	if (fflush(lease_file) == EOF) {
		dprintf(LOG_INFO, "%s" "write lease fflush failed %s", 
				FNAME, strerror(errno));
		return -1;
	}
	if (fsync(fileno(lease_file)) < 0) {
		dprintf(LOG_INFO, "%s" "write lease fsync failed %s", 
				FNAME, strerror(errno));
		return -1;
	}
	/* ToDo: if the lease file hasn't been sync within 5 mins, do sync_lease() */
	return 0;
}

int 
sync_leases (void) 
{
	int i, rc;
	struct hashlist_element *element;
        sync_file = fopen(PATH_DHCPv6S_TEMPLEASE, "w");
	if(!sync_file) {
                dprintf(LOG_ERR, "%s" "could not open sync file", FNAME);
                return -1;
        }
	for (i = 0; i < hash_anchors[HT_IPV6ADDR]->hash_size; i++) {
		element = hash_anchors[HT_IPV6ADDR]->hash_list[i];
		while (element) {
			rc = write_lease((struct server6_lease *)element->data, sync_file);
			if (rc) {
				dprintf(LOG_ERR, "%s" "write lease failed",
					FNAME);
				return -1;
			}
			element = element->next;
		}
	}
	fclose(lease_file);
	fclose(sync_file);
	rc = rename(PATH_DHCPv6S_TEMPLEASE, PATH_DHCPv6S_LEASE); 
	if (rc) {
		dprintf(LOG_ERR, "Could not rename sync file", FNAME);
		return -1;
	}
        lease_file = fopen(PATH_DHCPv6S_LEASE, "a+");
	if(!lease_file) {
                dprintf(LOG_ERR, "%s" "could not open sync file", FNAME);
		return -1;
	}
       return 0; 
}

int init_leases(void) 
{
        lease_file = fopen(PATH_DHCPv6S_LEASE, "a+");
        if(!lease_file) {
                dprintf(LOG_ERR, "%s" "could not open lease file", FNAME);
                return (-1);
        }
	if (0 != init_lease_hashes()) {
		dprintf(LOG_ERR, "%s" "Could not initialize hash arrays", FNAME);
		return (-1);
	}
	parse_leases();
} 

int init_lease_hashes(void) 
{

	hash_anchors = malloc(HASH_TABLE_COUNT*sizeof(struct hashtable *));
	if (!hash_anchors) {
		dprintf(LOG_ERR, "Couldn't malloc hash anchors", FNAME);
		return (-1);
	}
        hash_anchors[HT_IPV6ADDR] = hash_table_create(DEFAULT_HASH_SIZE, 
			addr_hash, addr_findkey, addr_key_compare);
	if (!hash_anchors[HT_IPV6ADDR]) {
		dprintf(LOG_ERR, "Couldn't create hash table", FNAME);
		return (-1);
	}
        hash_anchors[HT_IAIDADDR] = hash_table_create(DEFAULT_HASH_SIZE, 
			iaid_hash, iaid_findkey, iaid_key_compare);
	if (!hash_anchors[HT_IAIDADDR]) {
		dprintf(LOG_ERR, "%s" "Couldn't create hash table", FNAME);
		return (-1);
	}
	return 0;

}

void * addr_findkey(void *data)
{
        struct server6_lease *lease = (struct server6_lease *)data;
	return (void *)(&(lease->lease_addr));
}

int addr_key_compare(void *data, void *key)
{ 	
	int i;
	struct in6_addr *data_lease_address = &(((struct server6_lease *)data)->lease_addr);
	for (i = 0; i < 4; i++) {
		if (data_lease_address->in6_u.u6_addr32[i] != (((struct in6_addr *)key)->in6_u.u6_addr32[i])){
			return MISCOMPARE;
		}
        }
	return MATCH;
}

void * iaid_findkey(void *data)
{
        struct server6_cl_iaidaddr *iaidaddr = (struct server6_cl_iaidaddr *)data;
	return (void *)(&(iaidaddr->client_info));
}

int iaid_key_compare(void *data, void *key)
{ 	
	int i;
        struct server6_cl_iaidaddr *iaidaddr = (struct server6_cl_iaidaddr *)data;
	struct client_if *client_key = (struct client_if *)key;
	if (client_key->client_iaid == iaidaddr->client_info.client_iaid){
		if (0 == duidcmp(&client_key->clientid, &iaidaddr->client_info.clientid)){
			return MATCH;
		}
	}
	return MISCOMPARE;
}


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
 */

%option noyywrap
%option nounput

%{
#include "config.h"

#include <fcntl.h>
#include <syslog.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <resolv.h>

#include <glib.h>

#include "queue.h"
#include "duid.h"
#include "dhcp6.h"
#include "confdata.h"
#include "common.h"
#include "str.h"
#include "gfunc.h"

#undef yywrap

#define YY_NO_UNPUT 1
#define YY_NO_INPUT 1
#define ECHO \
    if (fwrite(yytext, yyleng, 1, yyout) != 1) { \
        YY_FATAL_ERROR("error performing ECHO on yytext"); \
    }

#define YYABORT(msg) g_error("%s %s lineno %d", msg, yytext, num_lines)

#define ABORT \
    do { \
        YYABORT("resolv parse error"); \
        remove(RESOLV_CONF_DHCPV6_FILE); \
        exit(1); \
    } while (0)

extern struct dhcp6_if *dhcp6_if;
static gint num_lines = 0;
static dns_info_t *new_dnsinfo;
static FILE *dhcp6_resolv_file;
static gint oldfd, newfd;

static void _check_existing_dns_servers(gpointer, gpointer);
static void _check_existing_dns_domains(gpointer, gpointer);
static void _print_to_search_line(gpointer, gpointer);
static gint yywrap();
gint resolv_parse(dns_info_t *);
static gint update_resolver(dns_info_t *);

%}

digit      [0-9]
number     ({digit})+
hexdigit   ([a-f]|[A-F]|[0-9])
ipv4addr   ({digit}{1,3}"."{digit}{1,3}"."{digit}{1,3}"."{digit}{1,3})
addr_head  ("::"|{hexdigit}{1,4}(":"|"::"))
addr_tail  ({hexdigit}{1,4}|({hexdigit}{1,4}"::")|{ipv4addr})?
addr_body  ({hexdigit}{1,4}(":"|"::"))*
ipv6addr   {addr_head}{addr_body}{addr_tail}
whitespace ([ \t])+
domainname [a-zA-Z0-9:\._-]+
nl         \n

%s S_ADDR S_DOMAIN

%%

{nl} {
    fprintf(dhcp6_resolv_file, yytext);
    num_lines++;
}

{whitespace} {
    fprintf(dhcp6_resolv_file, yytext);
}

"nameserver" {
    fprintf(dhcp6_resolv_file, yytext);
    BEGIN S_ADDR;
}

"search" {
    fprintf(dhcp6_resolv_file, yytext);
    BEGIN S_DOMAIN;
}

<S_DOMAIN>{domainname} {
    gchar *name = NULL;

    if (strlen(yytext) > MAXDNAME) {
        ABORT;
    }

    fprintf(dhcp6_resolv_file, yytext);
    name = g_strdup(yytext);
    g_debug("parse domain name %s", name);
    dhcp6_if->dnsinfo.domains = g_slist_append(dhcp6_if->dnsinfo.domains, name);

    BEGIN S_DOMAIN;
}

<S_DOMAIN>. {
    fprintf(dhcp6_resolv_file, yytext);
    BEGIN INITIAL;
}

<S_ADDR>{ipv6addr} {
    struct in6_addr *addr = g_malloc0(sizeof(struct in6_addr));

    if (addr == NULL) {
        ABORT;
    }

    fprintf(dhcp6_resolv_file, yytext);

    if (inet_pton(AF_INET6, yytext, addr) < 1) {
        ABORT;
    }

    g_debug("parse name server %s", in6addr2str(addr, 0));
    dhcp6_if->dnsinfo.servers = g_slist_append(dhcp6_if->dnsinfo.servers, addr);

    BEGIN S_ADDR;
}

<S_ADDR>. {
    fprintf(dhcp6_resolv_file, yytext);
    BEGIN INITIAL;
}

. {
    fprintf(dhcp6_resolv_file, yytext);
}

%%

static void _check_existing_dns_servers(gpointer data, gpointer user_data) {
    struct in6_addr *ns = (struct in6_addr *) data;
    GSList *existing_servers = (GSList *) user_data;
    GSList *dupe = NULL;

    dupe = g_slist_find_custom(existing_servers, ns, _find_in6_addr);
    if (dupe != NULL) {
        g_debug("nameserver %s found in resolv.conf", in6addr2str(ns, 0));
        existing_servers = g_slist_remove(existing_servers, dupe);
    }

    return;
}

static void _check_existing_dns_domains(gpointer data, gpointer user_data) {
    gchar *domain = (gchar *) data;
    GSList *existing_domains = (GSList *) user_data;
    GSList *dupe = NULL;

    dupe = g_slist_find_custom(existing_domains, domain, _find_string);
    if (dupe != NULL) {
        g_debug("domain name %s found in resolv.conf", domain);
        existing_domains = g_slist_remove(existing_domains, dupe);
    }

    return;
}

static void _print_to_search_line(gpointer data, gpointer user_data) {
    gchar *domain = (gchar *) data;
    FILE *resolv = (FILE *) user_data;

    g_debug("domain name %s added to resolv.conf", domain);
    fprintf(resolv, " %s", domain);
    return;
}

#ifdef NETWORK_FUNCTIONS_SCRIPT
gint change_resolv_conf(gchar *new_rscf) {
    gchar *argv[] = { "/bin/bash", "-c", 0L, 0L };
    gchar *cmd;
    gint l, pid, status;
    extern gchar **environ;

    if (new_rscf == NULL) {
        return -1;
    }

    if (getuid() != 0) {
        return 1;
    }

    l = strlen(NETWORK_FUNCTIONS_SCRIPT) + strlen(new_rscf) + 27;
    cmd = (gchar *) malloc(l);
    snprintf(cmd, l, ". %s ; change_resolv_conf %s",
             NETWORK_FUNCTIONS_SCRIPT, new_rscf);
    argv[2] = cmd;

    if ((pid = fork()) < 0) {
        return -1;
    } else if (pid > 0) {
        status = 0;

        if (waitpid(pid, &status, 0) == pid) {
            if ((status & 0x7f) == 0) {
                return ((status >> 8) & 0xff);
            } else {
                return -(status & 0x7f);
            }
        }
    } else {
        execve(argv[0], argv, environ);
    }

    return -1;
}
#endif

gint backup_resolv_conf(void) {
    struct stat buf;
    mode_t st_mode;
    gchar str[BUFSIZ];
    size_t rlen, wlen;

    /* Do not overwrite if a backup file already exists */
    if (!lstat(RESOLV_CONF_BAK_FILE, &buf)) {
        g_debug("%s: backup file for resolv.conf exists", __func__);
        return 0;
    }

    if (lstat(_PATH_RESCONF, &buf) < 0) {
        g_error("%s: Failed to stat %s : %s",
                __func__, _PATH_RESCONF, strerror(errno));
    }

    st_mode = buf.st_mode;

    if ((oldfd = open(_PATH_RESCONF, O_RDONLY)) < 0) {
        g_error("%s: Failed to open %s : %s",
                __func__, _PATH_RESCONF, strerror(errno));
        return -1;
    }

    newfd = open(resolv_dhcpv6_file, O_WRONLY | O_CREAT | O_EXCL, st_mode);
    if (newfd < 0) {
        g_error("%s: Failed to open %s : %s",
                __func__, resolv_dhcpv6_file, strerror(errno));
        close(oldfd);
        return -1;
    }

    while(1) {
        rlen = read(oldfd, str, sizeof(str));

        if (rlen < 0) {
            g_error("%s: Failed to read %s :%s ",
                    __func__, _PATH_RESCONF, strerror(errno));
            close(oldfd);
            close(newfd);
            return -1;
        } else if (rlen == 0) {
            break;
        }

        wlen = write(newfd, str, rlen);

        if (wlen < rlen) {
            g_error("%s: Failed to write %s :%s ",
                    __func__, resolv_dhcpv6_file, strerror(errno));
            close(oldfd);
            close(newfd);
            return -1;
        }
    }

    close(oldfd);
    close(newfd);

    if (rename(_PATH_RESCONF, RESOLV_CONF_BAK_FILE)) {
        g_error("%s: Failed to rename %s : %s",
                __func__, _PATH_RESCONF, strerror(errno));
        return -1;
    }

    if (rename(resolv_dhcpv6_file, _PATH_RESCONF)) {
        g_error("%s: Failed to rename %s : %s",
                __func__, resolv_dhcpv6_file, strerror(errno));
        /* Try to take back original resolv.conf */
        rename(RESOLV_CONF_BAK_FILE, _PATH_RESCONF);
        return -1;
    }

    return 0;
}

/* parse resolv.conf
 * create a new resolv.conf.dhcpv6
 * mv /etc/resolv.conf to /etc/resolv.conf.V6BAK
 * link resolv.conf to resolv.conf.dhcpv6
 */
gint resolv_parse(dns_info_t *dnsinfo) {
    struct stat buf;
    gchar pidstr[128];
    sprintf(pidstr, "%d", getpid());
    strcpy(resolv_dhcpv6_file, RESOLV_CONF_DHCPV6_FILE);
    strcat(resolv_dhcpv6_file, pidstr);
    dhcp6_if->dnsinfo.servers = NULL;
    dhcp6_if->dnsinfo.domains = NULL;
    new_dnsinfo = dnsinfo;

    /* Back up resolv.conf */
    if (!lstat(_PATH_RESCONF, &buf)) {
        if (backup_resolv_conf() < 0) {
            g_error("%s: backup failed for resolv.conf file", __func__);
            return -1;
        }
    }

    while ((oldfd = open(RESOLV_CONF_BAK_FILE, O_EXCL)) < 0) {
        switch (errno) {
            case ENOENT:
                /* exclusive open of new resolv.conf.dhcpv6 file */
                newfd = open(resolv_dhcpv6_file,
                             O_CREAT|O_EXCL|O_WRONLY|O_TRUNC, 0644);
                if (newfd < 0) {
                    g_error("%s: failed to open %s file",
                            __func__, resolv_dhcpv6_file);
                    return -1;
                }

                if ((dhcp6_resolv_file = fdopen(newfd, "w")) == NULL) {
                    g_error("%s: failed to fdopen %s file",
                            __func__, resolv_dhcpv6_file);
                    return -1;
                }

                return(update_resolver(dnsinfo));
            case EACCES:
                sleep(1);
                continue;
            default:
                g_error("resolv_parse: fopen(%s): %s",
                        RESOLV_CONF_BAK_FILE, strerror(errno));
                return -1;
        }
    }

    if (lstat(RESOLV_CONF_BAK_FILE, &buf)) {
        g_error("lstat %s file failed", RESOLV_CONF_BAK_FILE);
        return -1;
    }

    if ((yyin = fdopen(oldfd, "r")) == NULL) {
        g_error("resolv_parse: fdopen(%s): %s",
                RESOLV_CONF_BAK_FILE, strerror(errno));
        return -1;
    }

    /* exclusive open of new resolv.conf.dhcpv6 file */
    newfd = open(resolv_dhcpv6_file, O_CREAT|O_EXCL|O_WRONLY|O_TRUNC,
                 buf.st_mode);
    if (newfd < 0) {
        g_error("%s: failed to open resolv.conf.dhcpv6 file", __func__);
        return -1;
    }

    if ((dhcp6_resolv_file = fdopen(newfd, "w")) == NULL) {
        g_error("%s: failed to fdopen resolv.conf.dhcpv6 file", __func__);
        return -1;
    }

    return yylex();
}

static gint update_resolver(dns_info_t *dnsinfo) {
    struct stat buf;
    gint ret = 0;

    fseek(dhcp6_resolv_file, 0, SEEK_CUR);

    if (g_slist_length(dnsinfo->servers)) {
        g_slist_foreach(dnsinfo->servers, _print_in6_addr,
                        "received nameserver");
        g_slist_foreach(dhcp6_if->dnsinfo.servers, _check_existing_dns_servers,
                        dnsinfo->servers);

        if (g_slist_length(dnsinfo->servers)) {
            g_slist_foreach(dnsinfo->servers, _print_in6_addr, "nameserver");
        }
    }

    if (g_slist_length(dnsinfo->domains)) {
        g_slist_foreach(dnsinfo->domains, _print_string,
                        "received domain name");
        g_slist_foreach(dhcp6_if->dnsinfo.domains, _check_existing_dns_domains,
                        dnsinfo->domains);

        if (g_slist_length(dnsinfo->domains)) {
            fprintf(dhcp6_resolv_file, "search");
            g_slist_foreach(dnsinfo->domains, _print_to_search_line,
                            dhcp6_resolv_file);
            fprintf(dhcp6_resolv_file, "\n");
        }
    }

    if (fflush(dhcp6_resolv_file) == EOF) {
        g_error("%s: write resolv.conf.dhcpv6 file fflush failed %s",
                __func__, strerror(errno));
        ret = -1;
        goto out;
    }

    if (fsync(newfd) < 0) {
        g_error("%s: write resolv.conf.dhcpv6 file failed %s",
                __func__, strerror(errno));
        ret = -1;
        goto out;
    }

    fclose(dhcp6_resolv_file);
    close(newfd);

#ifdef NETWORK_FUNCTIONS_SCRIPT
    if (!lstat(NETWORK_FUNCTIONS_SCRIPT, &buf)) {
        if (change_resolv_conf(resolv_dhcpv6_file) != 0) {
            /* g_error("%s: rename failed for resolv.conf file", __func__); */
            /* needs initscripts patch!  return(-1); */
        }
    } else {
#endif
        if (rename(resolv_dhcpv6_file, _PATH_RESCONF)) {
            g_error("%s: rename failed for resolv.conf file", __func__);
            ret = -1;
            goto out;
        }
#ifdef NETWORK_FUNCTIONS_SCRIPT
    }
#endif

out:
    if (!lstat(resolv_dhcpv6_file, &buf))
        unlink(resolv_dhcpv6_file);
    return ret;
}

static gint yywrap() {
    update_resolver(new_dnsinfo);
    fclose(yyin);
    close(oldfd);
    return 1;
}

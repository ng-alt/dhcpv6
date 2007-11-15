/*
 * dhc6_alloc.c
 *
 * Copyright (C) 2006, 2007  Red Hat, Inc. All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions of
 * the GNU General Public License v.2, or (at your option) any later version.
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY expressed or implied, including the implied warranties of
 * MERCHANTABILITY or FITNESS FOR A * PARTICULAR PURPOSE.  See the GNU General
 * Public License for more details.  You should have received a copy of the
 * GNU General Public License along with this program; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.  Any Red Hat trademarks that are incorporated in the
 * source code or documentation are not subject to the GNU General Public
 * License and may only be used or replicated with the express permission of
 * Red Hat, Inc.
 *
 * Red Hat Author(s): Jason Vas Dias
 *                    David Cantrell <dcantrell@redhat.com>
 */

#include <malloc.h>
#include <search.h>
#include <string.h>

extern void tdestroy (void *root, void (*free_node)(void *nodep));
void *ifp_ptr;

static void *ptr_tree = NULL;

static int ptr_comparator(const void *p1, const void *p2) {
    return ((p1 == p2) ? 0 : ((p1 > p2) ? 1 : -1));
}

void *dhc6_alloc(size_t s) {
    void *ptr = malloc(s);
    if (ptr != 0)
        tsearch(ptr, &(ptr_tree), ptr_comparator);
    return ptr;
}

void *dhc6_realloc(void *ptr, size_t s) {
    void *ptr2 = realloc(ptr, s);
    if (ptr2 != 0) {
        if (ptr != 0)
            tdelete(ptr,&(ptr_tree), ptr_comparator);
        tsearch(ptr2, &(ptr_tree), ptr_comparator);
    }
    return ptr2;
}

void *dhc6_calloc(size_t n, size_t s) {
    void *ptr = calloc(n, s);
    if (ptr != 0)
        tsearch(ptr, &(ptr_tree), ptr_comparator);
    return ptr;
}

char *dhc6_strdup(char *str) {
    char *ptr = strdup(str);
    if (ptr != 0)
        tsearch(ptr, &(ptr_tree), ptr_comparator);
    return ptr;
}

void dhc6_free(void *ptr) {
    free(ptr);
    tdelete(ptr, &(ptr_tree), ptr_comparator);
}

void dhc6_free_all_pointers(void) {
    if (ptr_tree != NULL)
        tdestroy(ptr_tree, free);
    ptr_tree = NULL;
}

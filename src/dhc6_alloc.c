/*
 * dhc6_alloc.c
 *
 * Copyright (C) 2006, 2007, 2008  Red Hat, Inc.
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
 * Author(s): Jason Vas Dias
 *            David Cantrell <dcantrell@redhat.com>
 */

#include "config.h"

#include <stdlib.h>
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

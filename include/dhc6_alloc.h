/*
 * dhc6_alloc.h
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

extern void *dhc6_alloc(size_t);
extern void *dhc6_realloc(void *, size_t);
extern void *dhc6_calloc(size_t, size_t);
extern char *dhc6_strdup(char *str);
extern void dhc6_free(void *);
extern void dhc6_free_all_pointers(void);

#undef malloc
#define malloc(size) dhc6_alloc(size)
#undef realloc
#define realloc(ptr, size) dhc6_realloc(ptr, size)
#undef calloc
#define calloc(n, size) dhc6_calloc(n, size)
#undef free
#define free(ptr) dhc6_free(ptr)
#undef strdup
#define strdup(str) dhc6_strdup(str)

/*
 * dhc6_alloc.h
 *
 * Copyright (C) 2006, 2007, 2008  Red Hat, Inc.
 * All rights reserved.
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

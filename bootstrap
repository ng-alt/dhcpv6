#!/bin/bash
aclocal -I m4
if [ "$(uname -s)" = "Darwin" ]; then
    glibtoolize --copy --force
else
    libtoolize --copy --force
fi
autoconf
autoheader
touch config.h.in
automake --foreign --add-missing --copy
rm -rf autom4te.cache

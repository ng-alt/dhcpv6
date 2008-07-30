#!/usr/bin/env python
#
# tag - Reads configure.ac, extracts name and version, does a GPG-signed tag
#       on the repository.  Used so tags can be created without going through
#       a bootstrap process first.
#

import os
import sys

if __name__ == "__main__":
    cwd = os.getcwd()
    gpgkey = os.environ['GPGKEY']
    pkg = None
    ver = None

    if gpgkey == '':
        sys.stderr.write("GPGKEY environment variable missing, please set this to the key ID\nyou want to use to tag the repository.\n")
        sys.exit(1)

    if not os.path.isfile(cwd + '/configure.ac'):
        sys.stderr.write("Cannot find configure.ac in current directory.\n")
        sys.exit(2)

    f = open(cwd + '/configure.ac')
    lines = f.readlines()
    f.close()

    for line in lines:
        line = line.strip()
        if line.startswith('AC_INIT('):
            pkg = line.split('[')[1].split(']')[0]
            ver = line.split('[')[2].split(']')[0]
            break

    if pkg is None or ver is None:
        sys.stderr.write("Could not determine package name and/or version.\n")
        sys.exit(3)

    cmd = "git-tag -u %s -m \"Tag as %s-%s\" -f %s-%s" % (gpgkey, pkg, ver, pkg, ver,)
    os.system(cmd)

    print "Tagged as %s-%s (GPG signed)" % (pkg, ver,)
    sys.exit(0)

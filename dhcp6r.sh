#!/bin/bash
#
# chkconfig: - 66 36
# description: dhcp6r supports the DHCPv6 relay agent protocol.
# processname: dhcp6r
# config: /etc/sysconfig/dhcp6r

# Source function library
. /etc/init.d/functions

RETVAL=0
prog=dhcp6r
dhcp6r=/usr/sbin/dhcp6r
lockfile=/var/lock/subsys/dhcp6r

# Check that networking is up.
# networking is not up, return 1 for generic error
. /etc/sysconfig/network
[ $NETWORKING = "no" ] && exit 1

start() {
    # return 5 if program is not installed
    [ -x $dhcp6r ] || exit 5

    # return 6 if program is not configured
    [ -f /etc/sysconfig/dhcp6r ] || exit 6
    . /etc/sysconfig/dhcp6r

    echo -n $"Starting $prog: "
    daemon $dhcp6r $DHCP6RARGS
    RETVAL=$?
    echo
    [ $RETVAL -eq 0 ] && touch $lockfile
    return $RETVAL
}

stop() {
    echo -n $"Shutting down $prog: "
    killproc $prog -TERM
    RETVAL=$?
    echo
    [ $RETVAL -eq 0 ] && rm -f $lockfile
    return $RETVAL
}

# See how we were called.
case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        stop
        start
        ;;
    reload)
        RETVAL=3
        ;;
    condrestart)
        if [ -f $lockfile ]; then
            stop
            start
        fi
        ;;
    status)
        status dhcp6r
        RETVAL=$?
        ;;
    *)
        echo $"Usage: $0 {start|stop|restart|condrestart|status}"
        RETVAL=3
        ;;
esac

exit $RETVAL

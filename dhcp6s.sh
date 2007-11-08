#!/bin/bash
#
# chkconfig: - 66 36
# description: dhcp6s supports the server side of Dynamic Host Configuration \
#              Protocol for IPv6.
# processname: dhcp6s
# config: /etc/dhcp6s.conf
# config: /etc/sysconfig/dhcp6s

# Source function library
. /etc/init.d/functions

RETVAL=0
prog=dhcp6s
dhcp6s=/usr/sbin/dhcp6s
lockfile=/var/lock/subsys/dhcp6s

# Check that networking is up.
# networking is not up, return 1 for generic error
. /etc/sysconfig/network
[ $NETWORKING = "no" ] && exit 1

start() {
    # return 5 if program is not installed
    [ -x $dhcp6s ] || exit 5

    # return 6 if program is not configured
    [ -f /etc/dhcp6s.conf ] || exit 6
    [ -f /etc/sysconfig/dhcp6s ] || exit 6
    . /etc/sysconfig/dhcp6s

    if [ -z "$DHCP6SIF" ]; then
        logger -s -t "$prog" -p "daemon.info" "Warning: $prog listening on ALL interfaces"
    fi

    echo -n $"Starting $prog: "
    daemon $dhcp6s -c /etc/dhcp6s.conf $DHCP6SARGS $DHCP6SIF
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
        status $prog
        RETVAL=$?
        ;;
    *)
        echo $"Usage: $0 {start|stop|restart|condrestart|status}"
        RETVAL=3
        ;;
esac

exit $RETVAL

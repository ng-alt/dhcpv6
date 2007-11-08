#!/bin/sh
#
# dhcp6r        dhcp6r is an implementation of DHCPv6 relay agent.
#               This shell script takes care of starting and stopping
#               dhcp6r.
#
# chkconfig: - 66 36
# description: dhcp6r supports the DHCPv6 relay agent protocol. 
#            
# processname: dhcp6r
# config: /etc/sysconfig/dhcp6r

# Source function library.
. /etc/rc.d/init.d/functions

# Source networking configuration.
. /etc/sysconfig/network
. /etc/sysconfig/dhcp6r

# Check that networking is up.
# networking is not up, return 1 for generic error
[ ${NETWORKING} = "no" ] && exit 1

# Check that files exist
# return 5 if program is not installed
[ -f /usr/sbin/dhcp6r ] || exit 5

# return 6 if program is not configured
[ -f /etc/sysconfig/dhcp6r ] || exit 6

RETVAL=0
prog="dhcp6r"

start() {
	# Start daemons.
	echo -n $"Starting $prog: "
	daemon /usr/sbin/dhcp6r ${DHCP6RARGS}
	RETVAL=$?
	echo
	[ $RETVAL -eq 0 ] && touch /var/lock/subsys/dhcp6r
	return $RETVAL
}

stop() {
	# Stop daemons.
	echo -n $"Shutting down $prog: "
	killproc dhcp6r
	RETVAL=$?
	echo
	[ $RETVAL -eq 0 ] && rm -f /var/lock/subsys/dhcp6r
	return $RETVAL
}

# See how we were called.
case "$1" in
  start)
	start
	RETVAL=$?
	;;
  stop)
	stop
	RETVAL=$?
	;;
  restart|force-reload)
	stop
	start
	RETVAL=$?
	;;
  reload)
	# unimplemented
	RETVAL=3
	;;
  condrestart)
	if [ -f /var/lock/subsys/dhcp6s ]; then
	    stop
	    start
	    RETVAL=$?
	fi
	;;
  status)
	status dhcp6r
	RETVAL=$?
	;;
  *)
	echo $"Usage: $0 {start|stop|restart|condrestart|status}"
	exit 1
esac

exit $RETVAL

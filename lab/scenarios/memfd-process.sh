#!/bin/sh
# hosts: tarpit hatchery
# match: /memfd:labscenario
# fix: yes
# A process whose executable only exists in memory (fileless malware): copy sleep into a memfd and exec it.
PIDFILE=/tmp/lab-memfd.pid
case "$1" in
plant)
  nohup python3 -c "
import os
open('$PIDFILE', 'w').write(str(os.getpid()))
fd = os.memfd_create('labscenario')
os.write(fd, open('/bin/sleep', 'rb').read())
os.execv('/proc/self/fd/%d' % fd, ['sleep', '600'])" </dev/null >/dev/null 2>&1 &
  sleep 2
  echo /memfd:labscenario ;;
clean)
  [ -f "$PIDFILE" ] && kill -9 "$(cat "$PIDFILE")" 2>/dev/null
  rm -f "$PIDFILE" ;;
esac

#!/bin/sh
# hosts: tarpit hatchery
# match: /etc/ssh/sshd_config
# fix: no
# The LSE view of the same drift: a critical file the unprivileged account can write (its fix is the permission-drift one).
F=/etc/ssh/sshd_config
case "$1" in
plant)
  stat -c %a "$F" > /tmp/lab-mode2.bak
  chmod 0666 "$F" && echo "$F" ;;
clean)
  [ -f /tmp/lab-mode2.bak ] && chmod "$(cat /tmp/lab-mode2.bak)" "$F"
  rm -f /tmp/lab-mode2.bak ;;
esac

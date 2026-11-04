#!/bin/sh
# hosts: tarpit hatchery
# match: /etc/ssh/sshd_config
# fix: yes
# A system file whose mode drifted from what the distribution ships (anyone can write sshd_config).
F=/etc/ssh/sshd_config
case "$1" in
plant)
  stat -c %a "$F" > /tmp/lab-mode.bak 2>/dev/null || stat -f %Lp "$F" > /tmp/lab-mode.bak
  chmod 0666 "$F" && echo "$F" ;;
clean)
  [ -f /tmp/lab-mode.bak ] && chmod "$(cat /tmp/lab-mode.bak)" "$F"
  rm -f /tmp/lab-mode.bak ;;
esac

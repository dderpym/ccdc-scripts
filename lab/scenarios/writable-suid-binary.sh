#!/bin/sh
# hosts: tarpit hatchery
# match: /usr/local/bin/lab-suid-writable
# fix: yes
# A setuid binary anyone can overwrite is a one-step root escalation.
F=/usr/local/bin/lab-suid-writable
case "$1" in
plant) cp -L /bin/true "$F" && chmod 4777 "$F" && echo "$F" ;;
clean) rm -f "$F" ;;
esac

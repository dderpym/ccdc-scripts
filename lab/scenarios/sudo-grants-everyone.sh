#!/bin/sh
# hosts: tarpit hatchery
# match: everyone has
# fix: yes
# `ALL ALL=(ALL) NOPASSWD: ALL` hands root to every account on the box.
F=/etc/sudoers.d/90-lab-everyone
case "$1" in
plant)
  echo 'ALL ALL=(ALL) NOPASSWD: ALL' > "$F" && chmod 0440 "$F"
  echo "everyone has" ;;
clean) rm -f "$F" ;;
esac

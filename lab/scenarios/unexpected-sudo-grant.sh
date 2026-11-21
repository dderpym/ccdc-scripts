#!/bin/sh
# hosts: tarpit hatchery
# match: labsudo
# fix: yes
# One extra account with passwordless sudo that init never wrote.
F=/etc/sudoers.d/91-lab-user
case "$1" in
plant)
  useradd -M -s /bin/sh labsudo
  echo 'labsudo ALL=(ALL) NOPASSWD: ALL' > "$F" && chmod 0440 "$F"
  echo labsudo ;;
clean)
  rm -f "$F"
  userdel labsudo 2>/dev/null ;;
esac

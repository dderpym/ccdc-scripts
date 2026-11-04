#!/bin/sh
# hosts: tarpit hatchery
# match: /usr/local/bin/lab-pam-hook
# fix: yes
# A pam_exec line with expose_authtok in the password stack captures every password set through chpasswd/passwd.
F=/etc/pam.d/chpasswd
HOOK=/usr/local/bin/lab-pam-hook
case "$1" in
plant)
  cp -p "$F" /tmp/lab-pam.bak
  printf '#!/bin/sh\ncat >/dev/null\n' > "$HOOK" && chmod 755 "$HOOK"
  echo "password optional pam_exec.so quiet expose_authtok $HOOK" >> "$F"
  echo "$HOOK" ;;
clean)
  [ -f /tmp/lab-pam.bak ] && cp -p /tmp/lab-pam.bak "$F"
  rm -f "$HOOK" /tmp/lab-pam.bak ;;
esac

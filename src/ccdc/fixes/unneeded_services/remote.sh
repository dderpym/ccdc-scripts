#!/bin/bash
# Runs on the target. remote.sh disable UNIT...: `systemctl disable --now` each unit that exists.
# Prints {"disabled": [...], "absent": [...], "failed": {unit: reason}}. Units not installed
# are skipped, so the same list works on every host.
set -u

json() {  # JSON-escape one string
  printf '%s' "$1" | tr -d '\000-\037' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

if [ "${1:-}" != "disable" ] || [ $# -lt 2 ]; then
  echo "usage: remote.sh disable UNIT..." >&2
  exit 2
fi
shift

disabled=""
absent=""
failed=""
for unit in "$@"; do
  q="\"$(json "$unit")\""
  if ! [[ "$unit" =~ ^[A-Za-z0-9:_.@\\-]+$ ]] || [[ "$unit" == -* ]]; then
    failed="${failed:+$failed, }$q: \"invalid unit name\""
  elif ! systemctl list-unit-files "$unit" --no-legend 2>/dev/null | grep -qF -- "$unit"; then
    absent="${absent:+$absent, }$q"
  elif out=$(systemctl disable --now "$unit" 2>&1); then
    disabled="${disabled:+$disabled, }$q"
  else
    failed="${failed:+$failed, }$q: \"$(json "$out")\""
  fi
done
printf '{"disabled": [%s], "absent": [%s], "failed": {%s}}\n' "$disabled" "$absent" "$failed"

#!/bin/bash
# Runs on the target. Read-only: which desktop/hardware daemons are enabled or running RIGHT NOW.
# Usage: remote.sh [--allow UNIT]... UNIT...
# Prints {"findings": [{"unit","enabled","active"}], "errors": [...]}. A unit that is not installed
# is fine; a unit systemd cannot answer for is an error (the scan is incomplete), never silently clean.
set -u

json() {  # JSON-escape one string
  printf '%s' "$1" | tr -d '\000-\037' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

allow=()
units=()
while [ $# -gt 0 ]; do
  case "$1" in
    --allow) allow+=("$2"); shift 2 ;;
    *) units+=("$1"); shift ;;
  esac
done

if ! command -v systemctl >/dev/null 2>&1; then
  printf '{"findings": [], "errors": ["systemctl not found; cannot inspect services"]}\n'
  exit 0
fi

errf=$(mktemp) || exit 1
trap 'rm -f "$errf"' EXIT
findings=""
errors=""
for unit in "${units[@]}"; do
  skip=0
  for a in "${allow[@]+"${allow[@]}"}"; do [ "$a" = "$unit" ] && skip=1; done
  [ "$skip" = 1 ] && continue
  enabled=$(systemctl is-enabled -- "$unit" 2>"$errf")
  err1=$(cat "$errf")
  active=$(systemctl is-active -- "$unit" 2>"$errf")
  err2=$(cat "$errf")
  if [ -z "$enabled" ] && [[ "$err1" == *"No such file"* ]]; then continue; fi  # not installed
  if [ -z "$enabled" ] && [ -z "$active" ]; then
    msg="$unit: systemctl gave no answer (${err1:-${err2:-empty}})"
    errors="${errors:+$errors, }\"$(json "$msg")\""
    continue
  fi
  case "$enabled" in enabled|enabled-runtime|alias|linked|linked-runtime) hit=1 ;; *) hit=0 ;; esac
  case "$active" in active|activating|reloading) hit=1 ;; esac
  if [ "$hit" = 1 ]; then
    row="{\"unit\": \"$(json "$unit")\", \"enabled\": \"$(json "${enabled:-unknown}")\", \"active\": \"$(json "${active:-unknown}")\"}"
    findings="${findings:+$findings, }$row"
  fi
done
printf '{"findings": [%s], "errors": [%s]}\n' "$findings" "$errors"

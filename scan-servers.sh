#!/usr/bin/env bash
# scan-servers.sh -- run phpaftershell-check.php on several of your servers over
# SSH (CLI mode) and summarise which match the preconditions.
#
# CLI mode reads each server's CLI php.ini, which can differ from its web SAPI;
# treat this as a fast fleet sweep and confirm anything flagged with a real web
# run. Authorised use only -- servers you own or may test.
#
# Usage:
#   ./scan-servers.sh host1 host2 ...
#   ./scan-servers.sh -f hosts.txt            # one "[user@]host[:port]" per line
# Each host is reached with your normal ssh config/keys; nothing is left behind.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$HERE/phpaftershell-check.php"
[[ -f $SCRIPT ]] || { echo "cannot find phpaftershell-check.php next to this script" >&2; exit 2; }

hosts=()
if [[ ${1:-} == -f ]]; then
  [[ -f ${2:-} ]] || { echo "no such host file: ${2:-}" >&2; exit 2; }
  while read -r line; do line=${line%%#*}; line=$(echo "$line" | xargs); [[ -n $line ]] && hosts+=("$line"); done < "$2"
else
  hosts=("$@")
fi
(( ${#hosts[@]} )) || { echo "usage: $0 host1 host2 ... | $0 -f hosts.txt" >&2; exit 2; }

b64=$(base64 -w0 "$SCRIPT" 2>/dev/null || base64 "$SCRIPT" | tr -d '\n')
printf '%-34s %-12s %s\n' HOST PHP VERDICT
printf '%s\n' "$(printf '%.0s-' {1..70})"
fail=0
for h in "${hosts[@]}"; do
  port=22; target=$h
  [[ $h == *:* ]] && { target=${h%:*}; port=${h##*:}; }
  out=$(ssh -o BatchMode=yes -o ConnectTimeout=15 -p "$port" "$target" \
        "command -v php >/dev/null 2>&1 || { echo 'NO-PHP'; exit 0; }; echo '$b64' | base64 -d | php -- " 2>/dev/null) || {
    printf '%-34s %-12s %s\n' "$h" "-" "SSH/RUN ERROR"; fail=1; continue; }
  if [[ $out == NO-PHP* ]]; then
    printf '%-34s %-12s %s\n' "$h" "-" "php not found on PATH"; continue
  fi
  ver=$(sed -n 's/^ PHP  *\([0-9][^ ]*\).*/\1/p' <<<"$out" | head -1)
  verdict=$(sed -n 's/^ VERDICT: //p' <<<"$out" | head -1)
  [[ $verdict == EXPOSED* ]] && fail=1
  printf '%-34s %-12s %s\n' "$h" "${ver:-?}" "${verdict:-no verdict}"
done
exit $fail

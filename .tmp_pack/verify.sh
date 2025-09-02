#!/usr/bin/env bash
set -euo pipefail
echo "Verifying sample receipts..."
fails=0
total=0
mapfile -t RECEIPTS < <(find receipts -maxdepth 2 -type f -name '*.json' ! -name 'sth.json')
shuf -n 5 < <(printf '%s
' "${RECEIPTS[@]}") | while read -r r; do
  if python -m signet_cli verify-receipt "$r" | grep -q 'True'; then
    echo "[OK] $r"
  else
    echo "[FAIL] $r"; fails=$((fails+1))
  fi
  total=$((total+1))
done
if [ -f receipts/$(date +%Y-%m-%d)/sth.json ]; then
  echo "STH present: receipts/$(date +%Y-%m-%d)/sth.json"
fi
echo "Failures: $fails / $total"; [ "$fails" -eq 0 ] && echo PASS || (echo FAIL; exit 1)

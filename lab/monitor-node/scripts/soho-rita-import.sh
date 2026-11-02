#!/usr/bin/env bash
# /usr/local/sbin/soho-rita-import.sh — import kroczący logów Zeeka do wspólnego zbioru RITA.
# Uruchamiany przez rita.timer o *:05 (po godzinnej rotacji Zeeka).
# Importuje katalog wczorajszy i dzisiejszy (UTC): o 00:05 godzina 23 jest jeszcze
# w katalogu wczorajszym. Pliki już zaimportowane RITA pomija (metabaza).
set -euo pipefail
DB=${RITA_DB:-lab}
for d in "$(date -u -d yesterday +%F)" "$(date -u +%F)"; do
  dir=/opt/zeek/logs/$d
  [ -d "$dir" ] || continue
  /usr/local/bin/rita import --database="$DB" --logs="$dir" --rolling || rc=$?
  # "all files were previously imported" kończy się kodem != 0 — nie jest błędem
  if [ "${rc:-0}" -ne 0 ]; then echo "rita import $dir: kod ${rc} (sprawdź log, jeśli nie 'previously imported')"; fi
  unset rc
done

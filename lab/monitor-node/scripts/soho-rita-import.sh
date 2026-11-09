#!/usr/bin/env bash
# /usr/local/sbin/soho-rita-import.sh — import kroczący logów Zeeka do wspólnego zbioru RITA.
# Uruchamiany przez rita.timer o *:05 (po godzinnej rotacji Zeeka).
#
# RITA v5.1.2 zapamiętuje zaimportowane pliki po ścieżce w kontenerze. Wrapper montuje
# katalog --logs zawsze jako /tmp/zeek_logs, więc przy imporcie katalogu dziennego ścieżka
# nie ma daty: conn.18:00:00-19:00:00.log.gz z innego dnia blokował dzisiejszy plik
# o tej samej nazwie i godzina danych przepadała bez błędu (węzeł, 2026-11-08).
# Dlatego archiwa z wczoraj i dziś (UTC; o 00:05 godzina 23 jest w katalogu wczorajszym)
# trafiają do katalogu przejściowego pod ścieżką zawierającą datę:
#   RITA_PATH_MODE=dir   <data>/conn.HH:MM:SS-HH:MM:SS.log.gz   (wymaga odczytu podkatalogów)
#   RITA_PATH_MODE=name  conn.<data>_HH:MM:SS-HH:MM:SS.log.gz
# Pliki już zaimportowane RITA pomija (metabaza). Dodatkowe argumenty trafiają do
# `rita import`, np. jednorazowe --rebuild po zmianie ścieżek.
set -euo pipefail
DB=${RITA_DB:-lab}
MODE=${RITA_PATH_MODE:-dir}
ZEEK_LOGS=${ZEEK_LOGS:-/opt/zeek/logs}
RITA_BIN=${RITA_BIN:-/usr/local/bin/rita}
STAGE_ROOT=${STAGE_ROOT:-/var/tmp}

case "$MODE" in
  dir|name) ;;
  *) echo "RITA_PATH_MODE: oczekiwano dir albo name, jest '$MODE'" >&2; exit 2 ;;
esac

stage=$(mktemp -d "$STAGE_ROOT/soho-rita.XXXXXX")
trap 'rm -rf "$stage"' EXIT

copied=0
for d in "$(date -u -d yesterday +%F)" "$(date -u +%F)"; do
  [ -d "$ZEEK_LOGS/$d" ] || continue
  for f in "$ZEEK_LOGS/$d"/*.log.gz; do
    [ -e "$f" ] || continue
    base=$(basename "$f")
    if [ "$MODE" = dir ]; then
      mkdir -p "$stage/$d"
      cp -p "$f" "$stage/$d/$base"
    else
      cp -p "$f" "$stage/${base%%.*}.${d}_${base#*.}"
    fi
    copied=$((copied + 1))
  done
done
[ "$copied" -gt 0 ] || { echo "brak archiwów Zeeka z wczoraj i dziś w $ZEEK_LOGS"; exit 0; }

rc=0
"$RITA_BIN" import --database="$DB" --logs="$stage" --rolling "$@" || rc=$?
# "all files were previously imported" kończy się kodem != 0 — nie jest błędem
if [ "$rc" -ne 0 ]; then echo "rita import ($copied plików): kod $rc (sprawdź log, jeśli nie 'previously imported')"; fi

#!/usr/bin/env bash
# check-rita-dyn011b.sh — warunki startu i diagnostyka DYN-011b (tylko odczyt, węzeł monitorujący)
# Użycie: sudo TARGET=<adres celu c2-lab> [ROUTER=r1] bash check-rita-dyn011b.sh
# Wyłącznie SELECT kontem soho_agent (hasło z pliku, nie jest wypisywane). Nic nie zmienia
# w RITA, ClickHouse ani w repo instalacji. Na końcu blok `operator_checks:` do zapisania
# w pliku na hoście harnessu i przekazania: python -m harness pair … --operator-checks <plik>.
TARGET="${TARGET:?ustaw TARGET=<adres celu>, np. sudo TARGET=192.0.2.61 bash check-rita-dyn011b.sh}"
ROUTER="${ROUTER:-r1}"
ETC=/etc/soho-guard
SITE=/var/lib/soho-guard/site-lab
RITA_CFG=/etc/rita/config.hjson
DB=lab
[ "$(id -u)" -eq 0 ] || { echo "uruchom: sudo TARGET=<adres> bash $0"; exit 2; }

# adres WAN routera z inwentarza (addressing.wan_address, bywa z maską)
WAN=$(sed -n 's/^[[:space:]]*wan_address:[[:space:]]*"\{0,1\}\([0-9.]*\).*/\1/p' \
      "$SITE/routers/$ROUTER/inventory.yml" | head -1)
[ -n "$WAN" ] || { echo "brak addressing.wan_address w $SITE/routers/$ROUTER/inventory.yml"; exit 2; }

# zapytanie SQL ze stdin → wynik TSV; hasło czyta powłoka soho-agent, nie trafia na wyjście
q() {
  runuser -u soho-agent -- sh -c \
    "curl -sS -u \"soho_agent:\$(cat $ETC/clickhouse_ro)\" --data-binary @- http://127.0.0.1:8123/"
}
pass=0; fail=0
ok()  { printf '  \e[32mPASS\e[0m %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \e[31mFAIL\e[0m %s\n' "$1"; fail=$((fail+1)); }
describe() { echo "     kolumny $1:"; echo "DESCRIBE TABLE $1 FORMAT TSV" | q | cut -f1,2 | sed 's/^/       /'; }

echo "== DYN-011b: $ROUTER (WAN $WAN) → $TARGET, zbiór $DB"

echo "== 1. Konfiguracja beaconu RITA ($RITA_CFG)"
if [ -r "$RITA_CFG" ]; then
  hits=$(grep -nE 'weight|hours_seen|bimodal|unique_connection' "$RITA_CFG")
  if [ -n "$hits" ]; then echo "$hits" | sed 's/^/     /'
  else echo "     brak nadpisań — obowiązują domyślne v5.1.2 (0,25 ×4, dur 6 h, bimodal 11 h)"; fi
else
  echo "     brak $RITA_CFG — sprawdź ręcznie konfigurację RITA"
fi

echo "== 2. Okno zbioru (metadatabase.min_max)"
# okno = cały zbiór (wiersze min_max mogą być per import): min(min_ts) … max(max_ts), max. 24 h
win=$(printf "%s" "SELECT round((toUnixTimestamp(mx) - toUnixTimestamp(greatest(mn, \
mx - INTERVAL 24 HOUR))) / 3600, 2), greatest(mn, mx - INTERVAL 24 HOUR), mx FROM (SELECT \
min(min_ts) AS mn, max(max_ts) AS mx FROM metadatabase.min_max WHERE database = '$DB' AND beacon) \
FORMAT TSV" | q)
echo "     wiersze min_max (ostatnie 5):"
printf "%s" "SELECT min_ts, max_ts FROM metadatabase.min_max WHERE database = '$DB' AND beacon \
ORDER BY max_ts DESC LIMIT 5 FORMAT TSV" | q | sed 's/^/       /'
CONN_SPAN=$(printf "%s" "SELECT min(ts), max(ts) FROM $DB.conn FORMAT TSV" | q)
echo "     zakres $DB.conn (kontrolnie): $CONN_SPAN"
WIN_H=$(printf "%s" "$win" | cut -f1)
if printf "%s" "$WIN_H" | grep -qE '^[0-9.]+$'; then
  echo "     okno: $(printf "%s" "$win" | cut -f2) … $(printf "%s" "$win" | cut -f3) UTC (${WIN_H} h)"
  awk "BEGIN{exit !($WIN_H >= 23)}" && ok "okno zbioru ≥ 23 h" || bad "okno zbioru ${WIN_H} h < 23 h"
else
  bad "odczyt okna nieudany: $(printf "%s" "$win" | head -1)"; describe metadatabase.min_max; WIN_H=
fi

echo "== 3. Ostatni zakończony import (metadatabase.imports)"
AGE_S=$(printf "%s" "SELECT toUnixTimestamp(now()) - toUnixTimestamp(max(ended_at)) \
FROM metadatabase.imports WHERE database = '$DB' AND ended_at > toDateTime(0) FORMAT TSV" | q)
if printf "%s" "$AGE_S" | grep -qE '^[0-9]+$'; then
  echo "     wiek: ${AGE_S} s"
  [ "$AGE_S" -lt 7200 ] && ok "import < 2 h" || bad "import sprzed ${AGE_S} s (≥ 2 h)"
else
  bad "odczyt importu nieudany: $AGE_S"; AGE_S=
fi

echo "== 4. Połączenia $WAN → $TARGET w ostatnich 26 h ($DB.conn) — warunek STARTU (w trakcie przebiegu FAIL oczekiwany)"
CONNS=$(printf "%s" "SELECT count() FROM $DB.conn WHERE IPv6NumToString(src) IN ('::ffff:$WAN', '$WAN') \
AND IPv6NumToString(dst) IN ('::ffff:$TARGET', '$TARGET') AND ts >= now() - INTERVAL 26 HOUR FORMAT TSV" | q)
if printf "%s" "$CONNS" | grep -qE '^[0-9]+$'; then
  echo "     połączeń: $CONNS"
  [ "$CONNS" -eq 0 ] && ok "cel bez historii (para świeża)" || bad "cel ma $CONNS połączeń — wybierz inny adres"
else
  bad "odczyt conn nieudany: $(printf "%s" "$CONNS" | head -1)"; describe "$DB.conn"; CONNS=
fi

echo "== 5. Diagnostyka w trakcie przebiegu: najnowsza ocena pary ($DB.threat_mixtape)"
# HTTP: RITA zapisuje parę jako beacon `sni` — cel w fqdn/server_ips, dst pusty (jak czyta agent)
diag=$(printf "%s" "SELECT analyzed_at, beacon_type, beacon_score, ts_score, ds_score, dur_score, \
hist_score, count, last_seen FROM $DB.threat_mixtape WHERE IPv6NumToString(src) IN ('::ffff:$WAN', '$WAN') \
AND (IPv6NumToString(dst) IN ('::ffff:$TARGET', '$TARGET') OR fqdn = '$TARGET' \
OR has(arrayMap(x -> IPv6NumToString(x), server_ips), '::ffff:$TARGET')) \
ORDER BY analyzed_at DESC, beacon_score DESC LIMIT 1 FORMAT TSVWithNames" | q)
if printf "%s" "$diag" | head -1 | grep -q beacon_score; then
  if [ "$(printf "%s\n" "$diag" | wc -l)" -lt 2 ]; then echo "     brak oceny pary (przed startem: oczekiwane)"
  else printf "%s\n" "$diag" | column -t -s "$(printf '\t')" | sed 's/^/     /'; fi
else
  echo "     odczyt nieudany: $(printf "%s" "$diag" | head -1)"; describe "$DB.threat_mixtape"
fi

echo; echo "PASS: $pass   FAIL: $fail"
echo
echo "# --- zapisz poniższy blok na hoście harnessu (np. checks-$(date -u +%Y%m%dT%H%MZ).yml) ---"
echo "operator_checks:"
echo "  checked_at: \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\""
echo "  target: \"$TARGET\""
echo "  wan: \"$WAN\""
echo "  dataset_window_h: ${WIN_H:-null}"
echo "  import_age_s: ${AGE_S:-null}"
echo "  target_conns_26h: ${CONNS:-null}"
[ "$fail" -eq 0 ]

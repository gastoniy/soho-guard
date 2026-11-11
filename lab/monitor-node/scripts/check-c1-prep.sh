#!/usr/bin/env bash
# check-c1-prep.sh — kontrola węzła monitorującego (tylko odczyt): przygotowanie i praca agenta po C1
# Użycie: sudo LOGIN=<login-github> [MODE=main|test] bash check-c1-prep.sh
#   MODE=main (domyślnie): timery publikują na main, bez drop-inu test-branch.conf
#   MODE=test: timery na test/* przez drop-in (test RC, decyzja 2026-11-11)
# Sieć: git push --dry-run przez R1 i R2, zapytanie OTX przez R1. Nie wypisuje sekretów.
LOGIN="${LOGIN:?ustaw LOGIN=<login GitHub>, np. sudo LOGIN=jan bash check-c1-prep.sh}"
SITE=/var/lib/soho-guard/site-lab
ETC=/etc/soho-guard
MODE="${MODE:-main}"
case "$MODE" in main|test) ;; *) echo "MODE musi być main albo test"; exit 2;; esac
NODE=/opt/soho-guard/app/lab/monitor-node
DROPIN=/etc/systemd/system/agent@.service.d/test-branch.conf
A="runuser -u soho-agent --"
GH_FP="SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"
pass=0; fail=0
ok()  { printf '  \e[32mPASS\e[0m %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \e[31mFAIL\e[0m %s\n' "$1"; fail=$((fail+1)); }
chk() { if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }
perm(){ [ "$(stat -c '%a %U %G' "$1" 2>/dev/null)" = "$2" ]; }
[ "$(id -u)" -eq 0 ] || { echo "uruchom: sudo LOGIN=<login> bash $0"; exit 2; }

echo "== Wdrożenie kodu"
chk "app to dowiązanie do releases/"           '[ -L /opt/soho-guard/app ] && readlink -f /opt/soho-guard/app | grep -q "^/opt/soho-guard/releases/"'
echo "     -> $(readlink -f /opt/soho-guard/app 2>/dev/null)"
chk "kod tylko do odczytu dla agenta"          '! $A test -w /opt/soho-guard/app/tools'
chk "venv: librouteros, yaml, jsonschema, netmiko" '$A /opt/soho-guard/venv/bin/python -c "import librouteros, yaml, jsonschema, netmiko"'
chk "soho-deploy.sh zainstalowany"             '[ -x /usr/local/sbin/soho-deploy.sh ]'

echo "== Sekrety i konfiguracja"
chk "/etc/soho-guard: 751 root soho-agent"     'perm $ETC "751 root soho-agent"'
chk "ca.crt: 644 root"                         'perm $ETC/ca.crt "644 root root"'
chk "deploy_key: 600 soho-agent, poprawny"     'perm $ETC/deploy_key "600 soho-agent soho-agent" && $A ssh-keygen -y -f $ETC/deploy_key'
chk "clickhouse_ro: 600 soho-agent"            'perm $ETC/clickhouse_ro "600 soho-agent soho-agent"'
chk "ti.env: 600 soho-agent, OTX_API_KEY"      'perm $ETC/ti.env "600 soho-agent soho-agent" && grep -q "^OTX_API_KEY=." $ETC/ti.env'
for r in r1 r2; do
  chk "$r/: 700 soho-agent"                    "perm $ETC/$r '700 soho-agent soho-agent'"
  for f in monitor.pass remediate.pass monitor_rsa; do
    chk "$r/$f: 600, niepusty"                 "[ -s $ETC/$r/$f ] && [ \$(stat -c %a $ETC/$r/$f) = 600 ] && [ \$(stat -c %U $ETC/$r/$f) = soho-agent ]"
  done
done
chk "brak sekretów w ~ubuntu"                  '! grep -rlE "BEGIN (RSA |OPENSSH |ENCRYPTED )?PRIVATE KEY" /home/ubuntu 2>/dev/null | grep -v "/\."'

echo "== Routery: TLS i logowanie API"
for p in "r1 10.100.1.1" "r2 10.100.2.1"; do set -- $p
  chk "$1: api-ssl, certyfikat zweryfikowany CA" "$A openssl s_client -connect $2:8729 -CAfile $ETC/ca.crt -verify_return_error </dev/null 2>&1 | grep -q 'Verify return code: 0'"
  chk "$1: login monitor przez api-ssl"        "$A /opt/soho-guard/venv/bin/python - <<PY
import ssl, functools
from librouteros import connect
ctx = ssl.create_default_context(cafile='$ETC/ca.crt')
api = connect(username='monitor', password=open('$ETC/$1/monitor.pass').read().strip(), host='$2', port=8729,
              ssl_wrapper=functools.partial(ctx.wrap_socket, server_hostname='$2'))
list(api.path('system','identity'))
PY"
done

echo "== Repozytorium instalacji"
chk "known_hosts: odcisk GitHub ed25519"       "$A ssh-keygen -lf /var/lib/soho-guard/.ssh/known_hosts | grep -q '$GH_FP'"
chk "klon site-lab istnieje (soho-agent)"      "[ -d $SITE/.git ] && [ \$(stat -c %U $SITE) = soho-agent ]"
chk "remote = $LOGIN/soho-guard-site-lab"      "$A git -C $SITE remote get-url origin | grep -q '$LOGIN/soho-guard-site-lab'"
chk "git user.name/email ustawione"            "$A git -C $SITE config user.name && $A git -C $SITE config user.email"
chk "site.yml i routers/r1, r2 w klonie"       "[ -f $SITE/site.yml ] && [ -f $SITE/routers/r1/inventory.yml ] && [ -f $SITE/routers/r2/inventory.yml ]"
for p in "r1 10.100.1.10" "r2 10.100.2.10"; do set -- $p
  chk "push --dry-run przez $1 ($2), z flock"  "cd $SITE && $A flock -w 30 /var/lib/soho-guard/site-lab.lock env GIT_SSH_COMMAND='ssh -b $2 -i $ETC/deploy_key -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/var/lib/soho-guard/.ssh/known_hosts' git push --dry-run origin main"
done

echo "== Zeek"
chk "zeek.service enabled"                     'systemctl is-enabled zeek'
chk "zeekctl: running"                         '/opt/zeek/bin/zeekctl status | grep -q running'
chk "soho-agent w grupie zeek"                 'id -nG soho-agent | grep -qw zeek'
chk "agent czyta current/conn.log"             '$A test -r /opt/zeek/logs/current/conn.log'
chk "agent czyta archiwum dzisiejsze"          '$A sh -c "ls /opt/zeek/logs/$(date -u +%F)/conn.*.log.gz >/dev/null"'
chk "capture-loss w local.zeek"                'grep -q "^@load misc/capture-loss" /opt/zeek/share/zeek/site/local.zeek'
chk "capture_loss.log świeży (< 30 min)"       '$A find /opt/zeek/logs/current/capture_loss.log -mmin -30 | grep -q .'

echo "== ClickHouse / RITA"
chk "port 8123 tylko na 127.0.0.1"             'ss -tlnH "sport = :8123" | grep -q "127.0.0.1:8123" && ! ss -tlnH "sport = :8123" | grep -qE "0\.0\.0\.0:8123|\[::\]:8123"'
chk "soho_agent: odczyt działa"                "$A sh -c 'curl -sf -u \"soho_agent:\$(cat $ETC/clickhouse_ro)\" \"http://127.0.0.1:8123/?query=SELECT+1\"' | grep -q '^1'"
chk "soho_agent: zapis odrzucony (readonly)"   "$A sh -c 'curl -s -u \"soho_agent:\$(cat $ETC/clickhouse_ro)\" http://127.0.0.1:8123/ --data \"CREATE TABLE default.x (a UInt8) ENGINE=Memory\"' | grep -qi readonly"
chk "default bez hasła odrzucony"              '! curl -sf "http://127.0.0.1:8123/?query=SELECT+1" | grep -q "^1"'
chk "rita.timer enabled + active"              'systemctl is-enabled rita.timer && systemctl is-active rita.timer'
chk "rita.service: ostatni przebieg OK"        '[ "$(systemctl show -p Result --value rita.service)" = success ]'
chk "zbiór RITA lab istnieje"                  'rita list 2>/dev/null | grep -qw lab'
chk "soho-rita-import.sh zainstalowany"        '[ -x /usr/local/sbin/soho-rita-import.sh ]'

echo "== Jednostki i skrypty węzła zgodne z wdrożonym wydaniem (tryb $MODE)"
# Zainstalowana kopia musi być identyczna z plikiem z /opt/soho-guard/app (v0.7.0: stara jednostka bez --trigger timer).
for p in "systemd/agent@.service /etc/systemd/system/agent@.service" \
         "systemd/agent@.timer /etc/systemd/system/agent@.timer" \
         "systemd/rita.service /etc/systemd/system/rita.service" \
         "systemd/rita.timer /etc/systemd/system/rita.timer" \
         "systemd/zeek.service /etc/systemd/system/zeek.service" \
         "scripts/soho-deploy.sh /usr/local/sbin/soho-deploy.sh" \
         "scripts/soho-rita-import.sh /usr/local/sbin/soho-rita-import.sh" \
         "tmpfiles.d/soho-guard.conf /etc/tmpfiles.d/soho-guard.conf"; do set -- $p
  chk "$2 = wydanie"                           "cmp -s $NODE/$1 $2"
done
EXEC='systemctl show -p ExecStart --value agent@r1.service'
for r in r1 r2; do
  chk "agent@$r.timer enabled + active"        "systemctl is-enabled agent@$r.timer && systemctl is-active agent@$r.timer"
done
chk "ExecStart: --trigger timer, bez --dry-run/--no-remediate" "$EXEC | grep -q -- '--trigger timer' && ! $EXEC | grep -qE -- '--dry-run|--no-remediate'"
if [ "$MODE" = test ]; then
  chk "drop-in test-branch.conf = wydanie"     "cmp -s $NODE/systemd/agent@.service.d/test-branch.conf $DROPIN"
  chk "ExecStart: --publish-branch test/"      "$EXEC | grep -q -- '--publish-branch test/'"
else
  chk "brak drop-inu test-branch.conf"         "[ ! -e $DROPIN ]"
  chk "ExecStart: publikacja na main"          "! $EXEC | grep -q -- '--publish-branch'"
fi

echo "== L3, syslog, firewall"
chk "OTX API klucz ważny (przez R1)"           "curl -sf --interface 10.100.1.10 -H \"X-OTX-API-KEY: \$(sed -n 's/^OTX_API_KEY=//p' $ETC/ti.env)\" https://otx.alienvault.com/api/v1/user/me"
for r in r1 r2; do
  chk "syslog $r: wpis z ostatnich 24 h"       "[ -n \"\$(find /var/log/soho-guard/$r.log -mmin -1440 2>/dev/null)\" ]"
done
chk "nftables: drop-in ExecStop"               'systemctl cat nftables | grep -q "delete table inet filter"'
chk "Docker MASQUERADE obecny"                 'iptables -t nat -S POSTROUTING | grep -q MASQUERADE'

echo; echo "PASS: $pass   FAIL: $fail"
[ "$fail" -eq 0 ]

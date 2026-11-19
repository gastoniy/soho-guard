# Changelog

Format: `vMAJOR.MINOR.PATCH-lab` (0.x — kontrakt może się zmieniać). Opublikowanych tagów nie przesuwa się ani nie usuwa.

## [v0.8.0-lab] — 2026-11-19
Zamrożenie repozytorium przed kampanią końcową pracy dyplomowej. Agent i polityka bez zmian
względem `v0.7.1-lab`; węzeł monitorujący pozostaje na `v0.7.1-lab` (bez wdrożenia tego taga).

### Dodane
- Plany kampanii końcowej `harness/campaigns/static-final-r2.yml` i `static-final-r1.yml`: pełny reset routera na starcie, POL-004, POL-005, POL-006, SITE-007 i SITE-008 ×3 na każdym routerze (POL-003 pominięty — ma n = 11 i n = 14), BEN-002 ×1, na r1 na końcu BEN-001 (H8). Kolejność: r2, potem r1 (r1 dopiero po rozwiązaniu findingu `policy.dynamic.beacon`).
- Harness, iteracja 5 — skoordynowany przebieg pary DYN-011b + CTL-001 (`harness/pair.py`): `python -m harness pair <dyn-manifest> <ctl-manifest> [--offset S] [--seed N] [--close-artifacts] [--operator-checks F]` oraz krok pary w planie kampanii (`control:`, `repeat: 1`), plan `harness/campaigns/dyn-011b.yml`. Ruch okresowy z klienta za r1 (D-B1) sterowany ręcznie przez operatora — sterownik `generate.from: client` prosi w terminalu o start (`t0` = potwierdzenie) i stop (teardown, także po błędzie i Ctrl-C); konfiguracja r1 bez zmian, brak efektów ubocznych L1. DYN-011b (r1) oceniany na detekcję `policy.dynamic.beacon`, CTL-001 (r2) na brak findingu od startu do pierwszego commitu stanu r2 ≥ 2 cykle po wykryciu na r1 (D-B4). Werdykt pary = najgorsze z ramion; wynik `<run_id>-pair-<dyn>-<ctl>.json` (`results.write_pair`), `summary` daje wiersz na ramię. Warunki startu z węzła (`operator_checks`: okno zbioru RITA ≥ 23 h, import < 2 h, 0 połączeń WAN → cel w 26 h, odczyt ≤ 3 h przed startem; naruszenie = `invalid`) z nowego skryptu tylko do odczytu `lab/monitor-node/scripts/check-rita-dyn011b.sh`, który pokazuje też składowe `beacon_score` pary w trakcie przebiegu. Teardown: stop ruchu → pełny reset wg `teardown.reset` manifestów → czekanie na rozwiązanie findingu na r1 (D-B5). DYN-011b: `apply: none`, `generate.from: client`, budżet 50 400 s (D-B2, wyprowadzenie z krzywej `beacon_score` RITA v5.1.2 w manifeście). Nowy klucz `harness.yml`: `resolve_timeouts` (nadpisanie `timing.resolve_timeout_s` per id manifestu, DYN-011b: 93 600 s — patrz „Znane ograniczenia i korekty”); `endpoints.<nazwa>` odrzuca nieznane klucze.
- Harness, iteracja 4 — krok ruchowy (`harness/generate.py`) i DYN-011a (ścieżka szybka, rozbieżność L1 vs L2). Sterownik `router` (D-E): ruch generuje sam router pingiem do c2-lab (`count=1200 interval=1s`), uruchomionym w tle przez `:execute` (SSH, konto ansible) — bez śladu w konfiguracji; `t0` = start pingu (`generate.t0_marker`). Cel z puli adresów `endpoints.<nazwa>.addresses` w harness.yml; kolejne powtórzenia biorą kolejny adres (H8: inny cel). Playbook `playbooks/dynamic/covert-icmp.yml` (apply: reguła `/ip firewall raw chain=output action=notrack` dla ICMP do celu; revert: usunięcie po komentarzu). Teardown dynamiczny (H4): revert + pełny reset + czekanie na rozwiązanie findingu do `timing.resolve_timeout_s` (`teardown.reset`, `teardown.resolved`). Zadeklarowane efekty uboczne (`local.drift.firewall-raw`) zapisywane w `side_effects` bez zmiany werdyktu, a przy `--close-artifacts` ich PR też są zamykane (H9). Plan `harness/campaigns/dyn-011a.yml` (DYN-011a ×3 na r1). Nowe klucze konfiguracji: `endpoints`, `timing.resolve_timeout_s`.
- Harness, iteracja 3 — kampania: `python -m harness campaign <plan.yml> [--seed N] [--check]` (`harness/campaign.py`), plany w `harness/campaigns/` (`static-pol003.yml`: POL-003 ×10 na r2 i r1 z resetem na starcie; `static-new.yml`: nowe manifesty). Walidacja planu (nieznane i zduplikowane klucze, manifesty, routery, przesunięcia, okna H10), ostrzeżenia kolejności H8, losowe przesunięcie per przebieg z ziarnem kampanii, `campaign` w wyniku każdego przebiegu, wynik zbiorczy `<run_id>-campaign-<id>.json` zapisywany po każdym przebiegu, log kampanii i logi przebiegów. Przerwanie (kod 3): nieudany reset, `invalid`/`error`, Ctrl-C; niezgodna bramka po teardownie → pełny reset i dalej (niezgodna po resecie → przerwanie); `fail`/`timeout` → kod 1.
- Zestawienie: `python -m harness summary <wyniki|katalog|kampania.json>... [--csv F] [--agg-csv F]` (`harness/summary.py`) — Markdown z agregatami per manifest × router (n, werdykty, MTTD min/mediana/p90/max/średnia, mediany czasu do powiadomienia, do naprawy i okna; czasy tylko z `pass`) i wierszem na przebieg; bez konfiguracji i dostępu do labu.
- Manifesty POL-004 (`policy-proxy-enabled.yml`, `/ip proxy`), POL-005 (`policy-api-plain-enabled.yml`, `/ip service api`), SITE-008 (`site-user-add.yml`, nowy użytkownik na r1 → `local.drift.users`, `pr-alert`), BEN-001 (`benign-background.yml`, `apply: none`). Playbooki `policy/proxy-enabled.yml`, `policy/api-plain-enabled.yml`, `policy/winbox-public.yml` (POL-006; revert przywraca adres sprzed apply z `probe_pre`), `site/user-add.yml` (konto wyłączone, grupa `read`, hasło losowane, `no_log`). Zmiany przez `api_find_and_modify` (tylko podane pola).
- Przebieg `apply: none` (BEN-001): `t0` = zaplanowany moment H10, bez odczytu obiektu, teardown = sama bramka (`teardown.revert: skipped`). Playbooki dostają `probe_pre` (odczyt obiektu przed apply). Sondy: `NONEMPTY` (baseline zależny od routera), oczekiwane `""` przyjmuje brak pola.
- Harness, iteracja 3 — pełny reset (H4): `python -m harness reset <router> --yes` i `harness/reset.py` + `playbooks/common/reset.yml`. Zbiór plików do wgrania wyznaczany z `baseline.rsc.j2` w site-lab i porównywany z `routers.<id>.upload` w `harness.yml` (sprawdzane tylko istnienie plików); render baseline (host_vars z site-lab, Vault, `baseline_rev` = SHA, 0600, `no_log`) i `scp -O` tuż przed resetem, `shred` wyrenderowanego pliku w `always` (plus zabezpieczenie w Pythonie); komplet plików na routerze przed resetem, inaczej usunięcie ich z routera bez resetu; reset przez SSH o `:X0 + timing.reset_offset_s` (40 s); usunięcie wpisu z `ssh.known_hosts`, powrót MGMT = odczyt api-ssl i brak plików resetu (skrypt baseline doszedł do końca) do `mgmt_return_timeout_s`, nowy klucz hosta (`accept-new`; RouterOS 6 generuje klucz hosta dopiero przy pierwszej próbie SSH po starcie, a każda kolejna próba zaczyna generowanie od nowa — ponawianie co `timing.ssh_retry_s` = 150 s do `timing.ssh_ready_timeout_s` = 600 s od powrotu api-ssl; w wyniku `timing.ssh_ready_s`) z odciskiem w wyniku, bramka H5. Wynik `<run_id>-reset-<router>.json` i log; kod 0 albo 3. Nowe klucze konfiguracji: `build_dir`, `ssh.known_hosts`, `ssh.scp_bin`, `ssh.keygen_bin`, `routers.<id>.upload`, `timing.reset_offset_s`, `timing.mgmt_poll_s`, `timing.ssh_retry_s`, `timing.ssh_ready_timeout_s`; zduplikowany klucz w `harness.yml` jest błędem konfiguracji.
- Harness, iteracja 2 — bramka H5 (`harness/gate.py`): `/export terse hide-sensitive` przez SSH (konto `ansible`, `-F <ssh_config>`) porównany z `routers/<id>/export.rsc` — pomijany tylko nagłówek, `#error exporting` dosłownie — oraz `/user`, `/user ssh-keys`, `/certificate`, `/file` (pola stabilne) porównane z nowym wzorcem `routers/<id>/gate-objects.yml` w site-lab. Wzorzec: `python -m harness gate <router> --dump-objects`, wnoszony PR-em operatora (jak `export.rsc`). CLI `gate <router>` (0 zgodna, 3 niezgodna).
- Przebieg: bramka przed apply (niezgodna → `invalid`), teardown `--tags revert` + bramka; nieudany teardown nie zmienia werdyktu scenariusza (`teardown.ok = false`), CLI kończy się kodem 3 i przerywa powtórzenia.
- Okno H10 dla scenariuszy bez detekcji: apply ok. 12 min przed przewidywanym heartbeatem (`timing.heartbeat_lead_s`), zamknięcie na pierwszym commicie stanu z `run_seq` ≥ +2, którego przebieg jest co najmniej drugim cyklem po `t0` (`window.closing_cycles_after_t0`; przewidywany jest najwcześniejszy możliwy heartbeat), oracle na raportach z okna, maksimum `windows.<klasa>` → `timeout`.
- Warunki wstępne H8 z czekaniem do `timing.precondition_wait_s` (np. przy `--repeat` po SITE-007) i ponowną kontrolą tuż przed apply.
- Artefakty H9: numery PR (`agent/<router>/<run_id>`) i issue (ścieżka raportu) przez `gh` tylko do odczytu, `artifact_missing` bez zmiany werdyktu; `--close-artifacts` zamyka wyłącznie artefakty z przebiegu (komentarz `harness <run_id>`, bez usuwania gałęzi).
- Playbooki `benign/add-allowed-firewall-comment.yml` (BEN-002), `site/ppp-secret-add.yml` (SITE-007, hasło losowane, `no_log`); `common/read.yml` czyta kilka menu w jednym przebiegu.
- Log przebiegu `<run_id>.log` obok wyniku JSON (znaczniki w UTC; oczekiwanie na warunki wstępne logowane tylko przy zmianie); w wyniku `gate_before`, `teardown.gate`, `window`, `artifacts`.
- Harness, iteracja 1 (`harness/`, `playbooks/`): `python -m harness run <manifest> [--target R] [--repeat N] [--offset S] [--seed N]` dla scenariuszy wykrywanych z krokiem `apply`. Przebieg: warunki wstępne H8 ze stanu w site-lab (`invalid` przy niespełnieniu) → odczyt obiektu w baseline → apply w losowym momencie poza oknem `:X0…:X0+30 s` → `t0` = potwierdzenie zmiany odczytem `community.routeros.api_info` (api-ssl, CA) → czekanie na raport z regułą `new` (budżet MTTD + 120 s, `timeout`) → `oracle_eval` + MTTD/czas do powiadomienia/czas do naprawy (H11) + `end_state` własnym odczytem → `--tags revert` → wynik JSON w `harness/results/` (H7). Kody wyjścia 0/1/2/3.
- Playbooki: `common/read.yml` (odczyt menu do JSON), `policy/socks-enabled.yml` (POL-003, apply + `revert`); hasło konta `ansible` wyłącznie z pliku Vault routera, zadania z połączeniem `no_log`.
- `requirements-harness.txt` (`ansible-core==2.21.6`, `librouteros==4.2.2`, `pyyaml`, `jsonschema`), `playbooks/requirements.yml` (`community.routeros` 3.23.0), wzorzec konfiguracji `harness/harness.example.yml`.
- Testy harnessu na atrapach (`tests/test_harness.py`): repo Git w `tmp_path`, atrapa Ansible i `ansible-playbook`, zegar testowy.
- Manifest POL-006 (`scenarios/policy/policy-winbox-public.yml`): Winbox bez ograniczenia adresu, reguła uniwersalna bez `remediate` — `action: none`, `end_state: unchanged` (D-A).

### Zmienione
- Bramka H5: diff `/export` porównywany per menu — linie grupowane po ścieżce menu (linie `#` w jednej grupie), treść i kolejność wewnątrz menu nadal dosłownie (kolejność reguł firewalla/NAT/raw wykrywana), pomijana tylko kolejność samych menu w eksporcie. Powód (lab 2026-11-18): RouterOS 7 kilka minut po pierwszej dzierżawie DHCP przestawia blok `/ip dhcp-server` w eksporcie bez zmiany konfiguracji, co dawało fałszywą niezgodność bramki r1 przy aktywnym kliencie za routerem. Różnice raportowane jako `@@ <menu> @@` + linie `-`/`+`; wzorce `export.rsc` w site-lab bez zmian.
- `scenario.schema.json`: enum `generate.from` rozszerzony o `router` (ruch z samego routera, DYN-011a/D-E); zmiana addytywna, manifesty bez zmiany `schema_version`. DYN-011a: `generate.from: router`, playbook `covert-icmp.yml`.
- `harness.yml`: wymagana sekcja `ssh.config`; nowe `artifacts`, `windows`, `timing.precondition_wait_s`, `timing.heartbeat_lead_s`.
- Nieudany `revert` nie zamienia już werdyktu na `error` (decyzja 2026-11-14).
- `manifest_lint.py`: klasa `policy` dopuszcza parę `action: none` + `end_state: unchanged` obok `auto-remediate` + `baseline`; pary krzyżowe są błędem. Schemat `scenario.schema.json` bez zmian.
- Budżet MTTD scenariuszy POL/SITE: 420 s (cykl 300 s + odczyt L1 + zapas) — POL-003, SITE-007, POL-006.
- SITE-007 = **nowy** sekret PPP poza inwentarzem (H6), playbook `playbooks/site/ppp-secret-add.yml`; zmiana samego hasła nie jest driftem (D6a) i nie ma scenariusza na labie.
- `.gitignore`: `harness.yml` (lokalna konfiguracja harnessu) i jawnie `harness/results/`.

### Wyniki labu
Z `python -m harness summary harness/results/` (47 wierszy przebiegów, 2026-11-14…19; MTTD tylko z `pass`, w s).
Wszystkie przebiegi z drzewa `69493b7…-dirty` (iteracje 1–5).

| manifest | router | n | pass | invalid | error | MTTD min | MTTD mediana | MTTD max | budżet |
|---|---|---|---|---|---|---|---|---|---|
| POL-003 | r2 | 14 | 14 | 0 | 0 | 98,9 | 161,8 | 268,6 | 420 |
| POL-003 | r1 | 11 | 11 | 0 | 0 | 80,6 | 164,9 | 270,0 | 420 |
| POL-004 | r2 | 1 | 1 | 0 | 0 | 139,8 | 139,8 | 139,8 | 420 |
| POL-005 | r2 | 1 | 1 | 0 | 0 | 124,2 | 124,2 | 124,2 | 420 |
| POL-006 | r2 | 1 | 1 | 0 | 0 | 130,8 | 130,8 | 130,8 | 420 |
| SITE-007 | r2 | 2 | 2 | 0 | 0 | 110,6 | 163,0 | 215,3 | 420 |
| SITE-007 | r1 | 1 | 1 | 0 | 0 | 112,9 | 112,9 | 112,9 | 420 |
| SITE-008 | r1 | 1 | 1 | 0 | 0 | 137,4 | 137,4 | 137,4 | 420 |
| BEN-001 | r1 | 1 | 1 | 0 | 0 | — | — | — | okno 725,7 |
| BEN-002 | r2 | 1 | 1 | 0 | 0 | — | — | — | okno 503,6 |
| BEN-002 | r1 | 1 | 1 | 0 | 0 | — | — | — | okno 853,9 |
| DYN-011a | r1 | 4 | 4 | 0 | 0 | 1305,7 | 1338,1 | 1382,2 | 3600 |
| DYN-011b | r1 | 4 | 1 | 2 | 1 | 35 126,6 | 35 126,6 | 35 126,6 | 50 400 |
| CTL-001 | r2 | 4 | 1 | 2 | 1 | — | — | — | — |

- DYN-011b + CTL-001 `pass` (para `h20261118T181608Z-5b8467`, kampania `dyn-011b`): `beacon_score` 0,707 po 10 godzinnych przedziałach, kontrola na r2 czysta. Pozostałe próby pary: 2× `invalid` (bramka niezgodna przed apply — obiekty 2026-11-17; przestawiony `/ip dhcp-server` w eksporcie v7 2026-11-18, stąd bramka per menu), 1× `error` (przerwanie operatora 2026-11-17, wariant ze schedulerem r1, starsza wersja manifestu).
- Teardown pary `ok: false`: finding nierozwiązany w 9000 s (patrz niżej). Werdykt bez zmian.

### Znane ograniczenia i korekty
- **D-B5 skorygowane:** finding RITA (`policy.dynamic.beacon`) wygasa ok. 24 h 05 min – 25 h 15 min po ustaniu beaconu, a nie ok. 2 h 10 min. RITA v5.1.2 w danym imporcie analizuje tylko pary z nowymi połączeniami (`filtered_hashes`), więc ostatnia ocena pary obowiązuje, dopóki `last_seen ≥ max_ts − 24 h`. W tym czasie `posture: compromise-suspected` i naprawy na routerze są wstrzymane. `harness.example.yml`: `resolve_timeouts.DYN-011b: 93600`.
- Komentarze w `scenarios/dynamic/dynamic-c2-beacon.yml` wyprowadzają budżet z ok. 11 h beaconu i podają rozwiązanie findingu po ok. 2 h 10 min (`resolve_timeouts ≥ 9000`); zmierzone wykrycie to 9,8 h (10 przedziałów, rozpoczęta godzina liczy się jako przedział). Manifest pozostawiony bez zmian ze względu na `sha256` zapisany w wynikach.
- Przebiegi iteracji 1–5 wykonano z niezacommitowanego drzewa (`harness_commit: 69493b7…-dirty`). Stan kodu odpowiada temu tagowi; po starcie przebiegu DYN-011b (2026-11-18 18:16 UTC) zmieniono w repo tylko diagnostykę `lab/monitor-node/scripts/check-rita-dyn011b.sh` (sekcja 5, odczyt par `sni`) oraz komentarze/przykłady opisane w tej sekcji.
- Agent i polityka bez zmian względem `v0.7.1-lab` (`git diff v0.7.1-lab -- agent/ policy/` pusty); węzeł pozostaje na `v0.7.1-lab`.

## [v0.7.1-lab] — 2026-11-11
### Zmienione
- Komunikat commita agenta i linia podsumowania pokazują `posture` raportu i stanu, gdy się różnią (naprawa potwierdzona w cyklu, brak danych z routera): `agent(r2): raport policy-violation, stan no-violations, …`, na konsoli `posture=<stan> (raport: <raport>)`. Bez różnicy format bez zmian.
- `check-c1-prep.sh` jako kontrola węzła po C1: porównanie zainstalowanych jednostek (`agent@`, `rita`, `zeek`), skryptów (`soho-deploy.sh`, `soho-rita-import.sh`) i `tmpfiles.d` z wdrożonym wydaniem; timery `agent@r1`, `agent@r2` włączone, `ExecStart` z `--trigger timer`; `MODE=main` (bez drop-inu, publikacja na `main`) lub `MODE=test` (drop-in `test-branch.conf`, `--publish-branch test/`). Usunięta kontrola „timery wyłączone (przed C1)”. Świeżość `capture_loss` liczona także z archiwum ostatniej godziny (po rotacji `current/capture_loss.log` nie istnieje do następnego pomiaru).

## [v0.7.0-lab] — 2026-11-11
### Dodane
- Agent, iteracja 6: samokontrola czujników L2 (`agent/selfcheck.py`). Wynik obniża pokrycie i nigdy nie tworzy ani nie rozwiązuje findingu:
  - `current/conn.log` bez zapisu ponad 15 min (`selfcheck.zeek-stale`) albo brak ruchu routera w oknie 60 min (`selfcheck.no-router-traffic`): reguły Zeeka nieocenione, L2 `degraded`;
  - utrata pakietów na mirrorze z `capture_loss.log` powyżej 1% albo brak pomiaru z ostatnich 30 min (`selfcheck.capture-loss`): L2 `degraded`; wpis z mniej niż 500 potwierdzeniami TCP tylko jako uwaga;
  - `wan_address` nieobecny w `/ip/address` routera albo klient DHCP na interfejsie WAN (`selfcheck.wan-mismatch`): atrybucja niepewna, cała L2 (Zeek i RITA) `unavailable`.
- Retencja danych lokalnych: `lab/monitor-node/tmpfiles.d/soho-guard.conf` (dowody 30 dni, `orphaned/` 7 dni; `systemd-tmpfiles`).
- Wzorzec `lab/monitor-node/systemd/agent@.service.d/test-branch.conf`: timery w trybie pełnym na `test/timers` przed przejściem na `main`.
- Zeek w labie: `lab/monitor-node/zeek/local.zeek.fragment` (`@load misc/capture-loss`) dla samokontroli utraty pakietów; `check-c1-prep.sh` sprawdza wpis i świeżość `capture_loss.log`.
### Zmienione
- `collection.l2.note` łączy uwagi obniżające status z informacyjnymi (te drugie nie zmieniają `ok`).

## [v0.6.0-lab] — 2026-11-09
### Dodane
- Agent, iteracja 5: `policy.dynamic.beacon` z wyników RITA (ClickHouse `lab.threat_mixtape`): najnowsza ocena każdej pary z `last_seen` w oknie danych ostatniego importu, a w obrębie jednej analizy najwyższy wynik (RITA zapisuje dla pary kilka wierszy naraz, np. modyfikatory z wynikiem 0 i wiersz `sni`), tak jak `rita view` (import zapisuje tylko pary przeliczone w nim, więc sam ostatni import bywa pusty). Co cykl zapytanie o ostatni import, beacony tylko po nowym; wynik lokalnie w `rita.json`, więc finding trwa do kolejnego importu. Wynik `beacon_score` > `score_max` poza `beaconing.allowed_periodic` daje finding (alert).
- `allowed_periodic`: `dst` jako `*`, adres, CIDR albo nazwa; nazwa z FQDN RITA lub z odpowiedzi DNS w `dns.log` z ostatnich 60 min (także poddomeny). Każda para proto/port beaconu musi mieć wpis.
- Warstwa L3: OTX dla celów findingów rozbieżności, beaconu i resolvera spoza listy (bez adresów prywatnych). Wynik w `evidence.l3_corroboration`; `malicious`/`suspicious` dopisuje `L3` do `trust.corroborated_by`. Zapytanie z adresu źródłowego routera, timeout 10 s, cache 24 h (`ti-cache.json`); klucz z `/etc/soho-guard/ti.env`.
- Kody błędów `l2.rita-failed`, `l3.lookup-failed`. Awaria RITA lub TI nie tworzy ani nie rozwiązuje findingów.
### Zmienione
- `collection.l2`: `ok` (źródła `zeek`, `rita`), gdy Zeek jest czytelny, a ostatni import RITA ma najwyżej 2 h; inaczej `degraded` z powodem. Czysty router może mieć `no-violations` i pokrycie `full`.
- `collection.l3`: status OTX zamiast stałego `unavailable`.
- `policy_lint.py --dynamic` sprawdza postać `allowed_periodic.dst`.
### Poprawione
- `soho-rita-import.sh`: RITA v5.1.2 rozpoznaje zaimportowane pliki po ścieżce w kontenerze (`/tmp/zeek_logs/<plik>`, bez daty), więc plik godzinowy o nazwie znanej z innego dnia był pomijany bez błędu i godzina danych przepadała. Archiwa z wczoraj i dziś trafiają teraz do katalogu przejściowego pod ścieżką z datą (`RITA_PATH_MODE=dir`: podkatalog `<data>/`, `name`: data w nazwie pliku), jednym wywołaniem importu. Skrypt instaluje się ręcznie z wdrożonego wydania; po instalacji jednorazowo `soho-rita-import.sh --rebuild` (zbiór `lab` budowany od nowa, bez duplikatów godzin).

## [v0.5.0-lab] — 2026-11-08
### Dodane
- Agent, iteracja 4: warstwa L2 z logów Zeeka (`conn.log`, `dns.log`) z mirrora WAN, przypisanie po `addressing.wan_address` bez maski. Każdy cykl ocenia od nowa ostatnie 60 min (bez kursora), więc finding znika po godzinie bez zdarzeń.
- `integrity.divergence.connections`: 3 próbki `/ip/firewall/connection` co 5 s w cyklu, przechowywane lokalnie przez 60 min bez adresów LAN. Dowodem jest tylko przepływ zestawiony i trwający w chwili próbki; finding po brakach w co najmniej 3 różnych cyklach i bez trafienia celu w oknie. Przy wyłączonym śledzeniu połączeń reguła nie jest oceniana.
- `policy.dynamic.rogue-resolver` (resolver spoza `dns.allowed_resolvers`) i `policy.dynamic.dga` (finding na resolver; nazwy domen tylko w dowodzie lokalnym `ev:<run_id>/zeek`). Wyjątki DGA: opcjonalne `dns.allowed_suffixes` w `dynamic-baseline.yml`; `.arpa` pomijane.
- Kody błędów `l2.read-failed`, `l2.attribution-unavailable`, `l1.connections-failed`, `dynamic-baseline.invalid`. Awaria czujnika obniża pokrycie i nie tworzy findingu.
- Otwarty wskaźnik kompromitacji wstrzymuje naprawy w cyklu (`auto-remediate/skipped`), także na `test/*`.
- Kontrakt baseline'u dynamicznego: `schemas/dynamic-baseline.schema.json` (ścisły dla `dns` i `beaconing`), `policy_lint.py --dynamic`, przykład `examples/dynamic-baseline.yml`. Agent sprawdza plik i zgodność `router_id`; błąd daje `dynamic-baseline.invalid`, a reguły korzystające z pliku nie są oceniane.
- Migawka: `/ip/firewall/raw` i `/ip/firewall/mangle` (`local.drift.firewall-raw`, `local.drift.firewall-mangle`). Reguła `notrack` ukrywa sesję w tablicy połączeń, a `mangle` może skierować ruch inną trasą. Po wdrożeniu dopisać `firewall_raw: []` i `firewall_mangle: []` do `baseline-state.yml` (zasób spoza baseline nie jest oceniany).
- Brak `current/conn.log` (np. po `zeekctl stop`) to `l2.read-failed`: puste okno nie rozwiązuje findingów L2.
### Zmienione
- `policy.dynamic.dga`: `assert` z `min_label_length: 12` i `min_distinct: 3`.
- `collection.l2`: `degraded` ze źródłem `zeek` i oknem, dopóki nie ma RITA; pokrycie pozostaje `partial`.

## [v0.4.0-lab] — 2026-11-07
### Dodane
- Agent, iteracja 3: tryb pełny (bez `--dry-run` i `--no-remediate`), z `--publish-branch test/<nazwa>` lub na `main`. Reguły uniwersalne bez IOC z `remediate` są naprawiane kontem `remediate` i weryfikowane odczytem kontem `monitor`. Jedna próba, bez ponawiania.
- Drift: agent wypycha gałąź `agent/<router>/<run_id>` z propozycją `baseline-state.yml`, a PR otwiera workflow repo instalacji. Jeden PR na cykl. `external_ref` to odnośnik `compare`.
- Alert: raport z akcją `alert` dostaje status `succeeded` po zapisie do publikacji (nie oznacza to doręczenia), a workflow repo instalacji tworzy z niego issue.
- Kody błędów `act.remediate-failed` i `act.pr-failed`.
- Na `main` naprawa jest wstrzymana (`skipped`), gdy `site.yml` wskazuje inną wersję polityki niż wdrożona.
### Zmienione
- `policy.services.cloud-ddns.disabled` bez `remediate`: wartość `no` jest niepoprawna na v7. Akcja to teraz `none/skipped`.
- Reguły `rules` polityki lokalnej dostają `alert`, drift pozostaje `open-pr`.
- Raport jest walidowany (R10) także przed akcjami, żeby router nie zmienił się w przebiegu z niepoprawnym dokumentem.
- Migawka v7 bez wierszy-gniazd z `/ip/service` (`proto` bez `address`, np. `dhcp`, `ntp`, włączony `socks`): to stan działania, a nie konfiguracja. Włączony SOCKS dawał dodatkowy, fałszywy drift i błędny PR. Wiersze w istniejącym `baseline-state.yml` są pomijane przy wczytaniu. Nowe gniazdo nie jest driftem, tak jak dotąd na v6.
- Podsumowanie cyklu: licznik `naprawione=`.
- Migawka bez `next-run` i `run-count` (`/system/scheduler`, `/system/script`): stan wykonania zadania. Zaakceptowane zadanie dawało nowy drift po każdym uruchomieniu. Wartości w istniejącym `baseline-state.yml` są pomijane przy wczytaniu.

## [v0.3.0-lab] — 2026-11-07
### Dodane
- Agent, iteracja 2: publikacja do repo instalacji (`--no-remediate`, opcjonalnie `--publish-branch test/<nazwa>`). Raport przy zdarzeniu (R3), stan przy zmianie lub co `interval_s` (R9, heartbeat). Bez flag agent nadal kończy się błędem: remediacja powstaje w iteracji 3.
- Niewysłane dane czekają w lokalnym outboxie (`/var/lib/soho-guard/publish/<gałąź>/<router>/`), a commit powstaje dopiero przy publikacji, w tymczasowym worktree. Dane routera wychodzą wyłącznie przez jego łącze.
- Kody błędów `publish.sync-failed` i `publish.push-failed`; po utracie danych lokalnych łańcuch raportów jest kontynuowany z opublikowanego stanu.
### Zmienione
- `--no-remediate`: `evaluation_mode: enforce`, `auto-remediate` ma status `skipped`, a `open-pr` i `alert` status `proposed`.
- Oczekiwanie na blokadę klonu `site-lab` jest ograniczone czasowo (45 s).

## [v0.2.0-lab] — 2026-11-06
### Zmienione
- Schemat raportu, R5: w trybie what-if akcja może mieć status `proposed` lub `skipped` (rozszerzenie zgodne wstecz); nadal żadna nie może być wykonana.
- Onboarding: `verify_against_policy` korzysta z ewaluatora agenta; naruszenie zgłaszane per obiekt.
- Normalizacja stanu wydzielona do `agent/normalize.py`, wspólna dla agenta i onboardingu (bez zmiany zachowania).
- Scenariusz BEN-002: plik `benign-firewall-comment.yml` (było `benign-add-user-vlan.yml`), nazwa zgodna z playbookiem.
- `policyVersion` przyjmuje tagi `vX.Y.Z-lab` i `vX.Y.Z-lab.rcN` (rozszerzenie zgodne wstecz).
- `inventory.yml`: nowe `addressing.mgmt_address` i `addressing.agent_source`; `local_policy` to ścieżka do ręcznego `routers/<id>/local-policy.yml` zamiast listy.
- Migawka konfiguracji: dochodzi `/ppp/secret`; wartości tajne są pomijane (zmiana samego hasła nie jest driftem), `expires-after` jest ulotne. Po wdrożeniu odświeżyć `baseline-state.yml`.
### Dodane
- Agent, iteracja 1 (`python -m agent --router <id> --once --dry-run`): odczyt L1 przez api-ssl z weryfikacją CA, faza statyczna (polityka uniwersalna, reguły lokalne, drift), findingi, plan akcji R8, raport i stan z walidacją R10. Działa wyłącznie `--dry-run`: zapis lokalny, bez publikacji i bez zmian na routerze.
- `agent@.service`: `--trigger timer`.
- Kontrakt polityki lokalnej: `schemas/local-policy.schema.json`, `policy_lint.py --local`, przykład `examples/local-policy.yml`. Polityka lokalna może tylko zaostrzać politykę uniwersalną.
- `soho-deploy.sh` zapisuje plik `RELEASE` (tag, commit) w katalogu wydania.
- Onboarding: `--baseline-only` zapisuje wyłącznie `baseline-state.yml`.
### Poprawione
- Predykat `private`: każdy wpis listy adresów musi być prywatny. Wcześniej przechodziło np. `10.0.0.0/8,0.0.0.0/0` i publiczne `172.2.0.0/16`.
- Walidator R6: `preshared-key` (WireGuard) wymaga redakcji.
- Onboarding: domyślny `--out-dir` to `./routers` (było `./sites`).
- Migawka bez stanu synchronizacji NTP i portu efemerycznego wewnętrznego gniazda `log` z `/ip/service` (v7): dawały fałszywy drift.
- `policy.dynamic.rogue-resolver`: `allowed_from` jako odwołanie logiczne `dynamic-baseline#dns.allowed_resolvers` zamiast nieaktualnej ścieżki `sites/{id}/…` (plik wskazuje `inventory.yml` → `dynamic_baseline`).
- Onboarding bez `--router-id`: `dynamic_baseline` = `routers/CHANGE_ME/dynamic-baseline.yml` zamiast `sites/<site_id>/…`.
- `report.schema.json`: opis wskazuje `tools/validate_report.py` (było `validate.py`).

## [v0.1.2-lab] -- 2026-11-02
### Zmienione
- `inventory.yml`: wersja polityki wyłącznie w `site.yml` repozytorium instalacji; onboarding wpisuje `policy.universal_version_source: site.yml` (pole informacyjne).
### Dodane
- `lab/monitor-node/scripts/check-c1-prep.sh` — kontrola przygotowania węzła (`LOGIN` ze zmiennej środowiskowej).

## [v0.1.1-lab] — 2026-11-01
- Jednostki systemd (`rita`, `agent@`), `soho-rita-import.sh`, `soho-deploy.sh`, opcja `--ssh-key` w onboardingu.

## [v0.1.0-lab] — 2026-11-01
- Import początkowy: schematy, polityka uniwersalna, narzędzia, scenariusze, testy, konfiguracja labu (stan po etapach 1–4).

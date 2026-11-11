# Changelog

Format: `vMAJOR.MINOR.PATCH-lab` (0.x — kontrakt może się zmieniać). Opublikowanych tagów nie przesuwa się ani nie usuwa.

## [Unreleased]

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

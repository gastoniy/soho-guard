# Changelog

Format: `vMAJOR.MINOR.PATCH-lab` (0.x — kontrakt może się zmieniać). Opublikowanych tagów nie przesuwa się ani nie usuwa.

## [Unreleased]
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

# Changelog

Format: `vMAJOR.MINOR.PATCH-lab` (0.x — kontrakt może się zmieniać). Opublikowanych tagów nie przesuwa się ani nie usuwa.

## [Unreleased]

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

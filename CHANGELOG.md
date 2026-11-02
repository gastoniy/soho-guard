# Changelog

Format: `vMAJOR.MINOR.PATCH-lab` (0.x — kontrakt może się zmieniać). Opublikowanych tagów nie przesuwa się ani nie usuwa.

## [Unreleased]
### Zmienione
- `inventory.yml`: wersja polityki wyłącznie w `site.yml` repozytorium instalacji; onboarding wpisuje `policy.universal_version_source: site.yml` (pole informacyjne).
### Dodane
- `lab/monitor-node/scripts/check-c1-prep.sh` — kontrola przygotowania węzła (`LOGIN` ze zmiennej środowiskowej).

## [v0.1.1-lab] — 2026-11-01
- Jednostki systemd (`rita`, `agent@`), `soho-rita-import.sh`, `soho-deploy.sh`, opcja `--ssh-key` w onboardingu.

## [v0.1.0-lab] — 2026-11-01
- Import początkowy: schematy, polityka uniwersalna, narzędzia, scenariusze, testy, konfiguracja labu (stan po etapach 1–4).

# soho-guard

System monitorowania bezpieczeństwa routerów SOHO (MikroTik RouterOS) w podejściu GitOps —
repozytorium publiczne: polityka uniwersalna, schematy kontraktów, narzędzia, scenariusze testów,
konfiguracja labu, kod agenta.

| Katalog | Zawartość |
|---|---|
| `schemas/` | JSON Schema: raport, stan, scenariusz, polityka (`common` = wspólny słownik) |
| `policy/` | polityka uniwersalna (`static/`, `dynamic/`) — wersja = tag repozytorium |
| `tools/` | onboarding fazy 0', walidator raportów, lintery, oracle, kontrola sekretów w `.rsc` |
| `scenarios/` | manifesty scenariuszy testowych wg klasy |
| `examples/`, `tests/` | przykładowe raporty/stan, testy kontraktów (`pytest`) |
| `agent/` | kod agenta (etap 6) |
| `lab/` | konfiguracja labu GNS3: OVS, węzeł monitorujący, klienci tła |

Dane instalacji (inwentarz, wzorzec, szablon baseline) są w repozytorium instalacji `soho-guard-site-<site_id>` (jedno na instalację, routery w `routers/<id>/`).
**Sekrety nigdy nie trafiają do repozytorium** — patrz `.gitignore`, `pre-commit` (gitleaks + `check_rsc_secrets.py`).

    pip install -r requirements-dev.txt && pre-commit install
    python3 -m pytest tests -q

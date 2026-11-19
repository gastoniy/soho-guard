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

## Harness scenariuszy

`harness/` (runner, Python 3.12) i `playbooks/` (Ansible) uruchamiają manifesty z `scenarios/` wobec
routerów labu i oceniają wynik agenta odczytany z repozytorium instalacji. Harness działa na osobnym
hoście, nigdy na węźle monitorującym; konfiguracja lokalna `harness.yml` (wzorzec
`harness/harness.example.yml`) i sekrety (Ansible Vault) leżą poza repozytorium.

    pip install -r requirements-harness.txt
    ansible-galaxy collection install -r playbooks/requirements.yml
    H=(--config /path/to/harness.yml)
    python -m harness "${H[@]}" run scenarios/policy/policy-socks-enabled.yml [--target r1] [--repeat N]
    python -m harness "${H[@]}" pair <dynamic.yml> <control.yml> [--operator-checks F]
    python -m harness "${H[@]}" campaign harness/campaigns/<plan>.yml [--check]
    python -m harness "${H[@]}" reset <router> --yes
    python -m harness "${H[@]}" gate <router>
    python -m harness summary /path/to/results/ [--csv F]

Wyniki (JSON i log na przebieg) trafiają do `harness/results/` (ignorowany przez Git).

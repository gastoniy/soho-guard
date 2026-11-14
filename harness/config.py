"""Konfiguracja harnessu z lokalnego `harness.yml` (`--config`, `$SOHO_HARNESS_CONFIG`
albo `harness/harness.yml` w repo, objęty `.gitignore`); wzorzec: `harness/harness.example.yml`.

Plik zawiera wyłącznie adresy i ścieżki — nigdy wartości sekretów. Sekrety trafiają do Ansible
przez `-e @<plik Vault>` i `--vault-password-file`; harness ich nie odczytuje.
Klucze nieznane w tej iteracji (np. pliki do wgrania przed resetem) są pomijane.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import REPO_ROOT, UsageError

DEFAULT_PATH = REPO_ROOT / "harness" / "harness.yml"     # w .gitignore
ENV_VAR = "SOHO_HARNESS_CONFIG"


@dataclass(frozen=True)
class RouterCfg:
    router_id: str
    mgmt_address: str
    vault_file: Path
    api_port: int = 8729
    mgmt_return_timeout_s: int = 300


@dataclass(frozen=True)
class TimingCfg:
    cycle_s: int = 300              # agent@<router>.timer: OnCalendar=*:0/5
    avoid_window_s: int = 30        # odczyt L1 :X0…:X0+15 s + zapas — tu nie robimy apply
    apply_margin_s: int = 60        # apply + odczyt potwierdzający muszą się zmieścić przed :X0
    poll_interval_s: int = 30       # odpytywanie site-lab (git fetch)
    report_grace_s: int = 120       # po budżecie MTTD: publikacja raportu i push


@dataclass(frozen=True)
class Config:
    path: Path
    site_lab_clone: Path
    site_lab_remote: str
    site_lab_branch: str
    inventory: Path
    vault_password_file: Path
    ca_path: Path
    results_dir: Path
    routers: dict[str, RouterCfg]
    timing: TimingCfg = field(default_factory=TimingCfg)
    ansible_playbook: str = "ansible-playbook"
    ansible_timeout_s: int = 300

    def router(self, router_id: str) -> RouterCfg:
        try:
            return self.routers[router_id]
        except KeyError:
            raise UsageError(f"router '{router_id}' nieobecny w {self.path} (routers:)") from None


def _p(v: str, base: Path) -> Path:
    p = Path(os.path.expanduser(str(v)))
    return p if p.is_absolute() else (base / p)


def _req(d: dict, key: str, where: str):
    if not isinstance(d, dict) or key not in d or d[key] in (None, ""):
        raise UsageError(f"harness.yml: brak klucza {where}{key}")
    return d[key]


def resolve_path(cli_path: str | None) -> Path:
    raw = cli_path or os.environ.get(ENV_VAR) or str(DEFAULT_PATH)
    return Path(os.path.expanduser(raw))


def load(path: Path) -> Config:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as e:
        raise UsageError(f"nie można odczytać konfiguracji {path}: {e}") from None
    except yaml.YAMLError as e:
        raise UsageError(f"błędny YAML w {path}: {e}") from None
    if not isinstance(doc, dict):
        raise UsageError(f"{path}: oczekiwano mapy YAML")

    base = path.parent
    sl = _req(doc, "site_lab", "")
    an = _req(doc, "ansible", "")
    routers_doc = _req(doc, "routers", "")
    if not isinstance(routers_doc, dict) or not routers_doc:
        raise UsageError("harness.yml: routers musi być niepustą mapą <router_id>: {...}")

    routers = {}
    for rid, r in routers_doc.items():
        w = f"routers.{rid}."
        routers[rid] = RouterCfg(
            router_id=rid,
            mgmt_address=str(_req(r, "mgmt_address", w)),
            vault_file=_p(_req(r, "vault_file", w), base),
            api_port=int(r.get("api_port", 8729)),
            mgmt_return_timeout_s=int(r.get("mgmt_return_timeout_s", 300)),
        )

    t = doc.get("timing") or {}
    known = TimingCfg.__dataclass_fields__
    unknown = sorted(set(t) - set(known))
    if unknown:
        raise UsageError(f"harness.yml: nieznane klucze timing: {unknown}")
    timing = TimingCfg(**{k: int(v) for k, v in t.items()})
    if not 0 < timing.avoid_window_s < timing.cycle_s - timing.apply_margin_s:
        raise UsageError("harness.yml: wymagane 0 < avoid_window_s < cycle_s - apply_margin_s")

    return Config(
        path=path,
        site_lab_clone=_p(_req(sl, "clone", "site_lab."), base),
        site_lab_remote=str(sl.get("remote", "origin")),
        site_lab_branch=str(sl.get("branch", "main")),
        inventory=_p(_req(an, "inventory", "ansible."), base),
        vault_password_file=_p(_req(an, "vault_password_file", "ansible."), base),
        ansible_playbook=str(an.get("playbook_bin", "ansible-playbook")),
        ansible_timeout_s=int(an.get("timeout_s", 300)),
        ca_path=_p(_req(doc, "ca_path", ""), base),
        results_dir=_p(doc.get("results_dir", REPO_ROOT / "harness" / "results"), base),
        routers=routers,
        timing=timing,
    )

"""Konfiguracja harnessu z lokalnego `harness.yml` (`--config`, `$SOHO_HARNESS_CONFIG`
albo `harness/harness.yml` w repo, objęty `.gitignore`); wzorzec: `harness/harness.example.yml`.

Plik zawiera wyłącznie adresy i ścieżki — nigdy wartości sekretów. Sekrety trafiają do Ansible
przez `-e @<plik Vault>` i `--vault-password-file`; harness ich nie odczytuje.
Nieznane klucze w sekcjach `timing`, `windows` i `artifacts` są błędem. Pełny reset (H4) wymaga
dodatkowo `build_dir`, `ssh.known_hosts` i per router `upload` (plik lokalny → stała nazwa na routerze);
harness sprawdza tylko istnienie tych plików, treść czyta wyłącznie `scp`.
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
    # pełny reset: nazwa na routerze (stała, importuje ją baseline.rsc.j2) → plik lokalny;
    # baseline.rsc nie występuje — harness renderuje go sam
    upload: dict[str, Path] = field(default_factory=dict)


@dataclass(frozen=True)
class TimingCfg:
    cycle_s: int = 300              # agent@<router>.timer: OnCalendar=*:0/5
    avoid_window_s: int = 30        # odczyt L1 :X0…:X0+15 s + zapas — tu nie robimy apply
    apply_margin_s: int = 60        # apply + odczyt potwierdzający muszą się zmieścić przed :X0
    poll_interval_s: int = 30       # odpytywanie site-lab (git fetch)
    report_grace_s: int = 120       # po budżecie MTTD: publikacja raportu i push
    precondition_wait_s: int = 900  # H8: czekanie na spełnienie warunków wstępnych (np. przy --repeat)
    heartbeat_lead_s: int = 720     # H10: apply ok. 12 min przed przewidywanym heartbeatem
    reset_offset_s: int = 40        # H4: pełny reset po odczycie L1 (kalibracja: :X0+40 s)
    mgmt_poll_s: int = 10           # odpytywanie routera po resecie
    ssh_retry_s: int = 150          # RouterOS 6: każda próba SSH restartuje generowanie klucza hosta
    ssh_ready_timeout_s: int = 600  # gotowość SSH liczona od powrotu api-ssl
    resolve_timeout_s: int = 5400   # dynamic: czekanie na rozwiązanie findingu po pełnym resecie (okno 60 min + cykle)


@dataclass(frozen=True)
class ArtifactsCfg:
    timeout_s: int = 300            # agent-actions: start 3–5 s po commicie, koniec maks. ~122 s
    poll_s: int = 15


# H10: maksymalna długość okna „brak findingu” per klasa scenariusza [s od t0]
DEFAULT_WINDOWS = {"benign": 2700, "control": 2700}


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
    ssh_config: Path | None = None
    ssh_known_hosts: Path | None = None     # osobny known_hosts harnessu (H4)
    build_dir: Path | None = None           # wyrenderowany baseline (usuwany zaraz po wgraniu)
    timing: TimingCfg = field(default_factory=TimingCfg)
    artifacts: ArtifactsCfg = field(default_factory=ArtifactsCfg)
    windows: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_WINDOWS))
    ansible_playbook: str = "ansible-playbook"
    ansible_timeout_s: int = 300
    ssh_bin: str = "ssh"
    ssh_timeout_s: int = 120
    scp_bin: str = "scp"
    keygen_bin: str = "ssh-keygen"
    gh_bin: str = "gh"
    # krok ruchowy (generate): endpoint → pula adresów (np. c2-lab na Kali); kolejne powtórzenia
    # biorą kolejny adres (H8: inny cel). Same adresy, nigdy w repo (harness.yml jest w .gitignore).
    endpoints: dict[str, tuple[str, ...]] = field(default_factory=dict)
    # nadpisanie timing.resolve_timeout_s per id manifestu (np. DYN-011b, D-B5: finding RITA znika
    # ok. 24–25 h po ostatnim połączeniu (okno zbioru RITA 24 h); w tym czasie naprawy na r1 są
    # wstrzymane) — bez zmiany schematu manifestu
    resolve_timeouts: dict[str, int] = field(default_factory=dict)

    def router(self, router_id: str) -> RouterCfg:
        try:
            return self.routers[router_id]
        except KeyError:
            raise UsageError(f"router '{router_id}' nieobecny w {self.path} (routers:)") from None

    def endpoint(self, name: str) -> tuple[str, ...]:
        addrs = self.endpoints.get(name)
        if not addrs:
            raise UsageError(f"harness.yml: brak endpoints.{name}.addresses (krok generate)")
        return addrs

    def resolve_timeout(self, manifest_id: str) -> int:
        return self.resolve_timeouts.get(manifest_id, self.timing.resolve_timeout_s)


def _p(v: str, base: Path) -> Path:
    p = Path(os.path.expanduser(str(v)))
    return p if p.is_absolute() else (base / p)


def _req(d: dict, key: str, where: str):
    if not isinstance(d, dict) or key not in d or d[key] in (None, ""):
        raise UsageError(f"harness.yml: brak klucza {where}{key}")
    return d[key]


def _section(doc: dict, name: str, cls):
    sec = doc.get(name) or {}
    unknown = sorted(set(sec) - set(cls.__dataclass_fields__))
    if unknown:
        raise UsageError(f"harness.yml: nieznane klucze {name}: {unknown}")
    return cls(**{k: int(v) for k, v in sec.items()})


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader odrzucający zduplikowane klucze (PyYAML domyślnie bierze ostatni bez ostrzeżenia,
    np. drugi blok `routers:` po cichu zastępuje pierwszy)."""


def _construct_mapping(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, f"zduplikowany klucz '{key}'", key_node.start_mark)
        seen.add(key)
    return loader.construct_mapping(node, deep=deep)


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def load_yaml_unique(text: str):
    """yaml.safe_load z odrzucaniem zduplikowanych kluczy (harness.yml, plany kampanii)."""
    return yaml.load(text, Loader=_UniqueKeyLoader)


def resolve_path(cli_path: str | None) -> Path:
    raw = cli_path or os.environ.get(ENV_VAR) or str(DEFAULT_PATH)
    return Path(os.path.expanduser(raw))


def load(path: Path) -> Config:
    try:
        doc = load_yaml_unique(path.read_text(encoding="utf-8"))
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
        up = r.get("upload") or {}
        if not isinstance(up, dict) or any(not isinstance(k, str) or "/" in k for k in up):
            raise UsageError(f"harness.yml: {w}upload musi być mapą <nazwa na routerze>: <plik>")
        if "baseline.rsc" in up:
            raise UsageError(f"harness.yml: {w}upload: baseline.rsc renderuje harness — usuń wpis")
        routers[rid] = RouterCfg(
            router_id=rid,
            mgmt_address=str(_req(r, "mgmt_address", w)),
            vault_file=_p(_req(r, "vault_file", w), base),
            api_port=int(r.get("api_port", 8729)),
            mgmt_return_timeout_s=int(r.get("mgmt_return_timeout_s", 300)),
            upload={k: _p(v, base) for k, v in up.items()},
        )

    timing = _section(doc, "timing", TimingCfg)
    if not 0 < timing.avoid_window_s < timing.cycle_s - timing.apply_margin_s:
        raise UsageError("harness.yml: wymagane 0 < avoid_window_s < cycle_s - apply_margin_s")
    windows = dict(DEFAULT_WINDOWS)
    w = doc.get("windows") or {}
    unknown = sorted(set(w) - set(DEFAULT_WINDOWS))
    if unknown:
        raise UsageError(f"harness.yml: nieznane klucze windows: {unknown}")
    windows.update({k: int(v) for k, v in w.items()})

    endpoints = {}
    for name, ep in (doc.get("endpoints") or {}).items():
        unknown = sorted(set(ep or {}) - {"addresses"})
        if unknown:
            raise UsageError(f"harness.yml: nieznane klucze endpoints.{name}: {unknown}")
        addrs = (ep or {}).get("addresses")
        if not isinstance(addrs, list) or not addrs or any(not isinstance(a, str) for a in addrs):
            raise UsageError(f"harness.yml: endpoints.{name}.addresses musi być niepustą listą adresów")
        endpoints[str(name)] = tuple(str(a) for a in addrs)

    rt = doc.get("resolve_timeouts") or {}
    if not isinstance(rt, dict) or any(not isinstance(v, int) or isinstance(v, bool) or v <= 0
                                       for v in rt.values()):
        raise UsageError("harness.yml: resolve_timeouts musi być mapą <id manifestu>: <s> (> 0)")

    ssh = _req(doc, "ssh", "")

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
        ssh_config=_p(_req(ssh, "config", "ssh."), base),
        ssh_bin=str(ssh.get("bin", "ssh")),
        ssh_timeout_s=int(ssh.get("timeout_s", 120)),
        ssh_known_hosts=_p(ssh["known_hosts"], base) if ssh.get("known_hosts") else None,
        scp_bin=str(ssh.get("scp_bin", "scp")),
        keygen_bin=str(ssh.get("keygen_bin", "ssh-keygen")),
        build_dir=_p(doc["build_dir"], base) if doc.get("build_dir") else None,
        gh_bin=str((doc.get("github") or {}).get("bin", "gh")),
        artifacts=_section(doc, "artifacts", ArtifactsCfg),
        windows=windows,
        results_dir=_p(doc.get("results_dir", REPO_ROOT / "harness" / "results"), base),
        routers=routers,
        timing=timing,
        endpoints=endpoints,
        resolve_timeouts={str(k): int(v) for k, v in rt.items()},
    )

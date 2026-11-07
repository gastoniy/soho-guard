"""Konfiguracja przebiegu: site.yml, inventory.yml, baseline, plik RELEASE, ścieżki."""
from __future__ import annotations

import fcntl
import hashlib
import ipaddress
import re
import subprocess
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from agent.normalize import build_state

ROUTER_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
RELEASE_TAG = re.compile(r"^v([0-9]+\.[0-9]+\.[0-9]+)(-lab(\.rc[0-9]+)?)?$")
PROFILES = ("ros6", "ros7")
LOCK_WAIT_S = 45


class ConfigError(Exception):
    """Konfiguracja nie pozwala rozpocząć przebiegu."""


class LockTimeout(ConfigError):
    """Drugi przebieg zbyt długo trzyma blokadę klonu."""


@dataclass(frozen=True)
class Paths:
    app_dir: Path = Path("/opt/soho-guard/app")
    etc_dir: Path = Path("/etc/soho-guard")
    data_dir: Path = Path("/var/lib/soho-guard")
    site_dir: Path = Path("/var/lib/soho-guard/site-lab")

    @property
    def policy_dir(self) -> Path:
        return self.app_dir / "policy"

    @property
    def site_lock(self) -> Path:
        return self.data_dir / "site-lab.lock"

    @property
    def deploy_key(self) -> Path:
        return self.etc_dir / "deploy_key"

    @property
    def known_hosts(self) -> Path:
        return self.data_dir / ".ssh" / "known_hosts"


@dataclass
class Context:
    router_id: str
    site_id: str
    profile: str
    mgmt_address: str
    agent_source: str
    interval_s: int
    universal_pin: str
    release_tag: str
    release_commit: str
    agent_version: str
    local_commit: str
    local_digest: str
    local_policy_path: Path
    baseline: dict
    baseline_rel: str
    paths: Paths
    config_errors: list[tuple[str, str]] = field(default_factory=list)
    trigger: str = "manual"


@contextmanager
def site_lock(paths: Paths):
    """Wspólny klon repo instalacji: odczyt i git pod jedną blokadą (r1 i r2)."""
    paths.site_lock.parent.mkdir(parents=True, exist_ok=True)
    with open(paths.site_lock, "a", encoding="utf-8") as handle:
        deadline = time.monotonic() + LOCK_WAIT_S
        while True:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    raise LockTimeout(f"blokada {paths.site_lock} zajęta dłużej niż {LOCK_WAIT_S} s") from exc
                time.sleep(0.2)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def read_release(app_dir: Path) -> tuple[str, str, str]:
    """Plik RELEASE zapisuje soho-deploy.sh. Zwraca tag, commit, agent_version."""
    path = app_dir / "RELEASE"
    try:
        pairs = dict(line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines() if "=" in line)
    except OSError as exc:
        raise ConfigError(f"brak pliku RELEASE ({path}): uruchamiaj wdrożone wydanie") from exc
    tag, commit = pairs.get("tag", ""), pairs.get("commit", "")
    match = RELEASE_TAG.match(tag)
    if not match:
        raise ConfigError(f"RELEASE: niepoprawny tag {tag!r}")
    if not re.fullmatch(r"[0-9a-f]{7,40}", commit):
        raise ConfigError(f"RELEASE: niepoprawny commit {commit!r}")
    return tag, commit, match.group(1)


def _load_yaml(path: Path) -> dict:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"nie można odczytać {path}: {exc}") from exc
    if not isinstance(doc, dict):
        raise ConfigError(f"{path}: oczekiwano mapowania YAML")
    return doc


def _head_commit(site_dir: Path) -> str:
    try:
        out = subprocess.run(["git", "-C", str(site_dir), "rev-parse", "HEAD"],
                             check=True, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ConfigError(f"nie można odczytać commitu repo instalacji {site_dir}") from exc
    return out.stdout.strip()


def _ip(inventory_path: Path, addressing: dict, name: str) -> str:
    value = addressing.get(name)
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ConfigError(f"{inventory_path}: addressing.{name} musi być adresem IP, jest {value!r}") from exc
    return value


def _file_digest(*paths: Path) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.read_bytes() if path.exists() else b"\0missing\0")
    return digest.hexdigest()


def load_context(router_id: str, paths: Paths) -> Context:
    if not ROUTER_ID.match(router_id):
        raise ConfigError(f"niepoprawny identyfikator routera {router_id!r}")
    tag, commit, version = read_release(paths.app_dir)

    with site_lock(paths):
        site = _load_yaml(paths.site_dir / "site.yml")
        entry = next((r for r in site.get("routers", []) if r.get("router_id") == router_id), None)
        if entry is None:
            raise ConfigError(f"router {router_id} nie występuje w site.yml")
        router_dir = paths.site_dir / entry.get("path", f"routers/{router_id}")
        inventory_path = router_dir / "inventory.yml"
        inventory = _load_yaml(inventory_path)
        local_commit = _head_commit(paths.site_dir)

        baseline_path = router_dir / "baseline-state.yml"
        config_errors: list[tuple[str, str]] = []
        try:
            baseline = build_state(_load_yaml(baseline_path))
        except ConfigError as exc:
            baseline = {}
            config_errors.append(("baseline.invalid", str(exc)))
        local_ref = inventory.get("local_policy")
        local_path = paths.site_dir / local_ref if isinstance(local_ref, str) else router_dir / "local-policy.yml"
        digest = _file_digest(baseline_path, local_path)

    profile = inventory.get("profile")
    if profile not in PROFILES:
        raise ConfigError(f"{inventory_path}: profile musi być jednym z {PROFILES}, jest {profile!r}")
    addressing = inventory.get("addressing") or {}
    site_policy = site.get("policy") or {}
    try:
        interval = int((site.get("heartbeat") or {}).get("interval_s", 1800))
    except (TypeError, ValueError) as exc:
        raise ConfigError("site.yml: heartbeat.interval_s musi być liczbą") from exc

    return Context(
        router_id=router_id,
        site_id=site.get("site_id", ""),
        profile=profile,
        mgmt_address=_ip(inventory_path, addressing, "mgmt_address"),
        agent_source=_ip(inventory_path, addressing, "agent_source"),
        interval_s=interval,
        universal_pin=site_policy.get("universal_version", ""),
        release_tag=tag,
        release_commit=commit,
        agent_version=version,
        local_commit=local_commit,
        local_digest=digest,
        local_policy_path=local_path,
        baseline=baseline,
        baseline_rel=baseline_path.relative_to(paths.site_dir).as_posix(),
        paths=paths,
        config_errors=config_errors,
    )

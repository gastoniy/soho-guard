"""Odczyt wyniku agenta z repo instalacji (`soho-guard-site-lab`), wyłącznie przez Gita, tylko odczyt.

Harness robi `git fetch` klonu na hoście i czyta pliki z commitów zdalnej gałęzi (`git show`);
drzewo robocze klonu nie jest zmieniane. `state/` i `reports/` pisze wyłącznie agent.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

import yaml

from . import HarnessError
from .timing import parse_ts

Runner = Callable[..., subprocess.CompletedProcess]


@dataclass(frozen=True)
class ReportRef:
    path: str
    commit: str
    committed_at: datetime


@dataclass(frozen=True)
class Detection:
    ref: ReportRef
    report: dict
    finding: dict


class SiteLab:
    def __init__(self, clone: Path, remote: str = "origin", branch: str = "main",
                 runner: Runner = subprocess.run):
        self.clone = clone
        self.ref = f"{remote}/{branch}"
        self.remote = remote
        self.branch = branch
        self._run = runner

    def _git(self, *args: str) -> str:
        cmd = ["git", "-C", str(self.clone), *args]
        p = self._run(cmd, capture_output=True, text=True)
        if p.returncode != 0:
            raise HarnessError(f"git {' '.join(args[:2])}: {p.stderr.strip()[:500]}")
        return p.stdout

    # --- odczyt ---
    def fetch(self) -> str:
        """`git fetch` gałęzi agenta; zwraca SHA jej czubka."""
        self._git("fetch", "--quiet", self.remote, self.branch)
        return self.head()

    def head(self) -> str:
        return self._git("rev-parse", self.ref).strip()

    def show(self, sha: str, path: str) -> str:
        return self._git("show", f"{sha}:{path}")

    def site(self, sha: str) -> dict:
        try:
            return yaml.safe_load(self.show(sha, "site.yml"))
        except yaml.YAMLError as e:
            raise HarnessError(f"site.yml w {sha[:8]}: {e}") from None

    def state(self, sha: str, router_id: str) -> dict:
        return json.loads(self.show(sha, f"state/{router_id}.json"))

    def report(self, ref: ReportRef) -> dict:
        return json.loads(self.show(ref.commit, ref.path))

    def reports_since(self, base: str, head: str, router_id: str) -> list[ReportRef]:
        """Raporty routera dodane w commitach base..head, w kolejności commitów (najstarszy pierwszy)."""
        out = self._git("log", "--reverse", "--diff-filter=A", "--name-only",
                        "--format=%x00%H%x09%cI", f"{base}..{head}", "--",
                        f"reports/{router_id}/")
        refs: list[ReportRef] = []
        for chunk in out.split("\x00")[1:]:
            lines = [ln for ln in chunk.splitlines() if ln.strip()]
            sha, cdate = lines[0].split("\t")
            for path in sorted(p for p in lines[1:] if p.endswith(".json")):
                refs.append(ReportRef(path=path, commit=sha, committed_at=parse_ts(cdate)))
        return refs

    def find_detection(self, base: str, head: str, router_id: str, rule: str,
                       not_before: datetime) -> Detection | None:
        """Pierwszy raport po `not_before` z findingiem `rule` w statusie `new`."""
        for ref in self.reports_since(base, head, router_id):
            rep = self.report(ref)
            for f in rep.get("findings", []):
                if (f.get("rule") == rule and f.get("status") == "new"
                        and parse_ts(f["first_seen_at"]) >= not_before):
                    return Detection(ref=ref, report=rep, finding=f)
        return None


def preconditions(site: dict, state: dict, expect: dict) -> list[str]:
    """Warunki wstępne H8 (stan z Gita); pusta lista = spełnione."""
    errs = []
    if state.get("open_findings"):
        rules = ", ".join(f.get("rule", "?") for f in state["open_findings"])
        errs.append(f"open_findings niepuste: {rules}")
    if state.get("posture") != "no-violations":
        errs.append(f"posture '{state.get('posture')}' != 'no-violations'")
    pin = (site.get("policy") or {}).get("universal_version")
    deployed = (state.get("policy") or {}).get("universal_version")
    if pin != deployed:
        errs.append(f"pin site.yml '{pin}' != state.policy.universal_version '{deployed}'")
    if expect.get("coverage") == "full" and state.get("coverage") != "full":
        errs.append(f"coverage '{state.get('coverage')}' != 'full'")
    return errs


def router_profile(site: dict, router_id: str) -> str:
    for r in site.get("routers") or []:
        if r.get("router_id") == router_id:
            return r["profile"]
    raise HarnessError(f"router '{router_id}' nieobecny w site.yml")

"""Artefakty agenta w GitHubie (H9, D-G): numery PR i issue z raportu przebiegu.

Domyślnie wyłącznie odczyt (`gh pr list`, `gh issue list`, cwd = klon site-lab). Zamykanie tylko
z `--close-artifacts`: PR z gałęzi `agent/<router>/<run_id>` i issue wskazujące ścieżkę raportu
z wyniku, z komentarzem `harness <run_id>`; gałęzi nie usuwa. Brak artefaktu w czasie
`artifacts.timeout_s` = `artifact_missing` w wyniku, werdykt bez zmian.
"""
from __future__ import annotations

import json
import subprocess
from datetime import timedelta
from pathlib import Path
from typing import Callable

from . import HarnessError

Runner = Callable[..., subprocess.CompletedProcess]


class GitHub:
    def __init__(self, gh_bin: str, cwd: Path, runner: Runner = subprocess.run):
        self.gh = gh_bin
        self.cwd = cwd
        self._run = runner

    def _gh(self, *args: str) -> str:
        try:
            p = self._run([self.gh, *args], cwd=str(self.cwd), capture_output=True, text=True,
                          timeout=60)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise HarnessError(f"gh {args[0]} {args[1]}: {e}") from None
        if p.returncode != 0:
            raise HarnessError(f"gh {args[0]} {args[1]}: {p.stderr.strip()[:500]}")
        return p.stdout

    def prs_for_branch(self, branch: str) -> list[dict]:
        out = self._gh("pr", "list", "--head", branch, "--state", "all",
                       "--json", "number,url,state,headRefName")
        return [p for p in json.loads(out or "[]") if p.get("headRefName") == branch]

    def issues_for_report(self, report_path: str) -> list[dict]:
        out = self._gh("issue", "list", "--state", "all", "--search", f'"{report_path}" in:body',
                       "--json", "number,url,state,body")
        return [{k: i[k] for k in ("number", "url", "state")}
                for i in json.loads(out or "[]") if report_path in (i.get("body") or "")]

    def close_pr(self, number: int, comment: str) -> None:
        self._gh("pr", "close", str(number), "--comment", comment)

    def close_issue(self, number: int, comment: str) -> None:
        self._gh("issue", "close", str(number), "--comment", comment)


def expected(report: dict) -> dict:
    """PR, gdy raport ma `open-pr/succeeded`; po jednym issue na każdą akcję `alert/succeeded`."""
    acts = [a for a in report.get("actions", []) if a.get("status") == "succeeded"]
    return {"pr": any(a.get("type") == "open-pr" for a in acts),
            "issues": sum(1 for a in acts if a.get("type") == "alert")}


def collect(gh: GitHub, clock, router_id: str, report: dict, report_path: str,
            timeout_s: int, poll_s: int) -> dict:
    want = expected(report)
    out = {"expected": want, "branch": None, "prs": [], "issues": [], "status": "not-expected"}
    if not want["pr"] and not want["issues"]:
        return out
    branch = f"agent/{router_id}/{report['run']['run_id']}"
    out["branch"] = branch
    deadline = clock.now() + timedelta(seconds=timeout_s)
    while True:
        if want["pr"]:
            out["prs"] = gh.prs_for_branch(branch)
        if want["issues"]:
            out["issues"] = gh.issues_for_report(report_path)
        done = (not want["pr"] or out["prs"]) and len(out["issues"]) >= want["issues"]
        remaining = (deadline - clock.now()).total_seconds()
        if done or remaining <= 0:
            break
        clock.sleep(min(poll_s, remaining))
    out["status"] = "ok" if done else "artifact_missing"
    return out


def close(gh: GitHub, art: dict, run_id: str) -> list[str]:
    """Zamyka otwarte artefakty z wyniku przebiegu; zwraca listę zamkniętych (np. `pr#12`)."""
    comment = f"harness {run_id}"
    closed = []
    for p in art.get("prs", []):
        if p.get("state") == "OPEN" and p.get("headRefName") == art.get("branch"):
            gh.close_pr(p["number"], comment)
            closed.append(f"pr#{p['number']}")
    for i in art.get("issues", []):
        if i.get("state") == "OPEN":
            gh.close_issue(i["number"], comment)
            closed.append(f"issue#{i['number']}")
    return closed

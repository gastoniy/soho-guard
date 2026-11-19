"""Wynik przebiegu (H7): jeden plik JSON w `harness/results/` (katalog w `.gitignore`)."""
from __future__ import annotations

import json
import os
import secrets
import subprocess
from datetime import datetime
from pathlib import Path

from . import REPO_ROOT

RESULT_VERSION = "1"
# Katalogi, od których zależy wynik przebiegu; zmiana (także plik nieśledzony) = "-dirty".
CODE_PATHS = ("harness", "playbooks", "scenarios", "tools", "schemas")
VERDICTS = ("pass", "fail", "invalid", "timeout", "error")


def new_run_id(now: datetime) -> str:
    return f"h{now.strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(3)}"


def harness_commit() -> str | None:
    """SHA repo soho-guard, z którego uruchomiono harness; `-dirty`, gdy w CODE_PATHS są zmiany
    lub pliki nieśledzone (pliki z .gitignore, np. harness/results/, się nie liczą)."""
    try:
        sha = subprocess.run(["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
                             capture_output=True, text=True, check=True).stdout.strip()
        dirty = subprocess.run(["git", "-C", str(REPO_ROOT), "status", "--porcelain",
                                "--", *CODE_PATHS],
                               capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    return sha + ("-dirty" if dirty else "")


def _write(doc: dict, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return path


def write(result: dict, results_dir: Path) -> Path:
    assert result["verdict"] in VERDICTS, result["verdict"]
    name = f"{result['run_id']}-{result['manifest']['id']}-{result['target']['router_id']}.json"
    return _write(result, results_dir / name)


def write_reset(result: dict, results_dir: Path) -> Path:
    """Wynik pełnego resetu (H4): `<run_id>-reset-<router>.json`."""
    assert result["kind"] == "reset"
    return _write(result, results_dir / f"{result['run_id']}-reset-{result['router_id']}.json")


def write_pair(result: dict, results_dir: Path) -> Path:
    """Wynik skoordynowanej pary (iteracja 5): `<run_id>-pair-<dyn>-<ctl>.json`."""
    assert result["kind"] == "pair"
    assert result["verdict"] in VERDICTS, result["verdict"]
    p = result["pair"]
    return _write(result, results_dir / f"{result['run_id']}-pair-"
                  f"{p['dynamic_id']}-{p['control_id']}.json")


def write_campaign(summary: dict, results_dir: Path) -> Path:
    """Wynik zbiorczy kampanii: `<run_id>-campaign-<campaign_id>.json` (nadpisywany po każdym kroku)."""
    assert summary["kind"] == "campaign"
    return _write(summary, results_dir / f"{summary['run_id']}-campaign-{summary['campaign_id']}.json")

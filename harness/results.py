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


def write(result: dict, results_dir: Path) -> Path:
    assert result["verdict"] in VERDICTS, result["verdict"]
    results_dir.mkdir(parents=True, exist_ok=True)
    name = f"{result['run_id']}-{result['manifest']['id']}-{result['target']['router_id']}.json"
    path = results_dir / name
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return path

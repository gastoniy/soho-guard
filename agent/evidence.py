"""Dowody lokalne (R6): zostają na węźle, raport wskazuje je przez local_ref."""
from __future__ import annotations

import json
import os
from pathlib import Path

from agent.normalize import _is_sensitive


def local_ref(run_id: str, name: str) -> str:
    return f"ev:{run_id}/{name}"


def without_secrets(raw: dict) -> dict:
    """Odczyt API bez wartości tajnych: konto monitor może je widzieć, a dowód ich nie
    potrzebuje."""
    return {resource: [{k: v for k, v in row.items() if not _is_sensitive(k, v)} for row in rows]
            for resource, rows in raw.items()}


def store(evidence_dir: Path, run_id: str, name: str, data: dict) -> str:
    target = evidence_dir / run_id
    target.mkdir(parents=True, exist_ok=True, mode=0o750)
    path = target / f"{name}.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2, default=str)
    return local_ref(run_id, name)

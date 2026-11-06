"""Polityka: uniwersalna z wdrożonego wydania, lokalna z repo instalacji."""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from policy_lint import lint_local  # noqa: E402


def load_universal(policy_dir: Path) -> list[dict]:
    """Reguły statyczne. Politykę uniwersalną sprawdza CI przed wydaniem."""
    rules: list[dict] = []
    for path in sorted((policy_dir / "static").glob("*.yml")):
        rules.extend(yaml.safe_load(path.read_text(encoding="utf-8"))["rules"])
    return rules


def load_local(path: Path) -> tuple[dict, list[str]]:
    """Zwraca (dokument, błędy). Przy błędzie polityka lokalna jest pusta: drift działa
    z ustawieniami domyślnymi, a przebieg zgłasza obniżone pokrycie."""
    if not path.exists():
        return {}, [f"brak pliku {path.name}"]
    try:
        issues = lint_local([str(path)])
        if issues:
            return {}, issues
        return yaml.safe_load(path.read_text(encoding="utf-8")), []
    except (OSError, yaml.YAMLError) as exc:
        return {}, [f"{path.name}: {exc}"]

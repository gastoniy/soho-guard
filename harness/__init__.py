"""Harness scenariuszy soho-guard (C4): apply na routerze, czekanie na cykl agenta, ocena oracle'a.

Harness nie importuje niczego z `agent/` (H1). Z `tools/` używa `oracle_eval` i `manifest_lint`.
"""
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


class HarnessError(Exception):
    """Awaria harnessu (werdykt `error`)."""


class UsageError(Exception):
    """Błędne argumenty, konfiguracja lub manifest (kod wyjścia 2)."""

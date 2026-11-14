"""Obiekt routera sprawdzany własnym odczytem harnessu (H5, wynik scenariusza).

Dla każdego scenariusza z krokiem `apply`: menu RouterOS, filtr wiersza, wartości po apply
(potwierdzenie → `t0`) i wartości baseline (warunek przed apply oraz `end_state: baseline`).
`end_state: unchanged` = po detekcji router nadal ma wartości z apply.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import HarnessError


@dataclass(frozen=True)
class Probe:
    path: str
    applied: dict
    baseline: dict
    where: dict = field(default_factory=dict)


PROBES: dict[str, Probe] = {
    "POL-003": Probe(path="ip socks", applied={"enabled": True}, baseline={"enabled": False}),
}

_TRUE = {True, "true", "yes"}
_FALSE = {False, "false", "no"}


def _norm(v):
    """API zwraca true/false, polityka i CLI piszą yes/no — porównanie po normalizacji."""
    if isinstance(v, str):
        low = v.lower()
        if low in _TRUE:
            return True
        if low in _FALSE:
            return False
        return v
    return v


def get(scenario_id: str) -> Probe:
    try:
        return PROBES[scenario_id]
    except KeyError:
        raise HarnessError(f"brak definicji odczytu (harness/probes.py) dla {scenario_id}") from None


def select(rows: list[dict], where: dict) -> dict:
    hits = [r for r in rows if all(_norm(r.get(k)) == _norm(v) for k, v in where.items())]
    if len(hits) != 1:
        raise HarnessError(f"odczyt: oczekiwano 1 wiersza dla {where or '(menu jednowartościowe)'},"
                           f" jest {len(hits)}")
    return hits[0]


def matches(row: dict, expected: dict) -> list[str]:
    """Różnice row vs expected; pusta lista = zgodność."""
    return [f"{k}: {row.get(k)!r} != {v!r}" for k, v in expected.items()
            if _norm(row.get(k)) != _norm(v)]

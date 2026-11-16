"""Obiekt routera sprawdzany własnym odczytem harnessu (H5, wynik scenariusza).

Dla każdego scenariusza z krokiem `apply`: menu RouterOS, filtr wiersza, wartości po apply
(potwierdzenie → `t0`) i wartości baseline (warunek przed apply oraz `end_state: baseline`).
`end_state: unchanged` = po detekcji router nadal ma wartości z apply. `ABSENT` = wiersza brak
(np. baseline SITE-007: sekret PPP nie istnieje). `NONEMPTY` = pole ma niepustą wartość, gdy baseline
zależy od routera (POL-006: adres Winbox = segment MGMT). Wartość oczekiwana `""` przyjmuje też brak
pola (RouterOS pomija puste). Scenariusze z `apply: none` (BEN-001) nie mają odczytu.
Stałe muszą być zgodne z playbookami (sprawdza to test).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import HarnessError

ABSENT = None   # oczekiwany brak wiersza pasującego do `where`


class _NonEmpty:
    def __repr__(self):
        return "<niepuste>"


NONEMPTY = _NonEmpty()   # pole ma niepustą wartość (baseline zależny od routera)


@dataclass(frozen=True)
class Probe:
    path: str
    applied: dict | None
    baseline: dict | None
    where: dict = field(default_factory=dict)


BEN002_COMMENT_BASELINE = "BL: in icmp"
BEN002_COMMENT_APPLIED = "BL: in icmp (BEN-002)"
SITE007_SECRET = "harness-site-007"
SITE008_USER = "harness-site-008"

PROBES: dict[str, Probe] = {
    "POL-003": Probe(path="ip socks", applied={"enabled": True}, baseline={"enabled": False}),
    "BEN-002": Probe(path="ip firewall filter",
                     where={"chain": "input", "protocol": "icmp", "action": "accept"},
                     applied={"comment": BEN002_COMMENT_APPLIED},
                     baseline={"comment": BEN002_COMMENT_BASELINE}),
    "SITE-007": Probe(path="ppp secret", where={"name": SITE007_SECRET},
                      applied={"name": SITE007_SECRET}, baseline=ABSENT),
    "POL-004": Probe(path="ip proxy", applied={"enabled": True}, baseline={"enabled": False}),
    "POL-005": Probe(path="ip service", where={"name": "api"},
                     applied={"disabled": False}, baseline={"disabled": True}),
    "POL-006": Probe(path="ip service", where={"name": "winbox"},
                     applied={"address": ""}, baseline={"address": NONEMPTY}),
    "SITE-008": Probe(path="user", where={"name": SITE008_USER},
                      applied={"name": SITE008_USER, "group": "read"}, baseline=ABSENT),
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


# Pola, których wynik nigdy nie zawiera (np. /ppp secret zwraca hasło kontu z polityką `sensitive`).
SENSITIVE_FIELDS = frozenset({"password", "secret", "key", "private-key", "passphrase",
                              "authentication-password", "encryption-password", "psk"})


def view(row: dict | None, probe: Probe) -> dict | None:
    """Postać odczytu do wyniku JSON: tylko pola z `where` i wartości oczekiwanych, bez pól tajnych."""
    if row is None:
        return None
    keys = set(probe.where) | set(probe.applied or {}) | set(probe.baseline or {})
    return {k: row[k] for k in sorted(keys - SENSITIVE_FIELDS) if k in row}


def get(scenario_id: str) -> Probe:
    try:
        return PROBES[scenario_id]
    except KeyError:
        raise HarnessError(f"brak definicji odczytu (harness/probes.py) dla {scenario_id}") from None


def select(rows: list[dict], where: dict) -> dict | None:
    """Jedyny wiersz pasujący do `where` albo None, gdy brak; więcej niż jeden = błąd."""
    hits = [r for r in rows if all(_norm(r.get(k)) == _norm(v) for k, v in where.items())]
    if len(hits) > 1:
        raise HarnessError(f"odczyt: oczekiwano najwyżej 1 wiersza dla "
                           f"{where or '(menu jednowartościowe)'}, jest {len(hits)}")
    return hits[0] if hits else None


def matches(row: dict | None, expected: dict | None) -> list[str]:
    """Różnice row vs expected (ABSENT = wiersza ma nie być); pusta lista = zgodność."""
    if expected is ABSENT:
        return [] if row is None else ["wiersz obecny, oczekiwano braku"]
    if row is None:
        return ["wiersz nieobecny"]
    return [f"{k}: {row.get(k)!r} != {v!r}" for k, v in expected.items()
            if not _field_ok(row.get(k), v)]


def _field_ok(have, want) -> bool:
    if want is NONEMPTY:
        return have not in (None, "", [])
    if want == "":
        return have in (None, "")
    return _norm(have) == _norm(want)

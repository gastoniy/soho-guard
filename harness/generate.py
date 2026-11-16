"""Krok ruchowy (generate) scenariuszy behawioralnych — emulacja zachowania (A2) wobec c2-lab.

Sterownik per `generate.from`. Jedyny z iteracji 4: `router` (DYN-011a, D-E) — ruch generuje sam
router pingiem do c2-lab, uruchomionym w tle przez `:execute` (SSH, konto ansible). Ping jako job
nie zostawia śladu w konfiguracji; jedyny drift to reguła raw notrack dodana w kroku apply. Cel
wybierany z puli adresów endpointu w harness.yml (kolejne powtórzenia → kolejny adres, H8). t0 =
start pingu (`generate.t0_marker`).

`kali`, `client`, `other-router` nie są jeszcze zaimplementowane (iteracja 5: CTL-001 = other-router).
"""
from __future__ import annotations

import logging

from . import HarnessError, UsageError
from .timing import iso, parse_ts

log = logging.getLogger("harness")

PING_COUNT = 1200          # D-E: ≥ 3 próbki L1 z zapasem (lab 2026-11-13); ~20 min pingu
PING_INTERVAL_S = 1


def pick_target(cfg, endpoint: str, index: int) -> str:
    """Adres celu z puli endpointu; kolejne powtórzenia biorą kolejny adres (round-robin)."""
    addrs = cfg.endpoint(endpoint)
    return addrs[index % len(addrs)]


def _ping_remote(target: str) -> str:
    return f':execute script="/ping {target} count={PING_COUNT} interval={PING_INTERVAL_S}s"'


def _jobs_remote() -> str:
    return ":put [:len [/system script job find]]"


def _router(ctx, rcfg, target: str) -> dict:
    """Ping z routera do celu, w tle przez :execute; zwraca info z started_at = t0."""
    if ctx.ssh is None:
        raise HarnessError("generate.from=router wymaga SSH (harness.yml: ssh.config)")
    started = ctx.clock.now()
    ctx.ssh.run(rcfg, _ping_remote(target))                 # :execute wraca natychmiast
    out = ctx.ssh.run(rcfg, _jobs_remote()).stdout.strip()
    try:
        jobs = int(out.splitlines()[-1]) if out else 0
    except ValueError:
        jobs = -1
    if jobs < 1:
        raise HarnessError(f"ping nie wystartował: brak zadania w /system script job (jobs={out!r})")
    return {"target": target, "started_at": iso(started),
            "ping": {"count": PING_COUNT, "interval_s": PING_INTERVAL_S}, "jobs": jobs}


_DRIVERS = {"router": _router}


def run_generate(ctx, manifest: dict, rcfg, target: str) -> dict:
    """Uruchamia krok generate; zwraca info do wyniku (zawiera started_at = t0)."""
    gen = manifest["generate"]
    src = gen["from"]
    driver = _DRIVERS.get(src)
    if driver is None:
        raise UsageError(f"generate.from={src} nie jest zaimplementowany (iteracja 4: router)")
    log.info("%s %s: generate from=%s → %s (%s)", manifest["id"], rcfg.router_id, src, target,
             gen["to_endpoint"])
    info = driver(ctx, rcfg, target)
    return {"from": src, "to_endpoint": gen["to_endpoint"], "behavior": gen["behavior"], **info}


def started_at(gen_info: dict):
    return parse_ts(gen_info["started_at"])

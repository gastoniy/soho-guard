"""Krok ruchowy (generate) scenariuszy behawioralnych — emulacja zachowania (A2) wobec c2-lab.

Sterownik per `generate.from`: `start` (t0 = start ruchu, `generate.t0_marker`) i opcjonalnie
`stop` (teardown, także po błędzie i Ctrl-C). Cel wybierany z puli adresów endpointu w harness.yml.

  * `router` (DYN-011a, D-E): ping z routera do c2-lab w tle przez `:execute` (SSH, konto ansible);
    kończy się sam (count), bez `stop`.
  * `client` (DYN-011b, D-B1): ruch z klienta za routerem, którym steruje **operator ręcznie**.
    Harness nie łączy się z klientem: prosi w terminalu o uruchomienie (t0 = chwila potwierdzenia)
    i o zatrzymanie (czas zatrzymania = chwila potwierdzenia). Konfiguracja routera bez zmian →
    brak efektów ubocznych w L1; w L2 ruch ma `src` = WAN routera (NAT).

`kali` i `other-router` nie mają sterownika (CTL-001 = ramię kontrolne pary, bez własnego ruchu).
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


def _router(ctx, manifest, rcfg, target: str) -> dict:
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


def _confirm(ctx, text: str) -> None:
    if getattr(ctx, "prompt", None) is None:
        raise HarnessError("generate.from=client wymaga potwierdzeń operatora w terminalu")
    ctx.prompt(text)


def _client(ctx, manifest, rcfg, target: str) -> dict:
    """Operator uruchamia ruch na kliencie za routerem; t0 = chwila potwierdzenia."""
    gen = manifest["generate"]
    _confirm(ctx, f"{manifest['id']}: na kliencie za {rcfg.router_id} nie działa inny ruch tego "
                  f"typu; uruchom teraz: {gen['behavior']} (cel {target}) i potwierdź Enter")
    started = ctx.clock.now()
    return {"target": target, "started_at": iso(started), "control": "operator"}


def _client_stop(ctx, manifest, router_id: str) -> dict:
    """Operator zatrzymuje ruch; od tej chwili liczy się czekanie na rozwiązanie findingu."""
    asked = ctx.clock.now()
    try:
        _confirm(ctx, f"{manifest['id']}: zatrzymaj ruch na kliencie za {router_id} "
                      f"i potwierdź Enter")
    except (HarnessError, EOFError, KeyboardInterrupt) as e:
        log.error("zatrzymanie ruchu niepotwierdzone (%s) — zatrzymaj go ręcznie", e or type(e).__name__)
        return {"requested_at": iso(asked), "stopped_at": None, "confirmed": False}
    return {"requested_at": iso(asked), "stopped_at": iso(ctx.clock.now()), "confirmed": True}


_DRIVERS = {"router": {"start": _router},
            "client": {"start": _client, "stop": _client_stop}}


def _driver(manifest: dict) -> dict:
    src = manifest["generate"]["from"]
    d = _DRIVERS.get(src)
    if d is None:
        raise UsageError(f"generate.from={src} nie ma sterownika (dostępne: {sorted(_DRIVERS)})")
    return d


def run_generate(ctx, manifest: dict, rcfg, target: str) -> dict:
    """Uruchamia krok generate; zwraca info do wyniku (zawiera started_at = t0)."""
    gen = manifest["generate"]
    driver = _driver(manifest)["start"]
    log.info("%s %s: generate from=%s → %s (%s)", manifest["id"], rcfg.router_id, gen["from"],
             target, gen["to_endpoint"])
    info = driver(ctx, manifest, rcfg, target)
    return {"from": gen["from"], "to_endpoint": gen["to_endpoint"], "behavior": gen["behavior"],
            **info}


def stop_generate(ctx, manifest: dict, router_id: str) -> dict | None:
    """Zatrzymanie ruchu w teardownie; None = ruch kończy się sam (router)."""
    fn = _driver(manifest).get("stop")
    return fn(ctx, manifest, router_id) if fn else None


def started_at(gen_info: dict):
    return parse_ts(gen_info["started_at"])

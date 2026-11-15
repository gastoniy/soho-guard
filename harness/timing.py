"""Siatka cyklu agenta, wybór momentu apply i przesunięcie względem siatki.

Timer agenta: `OnCalendar=*:0/5` (UTC i czas lokalny mają tę samą siatkę 5-minutową), odczyt L1
kończy się ok. 10–15 s po :X0. Apply w oknie [:X0, :X0 + avoid_window_s) mógłby wejść do cyklu
częściowo, więc harness go unika.
"""
from __future__ import annotations

import random
import time
from datetime import datetime, timedelta, timezone

from . import UsageError
from .config import TimingCfg


class Clock:
    """Zegar ścienny UTC; testy wstrzykują własną implementację z tym samym interfejsem."""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)

    def sleep_until(self, t: datetime) -> None:
        self.sleep((t - self.now()).total_seconds())


def grid_offset(t: datetime, cycle_s: int = 300) -> float:
    """Sekundy od ostatniego punktu siatki cyklu (0 ≤ wynik < cycle_s)."""
    return t.timestamp() % cycle_s


def last_grid(t: datetime, cycle_s: int = 300) -> datetime:
    return t - timedelta(seconds=grid_offset(t, cycle_s))


def in_avoid_window(t: datetime, cfg: TimingCfg) -> bool:
    return grid_offset(t, cfg.cycle_s) < cfg.avoid_window_s


def check_offset(offset_s: float, cfg: TimingCfg) -> None:
    lo, hi = cfg.avoid_window_s, cfg.cycle_s - cfg.apply_margin_s
    if not lo <= offset_s <= hi:
        raise UsageError(f"--offset poza zakresem [{lo}, {hi}] s")


def plan_apply(now: datetime, cfg: TimingCfg, rng: random.Random,
               fixed_offset_s: float | None = None) -> tuple[datetime, float]:
    """Najbliższy moment apply z przesunięciem w [avoid_window_s, cycle_s - apply_margin_s].

    Przesunięcie losowane jednostajnie (kampania) albo podane (`--offset`). Zwraca (moment, przesunięcie).
    """
    lo, hi = cfg.avoid_window_s, cfg.cycle_s - cfg.apply_margin_s
    if fixed_offset_s is None:
        off = rng.uniform(lo, hi)
    else:
        check_offset(fixed_offset_s, cfg)
        off = float(fixed_offset_s)
    t = last_grid(now, cfg.cycle_s) + timedelta(seconds=off)
    if t <= now:
        t += timedelta(seconds=cfg.cycle_s)
    return t, off


def predict_heartbeat(heartbeat_at: datetime, interval_s: int, cycle_s: int = 300,
                      publish_s: float = 20, finish_s: float = 30) -> datetime:
    """Najwcześniejszy możliwy commit heartbeatu (R9).

    Agent porównuje `last_run.finished_at` (ok. :X0+17 s) z `heartbeat.at` poprzedniego commita,
    więc kolejny heartbeat wypada na granicy: w cyklu o tym samym przesunięciu albo w następnym
    (różnica ułamka sekundy w czasie trwania cyklu). Bierzemy pierwszy cykl, który mógłby
    skończyć się (do `finish_s` po :X0) co najmniej `interval_s` po poprzednim heartbeacie;
    commit ok. `publish_s` po :X0. Pomyłka o cykl w tę stronę tylko wydłuża okno H10."""
    due = heartbeat_at + timedelta(seconds=interval_s)
    g = last_grid(due - timedelta(seconds=finish_s), cycle_s)
    if g + timedelta(seconds=finish_s) < due:
        g += timedelta(seconds=cycle_s)
    return g + timedelta(seconds=publish_s)


def plan_h10(now: datetime, heartbeat_at: datetime, interval_s: int, cfg: TimingCfg,
             rng: random.Random, fixed_offset_s: float | None = None
             ) -> tuple[datetime, float, datetime]:
    """H10: apply ok. `heartbeat_lead_s` przed przewidywanym heartbeatem (poza oknem L1).

    Gdy na to za późno, celem jest następny heartbeat. Zwraca (moment apply, przesunięcie, heartbeat)."""
    hb = predict_heartbeat(heartbeat_at, interval_s, cfg.cycle_s)
    half = timedelta(seconds=cfg.cycle_s / 2)
    while hb - timedelta(seconds=cfg.heartbeat_lead_s) - half <= now:
        hb += timedelta(seconds=interval_s)
    t, off = plan_apply(hb - timedelta(seconds=cfg.heartbeat_lead_s) - half, cfg, rng,
                        fixed_offset_s)
    return t, off, hb


def parse_ts(s: str) -> datetime:
    """Znacznik ISO 8601 z raportu/stanu (`…Z`) → datetime UTC."""
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def iso(t: datetime | None) -> str | None:
    if t is None:
        return None
    return t.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

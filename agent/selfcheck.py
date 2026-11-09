"""Samokontrola czujników L2: wynik obniża pokrycie, nigdy nie tworzy findingu.

Bez niej brak zdarzeń w L2 wygląda tak samo jak czysty ruch. Sprawdzenia:
  (a) Zeek pisze: wiek current/conn.log,
  (b) utrata pakietów na mirrorze: capture_loss.log (misc/capture-loss),
  (d) ruch routera widoczny w L2: przepływ lub zapytanie z wan_address w oknie,
  (e) atrybucja: wan_address na interfejsie w L1 i brak klienta DHCP na tym interfejsie.
(c) wiek importu RITA sprawdza __main__ przy odczycie RITA.
"""
from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from pathlib import Path

from agent.l2_zeek import ZeekData, ZeekError, latest

STALE_CONN_S = 900
CAPTURE_LOSS_MAX = 1.0            # procent
CAPTURE_MIN_ACKS = 500
CAPTURE_MAX_AGE_S = 1800
CAPTURE_FIELDS = ("ts", "peer", "gaps", "acks", "percent_lost")
# Testy na atrapach nie mają ruchu tła ani pomiaru utraty; tests/conftest.py je wyłącza,
# a testy samokontroli włączają z powrotem.
REQUIRE_ROUTER_TRAFFIC = True
REQUIRE_CAPTURE_LOSS = True


@dataclass
class SelfCheck:
    """zeek_blocked: reguły Zeeka nieocenione (otwarte findingi zostają).
    attribution: ruchu nie da się przypisać routerowi, cała L2 niedostępna.
    degraded: uwagi obniżające status L2; info: uwagi bez wpływu na status."""
    zeek_blocked: str | None = None
    attribution: str | None = None
    degraded: list[str] = field(default_factory=list)
    info: list[str] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)

    def fail(self, code: str, message: str, *, degrade: bool = True) -> None:
        self.errors.append((code, message))
        if degrade:
            self.degraded.append(message)


def conn_log_age(zeek_dir: Path, now: float) -> float | None:
    try:
        return now - (zeek_dir / "current" / "conn.log").stat().st_mtime
    except OSError:
        return None


def _wan_interface(state: dict, wan: str) -> str | None | bool:
    """Interfejs z adresem WAN; False, gdy adresu nie ma; None, gdy menu nieodczytane."""
    rows = state.get("ip_addresses")
    if rows is None:
        return None
    for row in rows:
        try:
            ip = ipaddress.ip_interface(str(row.get("address", ""))).ip
        except ValueError:
            continue
        if str(ip) == wan and not row.get("disabled"):
            return str(row.get("interface") or row.get("actual-interface") or "")
    return False


def attribution(state: dict | None, wan: str) -> str | None:
    """Powód niepewnej atrybucji albo None. Brak odczytu L1 niczego nie przesądza."""
    if state is None:
        return None
    iface = _wan_interface(state, wan)
    if iface is None:
        return None
    if iface is False:
        return f"router nie ma adresu {wan} z addressing.wan_address"
    for client in state.get("dhcp_clients") or []:
        if not client.get("disabled") and str(client.get("interface", "")) == iface:
            return f"klient DHCP na interfejsie WAN {iface}: adres może się zmienić"
    return None


def capture_loss(zeek_dir: Path, now: float, result: SelfCheck) -> None:
    try:
        row = latest(zeek_dir, "capture_loss", CAPTURE_FIELDS, now - CAPTURE_MAX_AGE_S)
    except ZeekError as exc:
        row = None
        detail = f" ({exc})"
    else:
        detail = ""
    if row is None:
        result.fail("selfcheck.capture-loss", f"brak pomiaru utraty pakietów z ostatnich 30 min{detail}")
        return
    try:
        acks, lost = int(row["acks"] or 0), float(row["percent_lost"] or 0)
    except ValueError:
        result.fail("selfcheck.capture-loss", "nieczytelny wpis capture_loss.log")
        return
    if acks < CAPTURE_MIN_ACKS:
        result.info.append(f"za mało ruchu TCP do oceny utraty pakietów ({acks} potwierdzeń)")
    elif lost > CAPTURE_LOSS_MAX:
        result.fail("selfcheck.capture-loss", f"utrata pakietów na mirrorze {lost:.2f}% (próg {CAPTURE_LOSS_MAX}%)")


def check(zeek_dir: Path, wan: str | None, zeek: ZeekData | None, l1_state: dict | None,
          now: float | None = None) -> SelfCheck:
    now = time.time() if now is None else now
    result = SelfCheck()
    if wan is None:
        return result                      # l2.attribution-unavailable zgłasza __main__
    reason = attribution(l1_state, wan)
    if reason:
        result.attribution = reason
        result.fail("selfcheck.wan-mismatch", reason, degrade=False)
        return result
    if zeek is None:
        return result                      # l2.read-failed zgłasza __main__
    age = conn_log_age(zeek_dir, now)
    if age is not None and age > STALE_CONN_S:
        result.zeek_blocked = f"conn.log bez zapisu od {int(age // 60)} min"
        result.fail("selfcheck.zeek-stale", result.zeek_blocked)
    elif REQUIRE_ROUTER_TRAFFIC and not zeek.conn and not zeek.dns:
        result.zeek_blocked = "brak ruchu routera w L2 w ostatnich 60 min (mirror lub atrybucja)"
        result.fail("selfcheck.no-router-traffic", result.zeek_blocked)
    if REQUIRE_CAPTURE_LOSS:
        capture_loss(zeek_dir, now, result)
    return result

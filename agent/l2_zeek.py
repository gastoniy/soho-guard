"""L2: odczyt logów Zeeka z mirrora WAN (ADR-004).

Okno zamiast kursora: wpis conn.log powstaje po końcu przepływu, a ts to jego początek,
więc kursor po czasie gubiłby długie przepływy. Każdy cykl czyta od nowa ostatnie
WINDOW_S sekund: bieżący plik i archiwa zrotowane w tym czasie.
"""
from __future__ import annotations

import gzip
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

WINDOW_S = 3600
# Archiwum dostaje mtime przy rotacji: starsze nie mogą zawierać wpisów z okna.
ROTATION_SLACK_S = 300
CONN_FIELDS = ("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
               "duration", "orig_bytes", "resp_bytes", "conn_state", "resp_pkts")
DNS_FIELDS = ("ts", "uid", "id.orig_h", "id.resp_h", "id.resp_p", "proto", "query", "qtype_name")
UNSET = {"-", "(empty)"}


class ZeekError(Exception):
    """Logów nie da się odczytać: warstwa L2 niedostępna."""


@dataclass
class ZeekData:
    since: float
    until: float
    conn: list[dict] = field(default_factory=list)
    dns: list[dict] = field(default_factory=list)
    files: int = 0


def wan_ip(value: str | None) -> str | None:
    """addressing.wan_address bywa z maską (192.168.20.21/24): atrybucja jest po samym adresie."""
    if not value:
        return None
    return str(ipaddress.ip_interface(value).ip)


def _number(value: str | None, kind=float):
    if value is None:
        return None
    try:
        return kind(value)
    except ValueError:
        return None


def parse(lines, wanted: tuple[str, ...]) -> list[dict]:
    """Format TSV Zeeka: kolumny z nagłówka #fields. Wiersz z inną liczbą pól, np. ucięty
    w trakcie zapisu, jest pomijany."""
    columns: list[str] | None = None
    rows = []
    for line in lines:
        line = line.rstrip("\n")
        if line.startswith("#"):
            if line.startswith("#fields"):
                columns = line.split("\t")[1:]
            continue
        if not line or columns is None:
            continue
        values = line.split("\t")
        if len(values) != len(columns):
            continue
        record = dict(zip(columns, values))
        rows.append({k: None if record.get(k) in UNSET else record.get(k) for k in wanted})
    return rows


def _files(zeek_dir: Path, kind: str, since: float) -> list[Path]:
    current = zeek_dir / "current"
    if not current.is_dir():
        raise ZeekError(f"brak katalogu {current}")
    # Zatrzymany Zeek (zeekctl stop) archiwizuje bieżące logi. Puste okno wyglądałoby wtedy
    # jak brak zdarzeń i rozwiązywałoby findingi, więc brak conn.log to brak danych.
    # Pełna kontrola świeżości logów: samokontrola (iteracja 6).
    if kind == "conn" and not (current / "conn.log").exists():
        raise ZeekError(f"brak {current / 'conn.log'}: Zeek nie zapisuje logów")
    found = [current / f"{kind}.log"] if (current / f"{kind}.log").exists() else []
    moment = datetime.fromtimestamp(since, timezone.utc)
    # Katalogi dzienne mają datę lokalną węzła: dzień wcześniej i później obejmuje każdą strefę.
    days = {(moment + timedelta(days=d)).strftime("%Y-%m-%d") for d in (-1, 0, 1)}
    days.add(datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    for day in sorted(days):
        directory = zeek_dir / day
        if directory.is_dir():
            found += [p for p in sorted(directory.glob(f"{kind}.*.log.gz"))
                      if p.stat().st_mtime >= since - ROTATION_SLACK_S]
    return found


def _read(path: Path, wanted: tuple[str, ...]) -> list[dict]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
        return parse(handle, wanted)


def read(zeek_dir: Path, wan: str, now: float, window_s: int = WINDOW_S) -> ZeekData:
    """Przepływy i zapytania z wan_address, które trwały lub zaczęły się w oknie."""
    data = ZeekData(since=now - window_s, until=now)
    try:
        for kind, wanted, target in (("conn", CONN_FIELDS, data.conn), ("dns", DNS_FIELDS, data.dns)):
            for path in _files(zeek_dir, kind, data.since):
                data.files += 1
                for row in _read(path, wanted):
                    ts = _number(row["ts"])
                    if ts is None or row["id.orig_h"] != wan:
                        continue
                    row["ts"] = ts
                    row["id.resp_p"] = _number(row["id.resp_p"], int)
                    if kind == "conn":
                        row["duration"] = _number(row["duration"]) or 0.0
                        row["orig_bytes"] = _number(row["orig_bytes"], int) or 0
                        row["resp_bytes"] = _number(row["resp_bytes"], int) or 0
                        row["resp_pkts"] = _number(row["resp_pkts"], int) or 0
                        end = ts + row["duration"]
                    else:
                        end = ts
                    if end >= data.since and ts <= now:
                        target.append(row)
    except (OSError, EOFError, gzip.BadGzipFile) as exc:
        raise ZeekError(f"{type(exc).__name__}: {exc}") from exc
    return data

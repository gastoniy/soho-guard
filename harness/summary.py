"""Zestawienie wyników przebiegów (rozdział 8): wiersz na przebieg + agregaty per manifest × router.

Wejście: pliki JSON przebiegów, katalogi z nimi albo wynik zbiorczy kampanii (wtedy jego przebiegi,
pliki szukane obok). Wynik pary (DYN-011b + CTL-001) daje dwa wiersze — po jednym na ramię.
Wyniki resetów i kampanii jako wiersze są pomijane. Wyjście: Markdown na stdout,
opcjonalnie CSV przebiegów i agregatów.
"""
from __future__ import annotations

import csv
import json
import math
import statistics
from pathlib import Path

from . import UsageError

VERDICTS = ("pass", "fail", "timeout", "invalid", "error")
RUN_FIELDS = ("run_id", "campaign", "manifest_id", "router_id", "verdict", "mttd_s", "notify_s",
              "remediate_s", "window_s", "t0_grid_offset_s", "teardown_ok", "started_at")
AGG_FIELDS = ("manifest_id", "router_id", "n", *VERDICTS, "mttd_min", "mttd_median", "mttd_p90",
              "mttd_max", "mttd_mean", "notify_median", "remediate_median", "window_median")


def _load(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise UsageError(f"{path}: {e}") from None


def collect(paths: list[Path]) -> list[dict]:
    """Dokumenty przebiegów scenariuszy (bez duplikatów, w kolejności startu)."""
    docs: dict[str, dict] = {}

    def add(doc):
        if doc.get("kind") in (None, "scenario", "pair") and "manifest" in doc:
            docs[doc["run_id"]] = doc

    for p in paths:
        if p.is_dir():
            for f in sorted(p.glob("*.json")):
                add(_load(f))
            continue
        doc = _load(p)
        if doc.get("kind") == "campaign":
            for r in doc.get("runs", []):
                f = p.parent / r["path"]
                if not f.is_file():
                    raise UsageError(f"{p}: brak pliku przebiegu {f}")
                add(_load(f))
        else:
            add(doc)
    return sorted(docs.values(), key=lambda d: d.get("started_at") or "")


def run_row(doc: dict) -> dict:
    m = doc.get("metrics") or {}
    return {
        "run_id": doc["run_id"],
        "campaign": (doc.get("campaign") or {}).get("id", ""),
        "manifest_id": doc["manifest"]["id"],
        "router_id": doc["target"]["router_id"],
        "verdict": doc["verdict"],
        "mttd_s": m.get("mttd_s"),
        "notify_s": m.get("notify_s"),
        "remediate_s": m.get("remediate_s"),
        "window_s": m.get("window_s"),
        "t0_grid_offset_s": (doc.get("timing") or {}).get("t0_grid_offset_s"),
        "teardown_ok": (doc.get("teardown") or {}).get("ok"),
        "started_at": doc.get("started_at"),
    }


def run_rows(doc: dict) -> list[dict]:
    """Wiersze przebiegu: scenariusz → jeden; para → ramię dynamic (MTTD) i control."""
    if doc.get("kind") != "pair":
        return [run_row(doc)]
    out = []
    for arm in ("dynamic", "control"):
        a = doc[arm]
        m = a.get("metrics") or {}
        out.append({
            "run_id": doc["run_id"],
            "campaign": (doc.get("campaign") or {}).get("id", ""),
            "manifest_id": doc["manifest"][arm]["id"],
            "router_id": a["router_id"],
            "verdict": a.get("verdict") or doc["verdict"],
            "mttd_s": m.get("mttd_s"), "notify_s": m.get("notify_s"),
            "remediate_s": m.get("remediate_s"), "window_s": None,
            "t0_grid_offset_s": (doc.get("timing") or {}).get("t0_grid_offset_s"),
            "teardown_ok": (doc.get("teardown") or {}).get("ok"),
            "started_at": doc.get("started_at"),
        })
    return out


def _p90(xs: list[float]) -> float:
    s = sorted(xs)
    return s[math.ceil(0.9 * len(s)) - 1]          # percentyl metodą najbliższej rangi


def _stat(xs, fn):
    xs = [x for x in xs if x is not None]
    return round(fn(xs), 1) if xs else None


def aggregate(rows: list[dict]) -> list[dict]:
    groups: dict[tuple[str, str], list[dict]] = {}
    for r in rows:
        groups.setdefault((r["manifest_id"], r["router_id"]), []).append(r)
    out = []
    for (mid, rid), rs in sorted(groups.items()):
        ok = [r for r in rs if r["verdict"] == "pass"]      # czasy tylko z przebiegów `pass`
        mttd = [r["mttd_s"] for r in ok]
        out.append({
            "manifest_id": mid, "router_id": rid, "n": len(rs),
            **{v: sum(1 for r in rs if r["verdict"] == v) for v in VERDICTS},
            "mttd_min": _stat(mttd, min), "mttd_median": _stat(mttd, statistics.median),
            "mttd_p90": _stat(mttd, _p90), "mttd_max": _stat(mttd, max),
            "mttd_mean": _stat(mttd, statistics.fmean),
            "notify_median": _stat([r["notify_s"] for r in ok], statistics.median),
            "remediate_median": _stat([r["remediate_s"] for r in ok], statistics.median),
            "window_median": _stat([r["window_s"] for r in ok], statistics.median),
        })
    return out


def _cell(v) -> str:
    if v is None:
        return "—"
    if isinstance(v, bool):
        return "tak" if v else "NIE"
    return str(v)


def _table(rows: list[dict], fields: tuple[str, ...]) -> list[str]:
    lines = ["| " + " | ".join(fields) + " |", "|" + "---|" * len(fields)]
    lines += ["| " + " | ".join(_cell(r[f]) for f in fields) + " |" for r in rows]
    return lines


def markdown(rows: list[dict], aggs: list[dict]) -> str:
    out = ["## Agregaty (czasy w s, tylko przebiegi `pass`)", ""]
    out += _table(aggs, AGG_FIELDS)
    out += ["", f"## Przebiegi ({len(rows)})", ""]
    out += _table(rows, RUN_FIELDS)
    return "\n".join(out) + "\n"


def write_csv(path: Path, rows: list[dict], fields: tuple[str, ...]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(fields))
        w.writeheader()
        for r in rows:
            w.writerow({k: "" if r[k] is None else r[k] for k in fields})

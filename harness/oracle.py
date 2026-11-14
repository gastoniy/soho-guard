"""Oracle harnessu: kontrakt `tools/oracle_eval.py` + czasy H11 + budżet MTTD + end_state z odczytu.

Czasy (H11), wszystkie względem `t0` (potwierdzenie zmiany odczytem harnessu):
  MTTD                 = finding.first_seen_at − t0 (budżet: expect.max_detection_time_s)
  czas do powiadomienia = czas commita raportu − t0
  czas do naprawy      = actions[].finished_at (verification.result = resolved) − t0
Zegary hosta harnessu i węzła są synchronizowane NTP; ujemne MTTD oznacza zmianę zauważoną
przez agenta przed potwierdzeniem harnessu (apply blisko odczytu L1) i jest zapisywane w wyniku.
"""
from __future__ import annotations

import sys
from datetime import datetime

from . import REPO_ROOT
from .sitelab import Detection
from .timing import parse_ts

sys.path.insert(0, str(REPO_ROOT / "tools"))
from oracle_eval import oracle_eval  # noqa: E402


def _secs(a: datetime, b: datetime) -> float:
    return round((a - b).total_seconds(), 3)


def evaluate(manifest: dict, det: Detection, state: dict, t0: datetime,
             end_state_diffs: list[str] | None) -> dict:
    """Ocena scenariusza wykrywanego. `end_state_diffs` = różnice odczytu routera względem
    oczekiwanego stanu końcowego (None, gdy manifest nie ma `end_state`)."""
    exp = manifest["expect"]
    violations = list(oracle_eval(manifest, det.report, state))

    mttd = _secs(parse_ts(det.finding["first_seen_at"]), t0)
    budget = exp["max_detection_time_s"]
    if mttd > budget:
        violations.append(f"MTTD {mttd} s > budżet {budget} s")

    remediate_s = None
    for a in det.report.get("actions", []):
        ver = a.get("verification") or {}
        if (a.get("fingerprint") == det.finding["fingerprint"] and ver.get("result") == "resolved"
                and a.get("finished_at")):
            remediate_s = _secs(parse_ts(a["finished_at"]), t0)
            break

    if end_state_diffs:
        violations.append(f"end_state={exp.get('end_state')}: odczyt routera niezgodny: "
                          + "; ".join(end_state_diffs))

    return {
        "violations": violations,
        "metrics": {
            "mttd_s": mttd,
            "budget_s": budget,
            "notify_s": _secs(det.ref.committed_at, t0),
            "remediate_s": remediate_s,
        },
    }

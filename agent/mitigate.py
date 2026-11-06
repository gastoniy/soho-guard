"""Mitygacja: wybór akcji wg R8. Wykonanie remediacji dochodzi w iteracji 3, teraz
akcje są wyłącznie opisane."""
from __future__ import annotations

from agent.findings import Finding


def _plan(finding: Finding) -> tuple[str, str, str]:
    v = finding.violation
    if v.ioc:
        return "alert", "proposed", "R8: wskaźnik kompromitacji, wyłącznie alert"
    if v.rule_source == "local":
        return "open-pr", "proposed", "R8: reguła lokalna, decyzja człowieka przez PR"
    if v.remediate:
        values = ", ".join(f"{k}={val}" for k, val in sorted(v.remediate["set"].items()))
        return "auto-remediate", "proposed", f"dry-run: remediacja niewykonana, planowane {values}"[:500]
    return "none", "skipped", "reguła uniwersalna bez remediate, naruszenie widoczne w raporcie"


def plan_actions(findings: list[Finding]) -> list[dict]:
    """Dokładnie jedna akcja na nowy finding; utrzymujące się nie dostają kolejnej."""
    actions = []
    for finding in findings:
        if finding.status != "new":
            continue
        kind, status, reason = _plan(finding)
        actions.append({
            "action_id": f"A-{len(actions) + 1:02d}",
            "fingerprint": finding.fingerprint,
            "type": kind,
            "status": status,
            "reason": reason,
            "started_at": None,
            "finished_at": None,
            "external_ref": None,
            "verification": None,
            "local_ref": None,
        })
    return actions

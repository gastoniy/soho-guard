#!/usr/bin/env python3
"""Oracle referencyjny: ocena manifestu scenariusza względem opublikowanego
raportu i stanu (ADR-005, kontrakt B1).

To jest REFERENCJA kontraktu, nie pełny oracle harnessu (C4). Dowodzi, że
pola expect manifestu odwzorowują się jednoznacznie na asercje wobec raportu.
Pełny oracle harnessu dokłada: odczyt stanu routera własnym kanałem,
pomiar MTTD od znacznika t0 i czekanie na cykl agenta.

Czego ten moduł NIE sprawdza (robi to harness):
  - max_detection_time_s: wymaga t0 z harnessu (first_seen_at - t0)
  - rzeczywisty stan routera po akcji (harness czyta router, nie wierzy agentowi)

Wejście: manifest (dict), report (dict | None), state (dict).
Wyjście: lista naruszeń kontraktu (pusta = zgodność).
"""
from __future__ import annotations

ACTION_MAP = {
    "auto-remediate": {"auto-remediate"},
    "alert": {"alert"},
    "none": {"none"},
    "pr-alert": {"open-pr", "alert"},
}


def oracle_eval(manifest: dict, report: dict | None, state: dict) -> list[str]:
    exp = manifest["expect"]
    f: list[str] = []

    # --- scenariusz bez detekcji: benign, control ---
    if not exp["detected"]:
        if report is not None:
            new = [x for x in report["findings"] if x["status"] == "new"]
            if new:
                f.append(f"oczekiwano braku nowego findingu, jest {len(new)}: "
                         + ", ".join(x["rule"] for x in new))
        if state["posture"] != exp["posture"]:
            f.append(f"state.posture '{state['posture']}' != oczekiwane '{exp['posture']}'")
        return f

    # --- scenariusz wykrywany ---
    if report is None:
        return ["oczekiwano raportu, nie powstał"]

    if report["verdict"]["posture"] != exp["posture"]:
        f.append(f"verdict.posture '{report['verdict']['posture']}' != '{exp['posture']}'")

    if "coverage" in exp and report["verdict"]["coverage"] != exp["coverage"]:
        f.append(f"verdict.coverage '{report['verdict']['coverage']}' != '{exp['coverage']}'")

    hits = [x for x in report["findings"] if x["rule"] == exp["rule"]]
    if not hits:
        f.append(f"brak findingu rule={exp['rule']}")
        return f
    finding = hits[0]

    if finding["status"] != "new":
        f.append(f"finding {exp['rule']}: status '{finding['status']}' != 'new'")
    if "rule_source" in exp and finding["rule_source"] != exp["rule_source"]:
        f.append(f"finding.rule_source '{finding['rule_source']}' != '{exp['rule_source']}'")
    if "phase" in exp and finding["phase"] != exp["phase"]:
        f.append(f"finding.phase '{finding['phase']}' != '{exp['phase']}'")

    acts = [a for a in report["actions"] if a["fingerprint"] == finding["fingerprint"]]

    if "action" in exp:
        allowed = ACTION_MAP[exp["action"]]
        if not acts:
            f.append(f"brak akcji dla findingu (oczekiwano {exp['action']})")
        elif acts[0]["type"] not in allowed:
            f.append(f"action.type '{acts[0]['type']}' nie pasuje do expect.action '{exp['action']}'")
        elif acts[0]["type"] == "auto-remediate" and acts[0]["status"] != "succeeded":
            f.append(f"auto-remediate.status '{acts[0]['status']}' != 'succeeded'")

    es = exp.get("end_state")
    if es == "baseline":
        ok = acts and acts[0].get("verification") and acts[0]["verification"]["result"] == "resolved"
        if not ok:
            f.append("end_state=baseline: brak verification.result=resolved")
    elif es == "unchanged":
        if any(a["type"] == "auto-remediate" for a in acts):
            f.append("end_state=unchanged: wykonano auto-remediate")

    return f

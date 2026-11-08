"""Raport i stan (ADR-005): R1, R2, R3, ULID, łańcuch raportów, zapis atomowy.

R1 i R2 są tu liczone niezależnie od tools/validate_report.py: walidator ma sprawdzać
wynik agenta, a nie powtarzać ten sam kod.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import secrets
from datetime import datetime
from pathlib import Path

from agent.config import Context
from agent.evidence import local_ref
from agent.findings import ACCESS_LOST_RULE, Finding, Reconciled, render_values

SCHEMA_VERSION = "1.0.0"
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def timestamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def new_ulid(moment: datetime) -> str:
    value = (int(moment.timestamp() * 1000) << 80) | secrets.randbits(80)
    return "".join(CROCKFORD[(value >> shift) & 31] for shift in range(125, -1, -5))


def derive_coverage(collection: dict) -> str:
    required_ok = all(layer["status"] == "ok" for layer in collection.values() if layer["required"])
    return "full" if required_ok else "partial"


def derive_posture(indicators: list[bool], sources: list[str], coverage: str) -> str:
    if any(indicators):
        return "compromise-suspected"
    if "universal" in sources:
        return "policy-violation"
    if "local" in sources:
        return "site-drift"
    return "inconclusive" if coverage == "partial" else "no-violations"


def state_posture(open_findings: list[dict], coverage: str) -> str:
    return derive_posture([f["compromise_indicator"] for f in open_findings],
                          [f["rule_source"] for f in open_findings], coverage)


def should_report(prev_state: dict | None, posture: str, coverage: str, reconciled: Reconciled,
                  actions: list[dict], error_kinds: list[str], prev_error_kinds: list[str]) -> bool:
    """R3. Błąd przebiegu liczy się przy zmianie zestawu błędów: trwała awaria nie może
    wydłużać łańcucha raportem co 5 minut."""
    if prev_state is None or actions or reconciled.resolved:
        return True
    if any(f.status == "new" for f in reconciled.findings):
        return True
    if posture != prev_state["posture"] or coverage != prev_state["coverage"]:
        return True
    return sorted(error_kinds) != sorted(prev_error_kinds)


L2_EVIDENCE = "zeek"
STATIC_TRUST = {"observed_by": ["L1"], "corroborated_by": [], "contradicted_by": [], "divergence": False}


def _evidence(finding: Finding, run_id: str) -> dict:
    v = finding.violation
    if v.evidence is not None:
        return {"type": "behavioral", **v.evidence, "local_ref": local_ref(run_id, L2_EVIDENCE)}
    if v.rule == ACCESS_LOST_RULE:
        return {"type": "access", "stage": "l1-auth", "result": "rejected",
                "local_ref": local_ref(run_id, "l1")}
    return {"type": "state", "path": v.path, "expected": render_values(v.expected),
            "observed": render_values(v.observed), "local_ref": local_ref(run_id, "l1")}


def _finding_doc(finding: Finding, run_id: str) -> dict:
    v = finding.violation
    return {
        "fingerprint": finding.fingerprint,
        "rule": v.rule,
        "rule_source": v.rule_source,
        "also_matched": sorted(v.also_matched),
        "phase": v.phase,
        "severity": v.severity,
        "ioc": v.ioc,
        "status": finding.status,
        "first_seen_at": finding.first_seen_at,
        "trust": copy.deepcopy(v.trust or STATIC_TRUST),
        "evidence": _evidence(finding, run_id),
    }


def build_report(ctx: Context, *, run: dict, identity: str | None, version: str | None, collection: dict,
                 reconciled: Reconciled, actions: list[dict], prev_state: dict | None,
                 evaluation_mode: str = "what-if") -> dict:
    findings = [_finding_doc(f, run["run_id"]) for f in reconciled.findings]
    coverage = derive_coverage(collection)
    last = (prev_state or {}).get("last_report")
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "report",
        "run": run,
        "target": {
            "site_id": ctx.site_id,
            "router_id": ctx.router_id,
            "address": ctx.mgmt_address,
            "transport": "api-binary",
            "routeros_version_reported": version[:64] if version else None,
            "identity_reported": identity[:255] if identity else None,
            "profile_used": ctx.profile,
        },
        "policy": {
            "universal_version": ctx.release_tag,
            "universal_commit": ctx.release_commit,
            "local_commit": ctx.local_commit,
            "evaluation_mode": evaluation_mode,
            "mitigation_mode": "auto",
        },
        "collection": collection,
        "verdict": {
            "posture": derive_posture([f["ioc"] for f in findings], [f["rule_source"] for f in findings], coverage),
            "coverage": coverage,
            "findings_total": len(findings),
            "findings_new": sum(1 for f in findings if f["status"] == "new"),
            "findings_resolved": len(reconciled.resolved),
        },
        "findings": findings,
        "resolved": reconciled.resolved,
        "actions": actions,
        "integrity": {
            "report_seq": last["report_seq"] + 1 if last else 1,
            "previous_report_sha256": last["sha256"] if last else None,
        },
    }


def build_state_doc(ctx: Context, *, run: dict, posture: str, coverage: str, open_findings: list[dict],
                    last_report: dict | None) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "state",
        "site_id": ctx.site_id,
        "router_id": ctx.router_id,
        "posture": posture,
        "coverage": coverage,
        "open_findings": open_findings,
        "last_run": {"run_id": run["run_id"], "run_seq": run["run_seq"], "finished_at": run["finished_at"]},
        "last_report": last_report,
        "policy": {"universal_version": ctx.release_tag},
        "heartbeat": {"at": run["finished_at"], "interval_s": ctx.interval_s},
    }


def to_bytes(doc: dict) -> bytes:
    """Postać zapisywana: skrót tych bajtów tworzy łańcuch raportów (R7)."""
    return (json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_bytes(data)
    os.replace(temp, path)

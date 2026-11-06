"""Findingi: fingerprint (R7), redakcja (R6), rozliczenie z poprzednim przebiegiem."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from agent.static_eval import Violation

ACCESS_LOST_RULE = "integrity.management-access-lost"
ACCESS_LOST_PATH = "/login"
ATTR_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
SENSITIVE_ATTR = re.compile(
    r"(^|[.-])(password|passwd|secret|passphrase|key|private-key|pre-shared-key|preshared-key|"
    r"wpa-pre-shared-key|wpa2-pre-shared-key|authentication-key)$"
)
MAX_VALUE = 1024


@dataclass
class Finding:
    fingerprint: str
    violation: Violation
    status: str
    first_seen_at: str


@dataclass
class Reconciled:
    findings: list[Finding] = field(default_factory=list)
    resolved: list[dict] = field(default_factory=list)
    open_findings: list[dict] = field(default_factory=list)


def fingerprint(rule: str, path: str, object_key: str) -> str:
    digest = hashlib.sha256(f"{rule}\n{path}\n{object_key}".encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def access_lost_violation(account: str) -> Violation:
    return Violation(rule=ACCESS_LOST_RULE, rule_source="universal", severity="critical", ioc=True,
                     path=ACCESS_LOST_PATH, object_key=account, expected=None, observed=None)


def _text(value) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)[:MAX_VALUE]


def render_values(values: dict | None) -> dict | None:
    """Wartości do raportu: same napisy, atrybuty wrażliwe w postaci skrótu (R6)."""
    if values is None:
        return None
    out = {}
    for key, value in values.items():
        if value is None or not ATTR_NAME.match(key):
            continue
        text = _text(value)
        if SENSITIVE_ATTR.search(key):
            text = "redacted:sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]
        out[key] = text
    return out


def _open_entry(finding: Finding) -> dict:
    v = finding.violation
    return {"fingerprint": finding.fingerprint, "rule": v.rule, "rule_source": v.rule_source,
            "severity": v.severity, "compromise_indicator": v.ioc, "first_seen_at": finding.first_seen_at}


def reconcile(violations: list[Violation], prev_open: list[dict], *, now: str,
              evaluated_rules: set[str], known_rules: set[str], absorbed: set[str],
              universal_changed: bool, local_changed: bool) -> Reconciled:
    """Finding znika z otwartych tylko po potwierdzeniu: reguła oceniona i nie wykryła
    naruszenia. Brak danych niczego nie rozwiązuje."""
    prev = {p["fingerprint"]: p for p in prev_open}
    out = Reconciled()
    current: set[str] = set()
    for v in sorted(violations, key=lambda x: (x.rule, x.path, x.object_key)):
        fp = fingerprint(v.rule, v.path, v.object_key)
        current.add(fp)
        earlier = prev.get(fp)
        finding = Finding(fp, v, "persisting" if earlier else "new",
                          earlier["first_seen_at"] if earlier else now)
        out.findings.append(finding)
        out.open_findings.append(_open_entry(finding))

    for fp, item in prev.items():
        if fp in current:
            continue
        rule = item["rule"]
        if rule not in known_rules:
            resolved_by = "policy-change"
        elif fp in absorbed or rule not in evaluated_rules:
            out.open_findings.append(item)
            continue
        elif (item["rule_source"] == "local" and local_changed) or \
                (item["rule_source"] == "universal" and universal_changed):
            resolved_by = "policy-change"
        else:
            resolved_by = "external-change"
        out.resolved.append({"fingerprint": fp, "rule": rule, "first_seen_at": item["first_seen_at"],
                             "resolved_at": now, "resolved_by": resolved_by})
    return out

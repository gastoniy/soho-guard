"""Faza statyczna: polityka uniwersalna, reguły lokalne i drift względem baseline.

Moduł czysty: operuje na znormalizowanym stanie, nie otwiera połączeń ani plików.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from agent.normalize import (
    DRIFT_EXCLUDED,
    PATH_TO_KEY,
    RESOURCES,
    SINGLETONS,
    _canon,
    _match_predicate,
    drift_rule_id,
)

DRIFT_DEFAULT_SEVERITY = "medium"


@dataclass
class Violation:
    rule: str
    rule_source: str
    severity: str
    ioc: bool
    path: str
    object_key: str
    expected: dict | None
    observed: dict | None
    remediate: dict | None = None
    also_matched: list[str] = field(default_factory=list)
    where: dict | None = None
    drift: bool = False


@dataclass
class RuleCheck:
    evaluated: bool
    reason: str = ""
    violations: list[Violation] = field(default_factory=list)


@dataclass
class EvalResult:
    violations: list[Violation]
    evaluated_rules: set[str]
    known_rules: set[str]
    unevaluated: list[dict]
    # Naruszenia pochłonięte przez regułę o pierwszeństwie: (reguła, ścieżka, obiekt)
    absorbed: list[tuple[str, str, str]]


def ignored_attrs(local_doc: dict) -> dict[str, set[str]]:
    """Atrybuty wyłączone z driftu wpisami drift.ignore polityki lokalnej."""
    ignored: dict[str, set[str]] = {}
    for entry in (local_doc.get("drift") or {}).get("ignore", []):
        ignored.setdefault(entry["resource"], set()).update(entry["attrs"])
    return ignored


def _path_of(resource: str) -> str:
    return "/" + "/".join(RESOURCES[resource])


def _without(row: dict, ignored: set[str]) -> dict:
    return {k: v for k, v in row.items() if k not in ignored}


def _content_key(row: dict) -> str:
    canonical = json.dumps(row, sort_keys=True, ensure_ascii=False, default=str)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def object_keys(resource: str, rows: list[dict], ignored: set[str] | None = None) -> list[str]:
    """Stały klucz każdego wiersza. Singleton: ostatni segment ścieżki. Wiersz nazwany:
    nazwa, a gdy się powtarza, także proto (/ip/service: resolver tcp i udp). Wiersz bez
    nazwy (reguła firewalla, adres): skrót treści, bez atrybutów ignorowanych w drifcie."""
    ignored = ignored or set()
    if resource in SINGLETONS:
        bases = [RESOURCES[resource][-1]] * len(rows)
    else:
        bases = [str(r["name"]) if r.get("name") else _content_key(_without(r, ignored)) for r in rows]
        repeated = {b for b in bases if bases.count(b) > 1}
        bases = [f"{b}/{r['proto']}" if b in repeated and r.get("proto") else b
                 for b, r in zip(bases, rows)]
    seen: dict[str, int] = {}
    keys = []
    for base in bases:
        seen[base] = seen.get(base, 0) + 1
        keys.append(base if seen[base] == 1 else f"{base}#{seen[base]}")
    return keys


def _describe(cond) -> str:
    if not isinstance(cond, dict):
        return str(cond)
    if cond.get("private") is True:
        return "private"
    if cond.get("not_empty") is True:
        return "not-empty"
    if "one_of" in cond:
        return "one-of: " + ",".join(map(str, cond["one_of"]))
    if "not_one_of" in cond:
        return "not-one-of: " + ",".join(map(str, cond["not_one_of"]))
    return json.dumps(cond, sort_keys=True)


def check_rule(rule: dict, state: dict, rule_source: str = "universal",
               ignored: dict[str, set[str]] | None = None) -> RuleCheck:
    """Reguła z blokiem check, wspólna dla polityki uniwersalnej, lokalnej i onboardingu."""
    check = rule["check"]
    path = check["path"]
    resource = PATH_TO_KEY.get(path)
    if resource is None:
        return RuleCheck(False, f"ścieżka {path} nie jest zbierana (RESOURCES)")
    if resource not in state:
        return RuleCheck(False, f"menu {path} nieodczytane z urządzenia")

    rows = state[resource]
    keys = object_keys(resource, rows, (ignored or {}).get(resource))
    where = check.get("where")
    pairs = [(k, r) for k, r in zip(keys, rows)
             if not where or all(_match_predicate(r.get(a), c) for a, c in where.items())]
    asserts = check["assert"]

    def violation(key: str, expected: dict | None, observed: dict) -> Violation:
        return Violation(rule=rule["id"], rule_source=rule_source, severity=rule["severity"],
                         ioc=bool(rule.get("ioc", False)), path=path, object_key=key,
                         expected=expected, observed=observed, remediate=rule.get("remediate"), where=where)

    found: list[Violation] = []
    if check.get("scope") == "none-match":
        for key, row in pairs:
            if all(_match_predicate(row.get(a), c) for a, c in asserts.items()):
                found.append(violation(key, None, {a: row.get(a) for a in asserts}))
        return RuleCheck(True, violations=found)

    if not pairs and (where or resource in SINGLETONS):
        return RuleCheck(False, f"brak wiersza {path} spełniającego selektor reguły")
    for key, row in pairs:
        bad = [a for a, c in asserts.items() if not _match_predicate(row.get(a), c)]
        if bad:
            found.append(violation(key, {a: _describe(asserts[a]) for a in bad},
                                   {a: row.get(a) for a in bad}))
    return RuleCheck(True, violations=found)


def _same(a, b) -> bool:
    return _canon(a) == _canon(b) or (a is not None and b is not None and str(a) == str(b))


def _diff_resource(resource: str, base_rows: list[dict], cur_rows: list[dict], rule_id: str,
                   severity: str, ignored: set[str]) -> list[Violation]:
    path = _path_of(resource)
    base = dict(zip(object_keys(resource, base_rows, ignored),
                    (_without(r, ignored) for r in base_rows)))
    current = dict(zip(object_keys(resource, cur_rows, ignored),
                       (_without(r, ignored) for r in cur_rows)))

    def violation(key: str, expected: dict | None, observed: dict | None) -> Violation:
        return Violation(rule=rule_id, rule_source="local", severity=severity, ioc=False,
                         path=path, object_key=key, expected=expected, observed=observed, drift=True)

    found: list[Violation] = []
    for key in sorted(set(base) | set(current)):
        if key not in current:
            found.append(violation(key, base[key], None))
        elif key not in base:
            found.append(violation(key, None, current[key]))
        else:
            attrs = sorted(a for a in set(base[key]) | set(current[key])
                           if not _same(base[key].get(a), current[key].get(a)))
            if attrs:
                found.append(violation(key, {a: base[key].get(a) for a in attrs},
                                       {a: current[key].get(a) for a in attrs}))
    return found


def evaluate(state: dict, universal_rules: list[dict], local_doc: dict, baseline: dict) -> EvalResult:
    """Precedencja: reguła uniwersalna przed lokalną, reguła lokalna przed driftem. Reguła
    niższego poziomu na tym samym obiekcie nie tworzy osobnego naruszenia."""
    drift_cfg = local_doc.get("drift") or {}
    overrides = {o["resource"]: o for o in drift_cfg.get("overrides", [])}
    ignored = ignored_attrs(local_doc)

    result = EvalResult([], set(), set(), [], [])
    universal_by_object: dict[tuple[str, str], list[Violation]] = {}
    local_objects: set[tuple[str, str]] = set()

    def absorb(item: Violation, higher: Violation | None = None):
        result.absorbed.append((item.rule, item.path, item.object_key))
        if higher is not None and item.rule not in higher.also_matched:
            higher.also_matched.append(item.rule)

    def run_rule(rule: dict, source: str) -> list[Violation]:
        result.known_rules.add(rule["id"])
        check = check_rule(rule, state, source, ignored)
        if check.evaluated:
            result.evaluated_rules.add(rule["id"])
        else:
            result.unevaluated.append({"rule": rule["id"], "reason": check.reason})
        return check.violations

    for rule in universal_rules:
        if rule.get("phase") != "static" or "check" not in rule:
            continue
        for item in run_rule(rule, "universal"):
            universal_by_object.setdefault((item.path, item.object_key), []).append(item)
            result.violations.append(item)

    for rule in local_doc.get("rules", []):
        for item in run_rule(rule, "local"):
            obj = (item.path, item.object_key)
            if obj in universal_by_object:
                absorb(item, universal_by_object[obj][0])
            else:
                local_objects.add(obj)
                result.violations.append(item)

    for resource in RESOURCES:
        if resource in DRIFT_EXCLUDED:
            continue
        override = overrides.get(resource)
        rule_id = override["id"] if override else drift_rule_id(resource)
        severity = override["severity"] if override else DRIFT_DEFAULT_SEVERITY
        result.known_rules.add(rule_id)
        in_base, in_state = resource in baseline, resource in state
        if in_base and not in_state:
            result.unevaluated.append({"rule": rule_id, "reason": f"menu {_path_of(resource)} nieodczytane z urządzenia"})
            continue
        if in_state and not in_base and state[resource]:
            result.unevaluated.append({"rule": rule_id, "reason": f"zasobu {resource} nie ma we wzorcu baseline"})
            continue
        result.evaluated_rules.add(rule_id)
        if not (in_base and in_state):
            continue
        for item in _diff_resource(resource, baseline[resource], state[resource], rule_id, severity,
                                   ignored.get(resource, set())):
            obj = (item.path, item.object_key)
            if obj in universal_by_object:
                absorb(item, universal_by_object[obj][0])
            elif obj in local_objects:
                absorb(item)
            else:
                result.violations.append(item)
    return result

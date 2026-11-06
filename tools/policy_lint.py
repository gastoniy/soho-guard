#!/usr/bin/env python3
"""Walidacja plików polityki uniwersalnej (ADR-002/B2) i lokalnej.

Poziomy:
  1. struktura   - JSON Schema 2020-12 (schemas/policy.schema.json)
  2. spójność    - między plikami: unikalność id w całym policy/, prefiks
                   id zgodny z warstwą (policy.*/integrity.* = universal),
                   phase pliku zgodna z layer, obecność trace.timeline.

Polityka lokalna (--local): struktura wg schemas/local-policy.schema.json oraz
spójność z zasobami agenta (RESOURCES), unikalność id i rezerwacja local.drift.*.

Użycie: policy_lint.py policy/            (katalog, rekurencyjnie)
        policy_lint.py plik.yml...
        policy_lint.py --local routers/*/local-policy.yml
Kod: 0 OK, 1 naruszenie, 2 błąd. Wymaga PyYAML, jsonschema>=4.18.
"""
from __future__ import annotations
import json, sys
from pathlib import Path
import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent.normalize import DRIFT_EXCLUDED, DRIFT_PREFIX, PATH_TO_KEY, RESOURCES, drift_rule_id  # noqa: E402

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"


def _validator(schema="policy.schema.json"):
    res = []
    for p in SCHEMA_DIR.glob("*.json"):
        d = json.loads(p.read_text(encoding="utf-8"))
        res.append((d["$id"], Resource.from_contents(d)))
    reg = Registry().with_resources(res)
    pol = json.loads((SCHEMA_DIR / schema).read_text(encoding="utf-8"))
    return Draft202012Validator(pol, registry=reg)


_V = _validator()
_V_LOCAL = _validator("local-policy.schema.json")


def _files(args):
    out = []
    for a in args:
        p = Path(a)
        if p.is_dir():
            out += sorted(p.rglob("*.yml")) + sorted(p.rglob("*.yaml"))
        else:
            out.append(p)
    return out


def lint(paths) -> list[str]:
    issues = []
    seen_ids: dict[str, str] = {}
    files = _files(paths)
    if not files:
        return ["brak plików polityki"]
    for path in files:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        errs = sorted(_V.iter_errors(doc), key=lambda e: list(e.absolute_path))
        if errs:
            for e in errs:
                issues.append(f"{path.name} /" + "/".join(map(str, e.absolute_path)) + ": " + e.message)
            continue
        layer = doc["layer"]
        for i, r in enumerate(doc["rules"]):
            rid = r["id"]
            if rid in seen_ids:
                issues.append(f"{path.name}: zduplikowane id {rid} (też w {seen_ids[rid]})")
            seen_ids[rid] = path.name
            # prefiks → universal (policy.* lub integrity.*), nigdy local.*
            if rid.startswith("local."):
                issues.append(f"{path.name}: {rid} ma prefiks lokalny w polityce uniwersalnej")
            # phase reguły zgodna z layer pliku
            if r["phase"] != layer:
                issues.append(f"{path.name}: {rid} phase={r['phase']} != layer={layer}")
            # trace.timeline niepuste (identyfikowalność)
            if not r["trace"].get("timeline"):
                issues.append(f"{path.name}: {rid} bez trace.timeline")
    return issues


def _lint_local_doc(name: str, doc: dict) -> list[str]:
    issues = []
    drift = doc.get("drift", {})
    seen_ids: set[str] = set()

    def check_id(rid: str):
        if rid in seen_ids:
            issues.append(f"{name}: zduplikowane id {rid}")
        seen_ids.add(rid)

    def check_resource(where: str, resource: str):
        if resource not in RESOURCES:
            issues.append(f"{name}: {where}: nieznany zasób {resource}")
        elif resource in DRIFT_EXCLUDED:
            issues.append(f"{name}: {where}: zasób {resource} jest poza driftem")

    seen_overrides: set[str] = set()
    for i, o in enumerate(drift.get("overrides", [])):
        where = f"drift/overrides/{i}"
        check_resource(where, o["resource"])
        if o["resource"] in seen_overrides:
            issues.append(f"{name}: {where}: drugi override zasobu {o['resource']}")
        seen_overrides.add(o["resource"])
        check_id(o["id"])
        if o["id"].startswith(DRIFT_PREFIX) and o["id"] != drift_rule_id(o["resource"]):
            issues.append(f"{name}: {where}: id {o['id']} nie pasuje do zasobu "
                          f"(zarezerwowane: {drift_rule_id(o['resource'])})")
    for i, entry in enumerate(drift.get("ignore", [])):
        check_resource(f"drift/ignore/{i}", entry["resource"])
    for i, r in enumerate(doc.get("rules", [])):
        check_id(r["id"])
        if r["id"].startswith(DRIFT_PREFIX):
            issues.append(f"{name}: rules/{i}: prefiks {DRIFT_PREFIX} jest zarezerwowany dla driftu")
        if r["check"]["path"] not in PATH_TO_KEY:
            issues.append(f"{name}: rules/{i}: ścieżka {r['check']['path']} nie jest zbierana (RESOURCES)")
    return issues


def lint_local(paths) -> list[str]:
    """Każdy plik oceniany osobno: identyfikatory obowiązują w obrębie routera."""
    issues = []
    files = _files(paths)
    if not files:
        return ["brak plików polityki lokalnej"]
    for path in files:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        errs = sorted(_V_LOCAL.iter_errors(doc), key=lambda e: list(e.absolute_path))
        if errs:
            for e in errs:
                issues.append(f"{path} /" + "/".join(map(str, e.absolute_path)) + ": " + e.message)
            continue
        issues += _lint_local_doc(str(path), doc)
    return issues


def main(argv):
    local = argv[:1] == ["--local"]
    if local:
        argv = argv[1:]
    if not argv:
        print("użycie: policy_lint.py policy/ | plik.yml... | --local plik.yml...", file=sys.stderr)
        return 2
    try:
        issues = lint_local(argv) if local else lint(argv)
    except (OSError, yaml.YAMLError) as e:
        print(f"ERROR {e}", file=sys.stderr)
        return 2
    for i in issues:
        print("FAIL " + i)
    if not issues:
        print("OK: polityka spójna")
    return 1 if issues else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

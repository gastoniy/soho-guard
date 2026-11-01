#!/usr/bin/env python3
"""Walidacja plików polityki uniwersalnej (ADR-002/B2).

Poziomy:
  1. struktura   - JSON Schema 2020-12 (schemas/policy.schema.json)
  2. spójność    - między plikami: unikalność id w całym policy/, prefiks
                   id zgodny z warstwą (policy.*/integrity.* = universal),
                   phase pliku zgodna z layer, obecność trace.timeline.

Użycie: policy_lint.py policy/            (katalog, rekurencyjnie)
        policy_lint.py plik.yml...
Kod: 0 OK, 1 naruszenie, 2 błąd. Wymaga PyYAML, jsonschema>=4.18.
"""
from __future__ import annotations
import json, sys
from pathlib import Path
import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"


def _validator():
    res = []
    for p in SCHEMA_DIR.glob("*.json"):
        d = json.loads(p.read_text(encoding="utf-8"))
        res.append((d["$id"], Resource.from_contents(d)))
    reg = Registry().with_resources(res)
    pol = json.loads((SCHEMA_DIR / "policy.schema.json").read_text(encoding="utf-8"))
    return Draft202012Validator(pol, registry=reg)


_V = _validator()


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


def main(argv):
    if not argv:
        print("użycie: policy_lint.py policy/ | plik.yml...", file=sys.stderr)
        return 2
    try:
        issues = lint(argv)
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

#!/usr/bin/env python3
"""Walidacja manifestu scenariusza (ADR-005 / B1).

Dwa poziomy:
  1. struktura   - JSON Schema 2020-12 (schemas/scenario.schema.json)
  2. spójność    - reguły zależne od klasy, których JSON Schema nie wyraża:
                   zgodność expect z class, posture z rule_source (R1 z ADR-005),
                   prefiks reguły z pochodzeniem.

Użycie: manifest_lint.py scenariusz.yml...
Kod wyjścia: 0 = OK, 1 = naruszenie, 2 = błąd odczytu/użycia.
Wymaga: PyYAML, jsonschema>=4.18.
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
        doc = json.loads(p.read_text(encoding="utf-8"))
        res.append((doc["$id"], Resource.from_contents(doc)))
    reg = Registry().with_resources(res)
    scn = json.loads((SCHEMA_DIR / "scenario.schema.json").read_text(encoding="utf-8"))
    return Draft202012Validator(scn, registry=reg, format_checker=Draft202012Validator.FORMAT_CHECKER)


_V = _validator()

# Dozwolony kształt expect per klasa. None = pole musi być nieobecne.
CLASS_RULES = {
    # policy: action i end_state sprawdzane parami (POLICY_ACTION_END_STATE).
    "policy":  dict(detected=True,  rule_source="universal", action={"auto-remediate", "none"},
                    end_state={"baseline", "unchanged"},
                    posture={"policy-violation", "compromise-suspected"},
                    phase={"static", "dynamic"}, generate=False),
    "site":    dict(detected=True,  rule_source="local", action={"pr-alert"},
                    end_state="unchanged", posture={"site-drift"},
                    phase={"static"}, generate=False),
    "benign":  dict(detected=False, rule_source=None, action=None,
                    end_state=None, posture={"no-violations"}, phase=None, generate=False),
    "dynamic": dict(detected=True,  rule_source={"universal", "local"},
                    action={"alert", "pr-alert", "auto-remediate"}, end_state=None,
                    posture={"compromise-suspected", "policy-violation"},
                    phase={"dynamic"}, generate=True),
    "control": dict(detected=False, rule_source=None, action=None,
                    end_state=None, posture={"no-violations"}, phase=None, generate=True),
}

# D-A: reguła uniwersalna z remediate -> naprawa i powrót do baseline;
# reguła uniwersalna bez remediate -> akcja none, router bez zmian.
POLICY_ACTION_END_STATE = {"auto-remediate": "baseline", "none": "unchanged"}


def _struct_errors(doc) -> list[str]:
    out = []
    for e in sorted(_V.iter_errors(doc), key=lambda e: list(e.absolute_path)):
        out.append("struktura /" + "/".join(map(str, e.absolute_path)) + ": " + e.message)
    return out


def _consistency_errors(doc) -> list[str]:
    out = []
    cls = doc["class"]
    rules = CLASS_RULES[cls]
    exp = doc["expect"]

    if exp["detected"] != rules["detected"]:
        out.append(f"class={cls} wymaga expect.detected={rules['detected']}")
    if exp["posture"] not in rules["posture"]:
        out.append(f"class={cls}: posture '{exp['posture']}' spoza {sorted(rules['posture'])}")

    for field in ("rule_source", "end_state"):
        want = rules[field]
        have = exp.get(field)
        if want is None and have is not None:
            out.append(f"class={cls}: expect.{field} nie powinno występować")
        elif isinstance(want, str) and have != want:
            out.append(f"class={cls}: expect.{field} '{have}' != '{want}'")
        elif isinstance(want, set) and have not in want:
            out.append(f"class={cls}: expect.{field} '{have}' spoza {sorted(want)}")

    if rules["action"] is None:
        if "action" in exp:
            out.append(f"class={cls}: expect.action nie powinno występować")
    else:
        if exp.get("action") not in rules["action"]:
            out.append(f"class={cls}: action '{exp.get('action')}' spoza {sorted(rules['action'])}")

    if cls == "policy":
        act, es = exp.get("action"), exp.get("end_state")
        want_es = POLICY_ACTION_END_STATE.get(act)
        if want_es is not None and es in POLICY_ACTION_END_STATE.values() and es != want_es:
            out.append(f"class=policy: action '{act}' wymaga end_state '{want_es}', jest '{es}'")

    if rules["phase"] is not None and exp.get("phase") not in rules["phase"]:
        out.append(f"class={cls}: phase '{exp.get('phase')}' spoza {sorted(rules['phase'])}")

    if rules["generate"] and "generate" not in doc:
        out.append(f"class={cls} wymaga bloku generate")
    if not rules["generate"] and "generate" in doc:
        out.append(f"class={cls} nie powinna mieć bloku generate")

    # control: ruch musi pochodzić z innego routera
    if cls == "control" and doc.get("generate", {}).get("from") != "other-router":
        out.append("class=control: generate.from musi być 'other-router'")

    # R1 (ADR-005): spójność prefiksu reguły z rule_source
    if exp.get("detected") and "rule" in exp:
        is_local = exp["rule"].startswith("local.")
        src = exp.get("rule_source")
        if is_local and src != "local":
            out.append(f"reguła {exp['rule']} jest lokalna, a rule_source={src}")
        if not is_local and src == "local":
            out.append(f"reguła {exp['rule']} nie jest lokalna, a rule_source=local")

    # divergence → compromise-suspected
    if exp.get("rule", "").startswith("integrity.divergence") and exp.get("posture") != "compromise-suspected":
        out.append("reguła rozbieżności wymaga posture=compromise-suspected")
    return out


def validate(path: Path) -> list[str]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    errs = _struct_errors(doc)
    if errs:
        return errs
    return _consistency_errors(doc)


def main(argv):
    if not argv:
        print("użycie: manifest_lint.py scenariusz.yml...", file=sys.stderr)
        return 2
    failed = False
    try:
        for a in argv:
            p = Path(a)
            errs = validate(p)
            if errs:
                failed = True
                print(f"FAIL {p.name}")
                for e in errs:
                    print("     " + e)
            else:
                print(f"OK   {p.name}")
    except (OSError, yaml.YAMLError) as e:
        print(f"ERROR {e}", file=sys.stderr)
        return 2
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

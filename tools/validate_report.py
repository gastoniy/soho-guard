#!/usr/bin/env python3
"""Walidator kontraktu raportu agenta soho-guard (ADR-005).

Dwa poziomy kontroli:
  1. struktura  - JSON Schema 2020-12 (schemas/*.schema.json)
  2. semantyka  - reguły międzypolowe, których JSON Schema nie wyraża:
                  R1 posture, R2 coverage, R6 prywatność i redakcja,
                  R8 wybór akcji (dwa tory), spójność liczników i odnośników

Użycie:
  validate_report.py report <plik>... [--lan-prefix CIDR ...]
  validate_report.py state  <plik>...
  validate_report.py chain  <katalog>

Kod wyjścia: 0 = poprawne, 1 = naruszenie kontraktu, 2 = błąd użycia lub odczytu.

WAŻNE (ADR-005): agent NIE importuje tego modułu do wyznaczania własnego wyroku.
Walidator jest niezależną implementacją reguł. Wspólny kod sprawiłby, że błąd
w regule przechodziłby walidację niezauważony - ta sama zasada, co rozdział
kodu harnessu i agenta.

Wymagania: Python >= 3.10, jsonschema >= 4.18.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from datetime import datetime
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import best_match
from referencing import Registry, Resource

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"

# R6: klucze atrybutów, których wartości muszą być zredagowane.
SENSITIVE_KEY = re.compile(
    r"(^|[.-])(password|passwd|secret|passphrase|private-key|pre-shared-key|"
    r"wpa-pre-shared-key|wpa2-pre-shared-key|authentication-key|key)$"
)
REDACTED = re.compile(r"^redacted:sha256:[0-9a-f]{8}$")

POSTURE_ORDER = ("compromise-suspected", "policy-violation", "site-drift", "inconclusive", "no-violations")


# --------------------------------------------------------------------------- #
# Ładowanie schematów
# --------------------------------------------------------------------------- #
def _load_schemas() -> tuple[dict[str, dict], Registry]:
    schemas: dict[str, dict] = {}
    resources = []
    for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        schemas[path.name] = doc
        resources.append((doc["$id"], Resource.from_contents(doc)))
    return schemas, Registry().with_resources(resources)


_SCHEMAS, _REGISTRY = _load_schemas()


def _validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(
        _SCHEMAS[name],
        registry=_REGISTRY,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


def _structural_errors(doc: object, schema_name: str) -> list[str]:
    errors = []
    for err in sorted(_validator(schema_name).iter_errors(doc), key=lambda e: list(e.absolute_path)):
        pointer = "/" + "/".join(str(p) for p in err.absolute_path)
        message = err.message
        if err.context:
            message += f" [{best_match(err.context).message}]"
        errors.append(f"struktura {pointer}: {message}")
    return errors


# --------------------------------------------------------------------------- #
# Reguły
# --------------------------------------------------------------------------- #
def _ts(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")


def derive_posture(items: list[tuple[bool, str]], coverage: str) -> str:
    """R1. items: (wskaźnik_kompromitacji, rule_source) dla każdego naruszenia."""
    if any(indicator for indicator, _ in items):
        return "compromise-suspected"
    if any(source == "universal" for _, source in items):
        return "policy-violation"
    if any(source == "local" for _, source in items):
        return "site-drift"
    if coverage == "partial":
        return "inconclusive"
    return "no-violations"


def derive_coverage(collection: dict) -> str:
    """R2."""
    for layer in collection.values():
        if layer["required"] and layer["status"] != "ok":
            return "partial"
    return "full"


def allowed_action_types(finding: dict, mitigation_mode: str) -> set[str]:
    """R8. Dopuszczalne typy akcji dla naruszenia."""
    if finding["trust"]["divergence"] or finding["ioc"]:
        return {"alert"}
    if finding["rule_source"] == "universal":
        if mitigation_mode == "auto":
            return {"auto-remediate", "none"}
        return {"open-pr", "alert", "none"}
    return {"open-pr", "alert", "none"}


def _semantic_report_errors(doc: dict, lan_nets: list) -> list[str]:
    errors: list[str] = []
    findings = doc["findings"]
    by_fp = {}
    for i, f in enumerate(findings):
        if f["fingerprint"] in by_fp:
            errors.append(f"/findings/{i}: zduplikowany fingerprint {f['fingerprint']}")
        by_fp[f["fingerprint"]] = f

    # Spójność liczników
    v = doc["verdict"]
    if v["findings_total"] != len(findings):
        errors.append(f"/verdict/findings_total: {v['findings_total']} != liczba findingów {len(findings)}")
    new_count = sum(1 for f in findings if f["status"] == "new")
    if v["findings_new"] != new_count:
        errors.append(f"/verdict/findings_new: {v['findings_new']} != liczba findingów 'new' {new_count}")
    if v["findings_resolved"] != len(doc["resolved"]):
        errors.append(f"/verdict/findings_resolved: {v['findings_resolved']} != liczba w resolved {len(doc['resolved'])}")

    # Rozwiązane nie mogą jednocześnie być wykryte
    for i, r in enumerate(doc["resolved"]):
        if r["fingerprint"] in by_fp:
            errors.append(f"/resolved/{i}: fingerprint jest jednocześnie w findings")
        if _ts(r["resolved_at"]) < _ts(r["first_seen_at"]):
            errors.append(f"/resolved/{i}: resolved_at wcześniejsze niż first_seen_at")

    # Prefiks reguły a pochodzenie; rozbieżność a sprzeczne warstwy
    for i, f in enumerate(findings):
        expected_source = "local" if f["rule"].startswith("local.") else "universal"
        if f["rule_source"] != expected_source:
            errors.append(f"/findings/{i}/rule_source: reguła {f['rule']} wymaga '{expected_source}'")
        if bool(f["trust"]["contradicted_by"]) != f["trust"]["divergence"]:
            errors.append(f"/findings/{i}/trust: divergence musi być prawdą wtedy i tylko wtedy, gdy contradicted_by jest niepuste")

    # R2
    expected_cov = derive_coverage(doc["collection"])
    if v["coverage"] != expected_cov:
        errors.append(f"/verdict/coverage: '{v['coverage']}', wg R2 powinno być '{expected_cov}'")

    # R1 (na podstawie coverage wyliczonego, nie deklarowanego)
    items = [(f["trust"]["divergence"] or f["ioc"], f["rule_source"]) for f in findings]
    expected_posture = derive_posture(items, expected_cov)
    if v["posture"] != expected_posture:
        errors.append(f"/verdict/posture: '{v['posture']}', wg R1 powinno być '{expected_posture}'")

    # R8 + odnośniki akcji
    mitigation = doc["policy"]["mitigation_mode"]
    actions_per_fp: dict[str, int] = {}
    for i, a in enumerate(doc["actions"]):
        fp = a["fingerprint"]
        actions_per_fp[fp] = actions_per_fp.get(fp, 0) + 1
        finding = by_fp.get(fp)
        if finding is None:
            errors.append(f"/actions/{i}/fingerprint: brak findingu o tym fingerprincie w raporcie")
            continue
        allowed = allowed_action_types(finding, mitigation)
        if a["type"] not in allowed:
            errors.append(
                f"/actions/{i}/type: '{a['type']}' niedozwolone dla {finding['rule']} "
                f"(R8, dozwolone: {', '.join(sorted(allowed))})"
            )
        if a["started_at"] and a["finished_at"] and _ts(a["finished_at"]) < _ts(a["started_at"]):
            errors.append(f"/actions/{i}: finished_at wcześniejsze niż started_at")
    for i, f in enumerate(findings):
        count = actions_per_fp.get(f["fingerprint"], 0)
        if f["status"] == "new" and count != 1:
            errors.append(f"/findings/{i}: nowe naruszenie wymaga dokładnie jednej akcji, jest {count}")
        if f["status"] == "persisting" and count > 1:
            errors.append(f"/findings/{i}: utrzymujące się naruszenie może mieć najwyżej jedną akcję, jest {count}")

    # R6: redakcja wartości wrażliwych i brak hostów LAN
    for i, f in enumerate(findings):
        ev = f["evidence"]
        if ev["type"] == "state":
            for side in ("expected", "observed"):
                values = ev[side] or {}
                for key, value in values.items():
                    if SENSITIVE_KEY.search(key) and not REDACTED.match(value):
                        errors.append(f"/findings/{i}/evidence/{side}/{key}: wartość wrażliwa niezredagowana (R6)")
        if ev["type"] == "behavioral" and lan_nets:
            dest = ipaddress.ip_address(ev["l2_observation"]["destination"])
            if any(dest in net for net in lan_nets):
                errors.append(f"/findings/{i}/evidence/l2_observation/destination: adres z prefiksu LAN instalacji (R6)")

    # Czas przebiegu
    run = doc["run"]
    if _ts(run["finished_at"]) < _ts(run["started_at"]):
        errors.append("/run: finished_at wcześniejsze niż started_at")
    return errors


def _semantic_state_errors(doc: dict) -> list[str]:
    errors: list[str] = []
    seen = set()
    for i, f in enumerate(doc["open_findings"]):
        if f["fingerprint"] in seen:
            errors.append(f"/open_findings/{i}: zduplikowany fingerprint")
        seen.add(f["fingerprint"])
        expected_source = "local" if f["rule"].startswith("local.") else "universal"
        if f["rule_source"] != expected_source:
            errors.append(f"/open_findings/{i}/rule_source: reguła {f['rule']} wymaga '{expected_source}'")
    items = [(f["compromise_indicator"], f["rule_source"]) for f in doc["open_findings"]]
    expected = derive_posture(items, doc["coverage"])
    if doc["posture"] != expected:
        errors.append(f"/posture: '{doc['posture']}', wg R1 powinno być '{expected}'")
    if _ts(doc["heartbeat"]["at"]) < _ts(doc["last_run"]["finished_at"]):
        errors.append("/heartbeat/at: wcześniejsze niż zakończenie ostatniego przebiegu")
    return errors


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
def validate_report(doc: object, lan_prefixes: list[str] | None = None) -> list[str]:
    errors = _structural_errors(doc, "report.schema.json")
    if errors:
        return errors
    nets = [ipaddress.ip_network(p, strict=False) for p in (lan_prefixes or [])]
    return _semantic_report_errors(doc, nets)  # type: ignore[arg-type]


def validate_state(doc: object) -> list[str]:
    errors = _structural_errors(doc, "state.schema.json")
    if errors:
        return errors
    return _semantic_state_errors(doc)  # type: ignore[arg-type]


def validate_chain(directory: Path) -> list[str]:
    """Łańcuch raportów jednego routera. Podkatalog what-if/ tworzy osobny łańcuch
    i jest pomijany, chyba że zostanie wskazany bezpośrednio."""
    errors: list[str] = []
    entries = []
    for path in sorted(directory.rglob("*.json")):
        if "what-if" in path.relative_to(directory).parts:
            continue
        raw = path.read_bytes()
        doc = json.loads(raw)
        entries.append((doc["integrity"]["report_seq"], path, raw, doc))
    if not entries:
        return [f"{directory}: brak raportów"]
    entries.sort(key=lambda e: e[0])

    routers = {e[3]["target"]["router_id"] for e in entries}
    if len(routers) > 1:
        errors.append(f"{directory}: raporty różnych routerów w jednym łańcuchu: {sorted(routers)}")

    previous_raw = None
    for expected_seq, (seq, path, raw, doc) in enumerate(entries, start=1):
        if seq != expected_seq:
            errors.append(f"{path.name}: report_seq {seq}, oczekiwano {expected_seq} (luka lub duplikat)")
            break
        declared = doc["integrity"]["previous_report_sha256"]
        if previous_raw is None:
            if declared is not None:
                errors.append(f"{path.name}: pierwszy raport musi mieć previous_report_sha256 = null")
        else:
            actual = hashlib.sha256(previous_raw).hexdigest()
            if declared != actual:
                errors.append(f"{path.name}: zerwany łańcuch, poprzedni raport ma sha256 {actual}, zadeklarowano {declared}")
        previous_raw = raw
    return errors


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _load(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Walidator kontraktu raportu agenta soho-guard (ADR-005)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_report = sub.add_parser("report", help="walidacja raportów")
    p_report.add_argument("files", nargs="+", type=Path)
    p_report.add_argument("--lan-prefix", action="append", default=[], metavar="CIDR",
                          help="prefiks LAN instalacji; destynacja L2 z tego prefiksu narusza R6")
    p_state = sub.add_parser("state", help="walidacja plików stanu")
    p_state.add_argument("files", nargs="+", type=Path)
    p_chain = sub.add_parser("chain", help="weryfikacja łańcucha raportów jednego routera")
    p_chain.add_argument("directory", type=Path)
    args = parser.parse_args(argv)

    failed = False
    try:
        if args.cmd == "chain":
            errors = validate_chain(args.directory)
            for e in errors:
                print(f"FAIL {e}")
            if not errors:
                print(f"OK   łańcuch {args.directory}")
            return 1 if errors else 0

        for path in args.files:
            doc = _load(path)
            errors = (validate_report(doc, args.lan_prefix) if args.cmd == "report"
                      else validate_state(doc))
            if errors:
                failed = True
                print(f"FAIL {path}")
                for e in errors:
                    print(f"     {e}")
            else:
                print(f"OK   {path}")
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

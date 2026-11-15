"""Bramka H5: czy router jest w baseline.

Dwa niezależne porównania, oba kontem `ansible`:
  1. `/export terse hide-sensitive` (SSH) z `routers/<id>/export.rsc` w site-lab — pomijany tylko
     nagłówek (linie `#` przed pierwszą linią zaczynającą się od `/`); pozostałe linie `#`, w tym
     `#error exporting`, porównywane dosłownie;
  2. `/user`, `/user ssh-keys`, `/certificate`, `/file` (api-ssl, zwykły print — kolekcja modeluje
     te menu dopiero od RouterOS 7.15) z `routers/<id>/gate-objects.yml`
     — tylko pola stabilne, wzorzec generowany `python -m harness gate <router> --dump-objects`
     i wnoszony do site-lab PR-em operatora (jak export.rsc, D-C).
Kod bramki nie używa `agent.normalize` ani `tools/mikrotik_onboard.py`.
"""
from __future__ import annotations

import difflib
import json
from dataclasses import dataclass, field
from datetime import datetime

import yaml

from . import HarnessError
from .config import RouterCfg
from .timing import iso

EXPORT_FILE = "export.rsc"
OBJECTS_FILE = "gate-objects.yml"
OBJECTS_SCHEMA = "1"

# Pola stabilne per menu (bez liczników, czasów logowania, rozmiarów i treści plików).
OBJECT_FIELDS: dict[str, tuple[str, ...]] = {
    "user": ("name", "group", "address", "disabled", "comment"),
    "user ssh-keys": ("user", "key-owner", "bits", "key-type"),
    "certificate": ("name", "common-name", "fingerprint", "trusted", "private-key"),
    "file": ("name", "type"),
}


@dataclass
class GateResult:
    ok: bool
    export_diff: list[str] = field(default_factory=list)
    objects_diff: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"ok": self.ok, "export_diff": self.export_diff, "objects_diff": self.objects_diff}

    def summary(self) -> str:
        changed = sum(1 for ln in self.export_diff if ln.startswith(("+", "-")))   # bez nagłówków @@
        return (f"bramka niezgodna: eksport {changed} linii różnic, "
                f"obiekty {len(self.objects_diff)} różnic")


# ---------------------------------------------------------------- eksport
def export_body(text: str) -> list[str]:
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    start = next((i for i, ln in enumerate(lines) if ln.startswith("/")), len(lines))
    head = lines[:start]
    if any(ln and not ln.startswith("#") for ln in head):
        raise HarnessError("eksport: przed pierwszą linią '/' są linie spoza nagłówka '#'")
    body = lines[start:]
    while body and body[-1] == "":
        body.pop()
    return body


def diff_export(actual: str, pattern: str) -> list[str]:
    a, p = export_body(actual), export_body(pattern)
    return [ln for ln in difflib.unified_diff(p, a, "wzorzec", "router", n=0, lineterm="")
            if not ln.startswith(("---", "+++"))]


# ---------------------------------------------------------------- obiekty
def _canon(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, str) and v.lower() in ("yes", "no", "true", "false"):
        return "true" if v.lower() in ("yes", "true") else "false"
    return str(v)


def project(reads: dict[str, list[dict]]) -> dict[str, list[dict]]:
    """Tylko pola stabilne, wartości jako tekst, wiersze posortowane — postać wzorca."""
    out = {}
    for path, fields in OBJECT_FIELDS.items():
        rows = [{k: _canon(r[k]) for k in fields if r.get(k) is not None} for r in reads[path]]
        out[path] = sorted(rows, key=lambda r: json.dumps(r, sort_keys=True))
    return out


def diff_objects(actual: dict[str, list[dict]], ref: dict[str, list[dict]]) -> list[str]:
    out = []
    for path in OBJECT_FIELDS:
        a = {json.dumps(r, sort_keys=True, ensure_ascii=False) for r in actual.get(path, [])}
        r = {json.dumps(x, sort_keys=True, ensure_ascii=False) for x in ref.get(path, [])}
        out += [f"- {path}: {x}" for x in sorted(r - a)]
        out += [f"+ {path}: {x}" for x in sorted(a - r)]
    return out


def dump_objects(router_id: str, projected: dict, now: datetime) -> str:
    doc = {"schema_version": OBJECTS_SCHEMA, "router_id": router_id, "generated_at": iso(now),
           "objects": projected}
    head = (f"# Wzorzec bramki H5 (obiekty spoza /export) dla {router_id}.\n"
            f"# Wygenerowany: python -m harness gate {router_id} --dump-objects (router w baseline).\n"
            "# Tylko pola stabilne, bez wartości tajnych. Odświeżany PR-em operatora razem z export.rsc.\n")
    return head + yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)


def load_objects_ref(text: str, router_id: str) -> dict[str, list[dict]]:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise HarnessError(f"{OBJECTS_FILE}: błędny YAML ({e})") from None
    if not isinstance(doc, dict) or doc.get("schema_version") != OBJECTS_SCHEMA \
            or doc.get("router_id") != router_id or not isinstance(doc.get("objects"), dict):
        raise HarnessError(f"{OBJECTS_FILE}: oczekiwano schema_version '{OBJECTS_SCHEMA}', "
                           f"router_id '{router_id}' i mapy objects")
    missing = [p for p in OBJECT_FIELDS if p not in doc["objects"]]
    if missing:
        raise HarnessError(f"{OBJECTS_FILE}: brak menu {missing}")
    return {p: [{k: str(v) for k, v in r.items()} for r in doc["objects"][p]]
            for p in OBJECT_FIELDS}


# ---------------------------------------------------------------- bramka
def read_objects(ansible, router: RouterCfg) -> dict[str, list[dict]]:
    return project(ansible.read_many(router, list(OBJECT_FIELDS), raw=True))


def check(ssh, ansible, site, sha: str, site_doc: dict, router: RouterCfg) -> GateResult:
    try:
        pattern = site.router_file(sha, site_doc, router.router_id, EXPORT_FILE)
        ref_text = site.router_file(sha, site_doc, router.router_id, OBJECTS_FILE)
    except HarnessError as e:
        raise HarnessError(f"bramka: brak wzorca w site-lab ({e}); wzorzec obiektów: "
                           f"python -m harness gate {router.router_id} --dump-objects") from None
    ref = load_objects_ref(ref_text, router.router_id)
    exp_diff = diff_export(ssh.export(router), pattern)
    obj_diff = diff_objects(read_objects(ansible, router), ref)
    return GateResult(ok=not exp_diff and not obj_diff, export_diff=exp_diff,
                      objects_diff=obj_diff)

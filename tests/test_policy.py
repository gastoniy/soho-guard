import copy, sys
from pathlib import Path
import yaml, pytest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import policy_lint as pl

POLDIR = ROOT / "policy"

def test_shipped_policy_valid():
    assert pl.lint([str(POLDIR)]) == []

def test_dynamic_refs_are_logical_not_paths():
    # polityka uniwersalna odwołuje się do dynamic-baseline logicznie (plik z inventory.yml)
    for f in (POLDIR / "dynamic").glob("*.yml"):
        for rule in yaml.safe_load(f.read_text(encoding="utf-8"))["rules"]:
            ref = rule.get("assert", {}).get("allowed_from")
            if ref is not None:
                assert ref.startswith("dynamic-baseline#") and "/" not in ref, (rule["id"], ref)

def _local(tmp_path, doc):
    p = tmp_path / "local-policy.yml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return pl.lint_local([str(p)])

LOCAL_RULE = {
    "id": "local.mgmt.winbox", "title": "regula testowa", "severity": "high", "reason": "powod",
    "check": {"path": "/ip/service", "where": {"name": "winbox"}, "assert": {"address": "10.0.0.0/24"}},
}

def test_local_example_valid():
    assert pl.lint_local([str(ROOT / "examples" / "local-policy.yml")]) == []

def test_local_minimal_file_valid(tmp_path):
    assert _local(tmp_path, {"schema_version": "1.0"}) == []

def test_local_empty_file_rejected(tmp_path):
    p = tmp_path / "local-policy.yml"
    p.write_text("", encoding="utf-8")
    assert pl.lint_local([str(p)])

@pytest.mark.parametrize("field,value", [
    ("ioc", True), ("ioc", False), ("phase", "dynamic"),
    ("remediate", {"set": {"enabled": "no"}}),
])
def test_local_rule_forbidden_fields(tmp_path, field, value):
    r = copy.deepcopy(LOCAL_RULE); r[field] = value
    assert _local(tmp_path, {"schema_version": "1.0", "rules": [r]})

@pytest.mark.parametrize("rid", ["policy.services.x", "integrity.x"])
def test_local_rule_needs_local_prefix(tmp_path, rid):
    r = copy.deepcopy(LOCAL_RULE); r["id"] = rid
    assert _local(tmp_path, {"schema_version": "1.0", "rules": [r]})

def test_local_rule_needs_reason(tmp_path):
    r = copy.deepcopy(LOCAL_RULE); del r["reason"]
    assert _local(tmp_path, {"schema_version": "1.0", "rules": [r]})

def test_local_rule_path_must_be_collected(tmp_path):
    r = copy.deepcopy(LOCAL_RULE); r["check"] = {"path": "/ip/x", "assert": {"enabled": "no"}}
    assert any("nie jest zbierana" in e for e in _local(tmp_path, {"schema_version": "1.0", "rules": [r]}))

def test_local_unquoted_no_rejected(tmp_path):
    # YAML czyta niecytowane no jako false; wymagany zapis "no"
    r = copy.deepcopy(LOCAL_RULE); r["check"] = {"path": "/ip/socks", "assert": {"enabled": False}}
    assert _local(tmp_path, {"schema_version": "1.0", "rules": [r]})

def test_local_rule_drift_prefix_reserved(tmp_path):
    r = copy.deepcopy(LOCAL_RULE); r["id"] = "local.drift.users"
    assert any("zarezerwowany" in e for e in _local(tmp_path, {"schema_version": "1.0", "rules": [r]}))

def test_local_duplicate_ids(tmp_path):
    doc = {"schema_version": "1.0", "rules": [LOCAL_RULE],
           "drift": {"overrides": [{"resource": "scheduler", "id": LOCAL_RULE["id"], "severity": "high"}]}}
    assert any("zduplikowane" in e for e in _local(tmp_path, doc))

def test_local_second_override_of_resource(tmp_path):
    over = [{"resource": "scheduler", "id": "local.a", "severity": "high"},
            {"resource": "scheduler", "id": "local.b", "severity": "low"}]
    assert any("drugi override" in e for e in _local(tmp_path, {"schema_version": "1.0", "drift": {"overrides": over}}))

def test_local_override_keeps_default_drift_id(tmp_path):
    over = [{"resource": "ppp_secrets", "id": "local.drift.ppp-secrets", "severity": "high"}]
    assert _local(tmp_path, {"schema_version": "1.0", "drift": {"overrides": over}}) == []
    over[0]["id"] = "local.drift.users"
    assert _local(tmp_path, {"schema_version": "1.0", "drift": {"overrides": over}})

@pytest.mark.parametrize("resource,fragment", [("nie_ma", "nieznany"), ("system_resource", "poza driftem")])
def test_local_drift_resource_checked(tmp_path, resource, fragment):
    doc = {"schema_version": "1.0", "drift": {"ignore": [{"resource": resource, "attrs": ["comment"], "reason": "powod"}]}}
    assert any(fragment in e for e in _local(tmp_path, doc))

def test_local_ignore_needs_reason_and_attrs(tmp_path):
    assert _local(tmp_path, {"schema_version": "1.0", "drift": {"ignore": [{"resource": "users", "attrs": ["comment"]}]}})
    assert _local(tmp_path, {"schema_version": "1.0", "drift": {"ignore": [{"resource": "users", "attrs": [], "reason": "powod"}]}})

def test_local_cli(tmp_path):
    good = str(ROOT / "examples" / "local-policy.yml")
    assert pl.main(["--local", good]) == 0
    bad = tmp_path / "x.yml"
    bad.write_text("schema_version: '9'\n", encoding="utf-8")
    assert pl.main(["--local", str(bad)]) == 1
    assert pl.main(["--local"]) == 2

def _one(tmp_path, rule, layer="static"):
    p = tmp_path / "r.yml"
    p.write_text(yaml.safe_dump({"layer": layer, "rules": [rule]}), encoding="utf-8")
    return str(p)

BASE_STATIC = {
    "id": "policy.services.x.disabled", "title": "regula testowa", "severity": "high",
    "ioc": False, "phase": "static", "trace": {"timeline": "test"},
    "check": {"path": "/ip/x", "assert": {"enabled": "no"}},
}

def test_local_prefix_rejected(tmp_path):
    r = copy.deepcopy(BASE_STATIC); r["id"] = "local.services.x"
    assert any("prefiks lokalny" in e or "pattern" in e for e in pl.lint([_one(tmp_path, r)]))

def test_phase_layer_mismatch(tmp_path):
    r = copy.deepcopy(BASE_STATIC); r["phase"] = "dynamic"
    # dynamic rule bez detector -> schema zareaguje, ale też phase!=layer
    assert pl.lint([_one(tmp_path, r, layer="static")])

def test_missing_timeline_rejected(tmp_path):
    r = copy.deepcopy(BASE_STATIC); r["trace"] = {}
    assert pl.lint([_one(tmp_path, r)])

def test_ioc_rule_cannot_remediate(tmp_path):
    r = copy.deepcopy(BASE_STATIC); r["ioc"] = True
    r["remediate"] = {"set": {"enabled": "no"}}
    assert pl.lint([_one(tmp_path, r)])

def test_static_needs_check(tmp_path):
    r = copy.deepcopy(BASE_STATIC); del r["check"]
    assert pl.lint([_one(tmp_path, r)])

def test_dynamic_needs_detector(tmp_path):
    r = {"id": "policy.dynamic.x", "title": "regula testowa", "severity": "high", "ioc": True,
         "phase": "dynamic", "trace": {"timeline": "t"}, "assert": {"score_max": 0.5}}
    # brak detector
    assert pl.lint([_one(tmp_path, r, layer="dynamic")])

def test_duplicate_id_across_files(tmp_path):
    (tmp_path / "a.yml").write_text(yaml.safe_dump({"layer": "static", "rules": [BASE_STATIC]}))
    (tmp_path / "b.yml").write_text(yaml.safe_dump({"layer": "static", "rules": [BASE_STATIC]}))
    assert any("zduplikowane" in e for e in pl.lint([str(tmp_path)]))

def test_every_shipped_rule_has_timeline():
    import glob
    for f in glob.glob(str(POLDIR / "**/*.yml"), recursive=True):
        for r in yaml.safe_load(open(f))["rules"]:
            assert r["trace"].get("timeline"), r["id"]


# --- baseline dynamiczny (--dynamic) ---
def _dynamic(tmp_path, change=None):
    doc = yaml.safe_load((ROOT / "examples" / "dynamic-baseline.yml").read_text(encoding="utf-8"))
    if change:
        change(doc)
    p = tmp_path / "dynamic-baseline.yml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return pl.lint_dynamic([str(p)])


def test_dynamic_example_valid():
    assert pl.lint_dynamic([str(ROOT / "examples" / "dynamic-baseline.yml")]) == []


def test_dynamic_minimal_file_valid(tmp_path):
    p = tmp_path / "d.yml"
    p.write_text('schema_version: "1.0"\nrouter_id: r1\n', encoding="utf-8")
    assert pl.lint_dynamic([str(p)]) == []


@pytest.mark.parametrize("change", [
    lambda d: d["dns"].update(allowed_resolver=d["dns"].pop("allowed_resolvers")),   # literówka
    lambda d: d.update(dsn={}),                                                       # nieznana sekcja
    lambda d: d["dns"].update(allowed_resolvers=["1.1.1"]),                           # zły adres
    lambda d: d["dns"].update(alert_on_other_resolver="tak"),
    lambda d: d["dns"].update(allowed_suffixes=["CDN.Example"]),
    lambda d: d["beaconing"]["allowed_periodic"][0].update(port=70000),
    lambda d: d.pop("router_id"),
])
def test_dynamic_errors_rejected(tmp_path, change):
    assert _dynamic(tmp_path, change)


def test_dynamic_cli_mode(tmp_path, capsys):
    assert pl.main(["--dynamic", str(ROOT / "examples" / "dynamic-baseline.yml")]) == 0
    p = tmp_path / "d.yml"
    p.write_text('schema_version: "1.0"\nrouter_id: r1\ndns: {allowed_resolver: []}\n', encoding="utf-8")
    assert pl.main(["--dynamic", str(p)]) == 1
    assert "allowed_resolver" in capsys.readouterr().out

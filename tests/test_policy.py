import copy, sys
from pathlib import Path
import yaml, pytest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import policy_lint as pl

POLDIR = ROOT / "policy"

def test_shipped_policy_valid():
    assert pl.lint([str(POLDIR)]) == []

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

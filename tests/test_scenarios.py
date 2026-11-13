"""Testy manifestu scenariusza i kontraktu oracle'a (B1).

Kontrakt domyka się na PRAWDZIWYCH przykładach raportów z ADR-005:
  POL-003 <-> report-policy-violation.json
  DYN-011a <-> report-compromise-suspected.json (rozbieżność, zeek.conn)
  DYN-011b <-> report-beacon-suspected.json (beacon, rita.beacon)
Dla klas site/benign/control brak gotowych przykładów raportu, więc oracle
testowany jest na minimalnych, jawnie zbudowanych raportach/stanach.
"""
import copy, json, sys
from pathlib import Path
import yaml
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import manifest_lint as ml
import oracle_eval as oe

EX = ROOT / "examples"          # fixtures raportów
SCN = ROOT / "scenarios"        # manifesty, w podkatalogach wg klasy


def find_scn(name):
    hits = list(SCN.rglob(name))
    assert len(hits) == 1, f"manifest {name}: {hits}"
    return hits[0]


def load_yaml(name): return yaml.safe_load(find_scn(name).read_text(encoding="utf-8"))
def load_json(name): return json.loads((EX / name).read_text(encoding="utf-8"))


# ---------------- manifest_lint: pozytywne ----------------
@pytest.mark.parametrize("name", [
    "policy-socks-enabled.yml", "policy-winbox-public.yml",
    "site-ppp-secret.yml", "benign-firewall-comment.yml",
    "dynamic-c2-beacon.yml", "dynamic-c2-divergence.yml", "control-l2-attribution.yml",
])
def test_examples_valid(name):
    assert ml.validate(find_scn(name)) == []


# ---------------- manifest_lint: negatywne (po jednym na regułę) ----------------
def _write(tmp_path, doc):
    p = tmp_path / "s.yml"; p.write_text(yaml.safe_dump(doc), encoding="utf-8"); return p

def test_policy_cannot_be_local(tmp_path):
    d = load_yaml("policy-socks-enabled.yml"); d["expect"]["rule_source"] = "local"
    errs = ml.validate(_write(tmp_path, d))
    assert any("rule_source" in e for e in errs)

def test_policy_cannot_pr_alert(tmp_path):
    d = load_yaml("policy-socks-enabled.yml"); d["expect"]["action"] = "pr-alert"
    assert any("action" in e for e in ml.validate(_write(tmp_path, d)))

@pytest.mark.parametrize("name,action,end_state", [
    ("policy-socks-enabled.yml", "auto-remediate", "unchanged"),
    ("policy-winbox-public.yml", "none", "baseline"),
])
def test_policy_action_end_state_pair(tmp_path, name, action, end_state):
    # D-A: auto-remediate <-> baseline, none <-> unchanged; krzyżowe pary odrzucone
    d = load_yaml(name); d["expect"]["action"] = action; d["expect"]["end_state"] = end_state
    assert any("wymaga end_state" in e for e in ml.validate(_write(tmp_path, d)))

def test_policy_action_none_requires_end_state(tmp_path):
    d = load_yaml("policy-winbox-public.yml"); del d["expect"]["end_state"]
    assert any("end_state" in e for e in ml.validate(_write(tmp_path, d)))

def test_policy_cannot_alert(tmp_path):
    d = load_yaml("policy-winbox-public.yml"); d["expect"]["action"] = "alert"
    assert any("action" in e for e in ml.validate(_write(tmp_path, d)))

def test_site_must_be_unchanged(tmp_path):
    d = load_yaml("site-ppp-secret.yml"); d["expect"]["end_state"] = "baseline"
    assert any("end_state" in e for e in ml.validate(_write(tmp_path, d)))

def test_benign_cannot_have_action(tmp_path):
    d = load_yaml("benign-firewall-comment.yml"); d["expect"]["action"] = "alert"
    assert ml.validate(_write(tmp_path, d))

def test_dynamic_requires_generate(tmp_path):
    d = load_yaml("dynamic-c2-beacon.yml"); del d["generate"]
    assert ml.validate(_write(tmp_path, d))

def test_dynamic_requires_coverage_full_via_posture(tmp_path):
    d = load_yaml("dynamic-c2-beacon.yml"); d["expect"]["posture"] = "site-drift"
    assert any("posture" in e for e in ml.validate(_write(tmp_path, d)))

def test_control_must_be_other_router(tmp_path):
    d = load_yaml("control-l2-attribution.yml"); d["generate"]["from"] = "kali"
    assert any("other-router" in e for e in ml.validate(_write(tmp_path, d)))

def test_rule_prefix_must_match_source(tmp_path):
    d = load_yaml("policy-socks-enabled.yml"); d["expect"]["rule"] = "local.foo.bar"
    # rule_source wciąż universal -> niespójność prefiksu
    assert any("lokalna" in e for e in ml.validate(_write(tmp_path, d)))

def test_detected_requires_mttd_budget(tmp_path):
    d = load_yaml("policy-socks-enabled.yml"); del d["expect"]["max_detection_time_s"]
    assert any("max_detection_time_s" in e for e in ml.validate(_write(tmp_path, d)))


# ---------------- oracle: kontrakt domyka się na realnych raportach ----------------
def test_oracle_policy_matches_adr005_report():
    m = load_yaml("policy-socks-enabled.yml")
    rep = load_json("report-policy-violation.json")
    assert oe.oracle_eval(m, rep, load_json("state-r2.json")) == []

def test_oracle_dynamic_matches_adr005_report():
    m = load_yaml("dynamic-c2-divergence.yml")
    rep = load_json("report-compromise-suspected.json")
    # stan nieistotny dla detected=True; podajemy dowolny poprawny
    st = load_json("state-r2.json")
    assert oe.oracle_eval(m, rep, st) == []


def _winbox_report(action_type="none", status="skipped"):
    """Minimalny raport POL-006: finding winbox new, akcja none/skipped (mitigate._plan)."""
    rep = copy.deepcopy(load_json("report-policy-violation.json"))
    f = rep["findings"][0]
    f["rule"] = "policy.mgmt.winbox.not-public"
    f["evidence"] = {"type": "state", "path": "/ip/service",
                     "expected": {"address": {"private": True}}, "observed": {"address": ""}}
    a = rep["actions"][0]
    a.update(type=action_type, status=status, verification=None,
             reason="reguła uniwersalna bez remediate, naruszenie widoczne w raporcie")
    return rep

def test_oracle_policy_action_none_passes():
    m = load_yaml("policy-winbox-public.yml")
    assert oe.oracle_eval(m, _winbox_report(), load_json("state-r2.json")) == []

def test_oracle_policy_action_none_rejects_remediation():
    m = load_yaml("policy-winbox-public.yml")
    errs = oe.oracle_eval(m, _winbox_report("auto-remediate", "succeeded"), load_json("state-r2.json"))
    assert any("action.type" in e for e in errs)


# ---------------- oracle: wykrywa niezgodności ----------------
def test_oracle_wrong_posture_fails():
    m = load_yaml("policy-socks-enabled.yml")
    rep = copy.deepcopy(load_json("report-policy-violation.json"))
    rep["verdict"]["posture"] = "site-drift"
    assert any("posture" in e for e in oe.oracle_eval(m, rep, load_json("state-r2.json")))

def test_oracle_missing_rule_fails():
    m = copy.deepcopy(load_yaml("policy-socks-enabled.yml"))
    m["expect"]["rule"] = "policy.services.telnet.disabled"
    rep = load_json("report-policy-violation.json")
    assert any("brak findingu" in e for e in oe.oracle_eval(m, rep, load_json("state-r2.json")))

def test_oracle_remediation_not_resolved_fails():
    m = load_yaml("policy-socks-enabled.yml")
    rep = copy.deepcopy(load_json("report-policy-violation.json"))
    rep["actions"][0]["verification"]["result"] = "still-present"
    assert any("baseline" in e for e in oe.oracle_eval(m, rep, load_json("state-r2.json")))

def test_oracle_dynamic_partial_coverage_fails():
    m = load_yaml("dynamic-c2-divergence.yml")
    rep = copy.deepcopy(load_json("report-compromise-suspected.json"))
    rep["verdict"]["coverage"] = "partial"
    assert any("coverage" in e for e in oe.oracle_eval(m, rep, load_json("state-r2.json")))

def test_oracle_benign_with_finding_fails():
    m = load_yaml("benign-firewall-comment.yml")
    rep = load_json("report-policy-violation.json")   # raport z findingiem new
    st = copy.deepcopy(load_json("state-r2.json")); st["posture"] = "no-violations"
    assert any("nowego findingu" in e for e in oe.oracle_eval(m, rep, st))

def test_oracle_benign_clean_passes():
    m = load_yaml("benign-firewall-comment.yml")
    st = copy.deepcopy(load_json("state-r2.json")); st["posture"] = "no-violations"
    assert oe.oracle_eval(m, None, st) == []

def test_oracle_control_clean_passes():
    m = load_yaml("control-l2-attribution.yml")
    st = copy.deepcopy(load_json("state-r2.json")); st["posture"] = "no-violations"
    assert oe.oracle_eval(m, None, st) == []

def test_oracle_control_detects_false_attribution():
    # gdyby filtr L2 zawiódł: pojawia się finding rozbieżności na bezczynnym R2
    m = load_yaml("control-l2-attribution.yml")
    rep = load_json("report-compromise-suspected.json")
    st = copy.deepcopy(load_json("state-r2.json")); st["posture"] = "compromise-suspected"
    assert oe.oracle_eval(m, rep, st)


# ---------------- DYN-011a/b: podział ścieżek detekcji (2026-10-28) ----------------
def test_oracle_beacon_matches_report():
    m = load_yaml("dynamic-c2-beacon.yml")
    assert m["id"] == "DYN-011b" and m["expect"]["rule"] == "policy.dynamic.beacon"
    assert oe.oracle_eval(m, load_json("report-beacon-suspected.json"), load_json("state-r2.json")) == []

def test_divergence_report_does_not_satisfy_beacon_scenario():
    m = load_yaml("dynamic-c2-beacon.yml")
    errs = oe.oracle_eval(m, load_json("report-compromise-suspected.json"), load_json("state-r2.json"))
    assert any("brak findingu" in e for e in errs)

def test_mttd_budget_upper_bound_24h(tmp_path):
    d = load_yaml("dynamic-c2-beacon.yml"); d["expect"]["max_detection_time_s"] = 86400
    assert ml.validate(_write(tmp_path, d)) == []
    d["expect"]["max_detection_time_s"] = 86401
    assert ml.validate(_write(tmp_path, d))

def test_scenario_id_allows_variant_suffix(tmp_path):
    d = load_yaml("dynamic-c2-beacon.yml"); d["id"] = "DYN-011B"
    assert ml.validate(_write(tmp_path, d))          # tylko mała litera jako wariant

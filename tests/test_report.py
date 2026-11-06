"""Testy kontraktu raportu (ADR-005).

Każda reguła ma przypadek pozytywny i co najmniej jeden negatywny. Przypadki
negatywne są budowane przez mutację poprawnych przykładów, więc każdy test
sprawdza dokładnie jedno naruszenie.
"""
import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import validate_report as validate  # noqa: E402

LAN = ["10.20.0.0/24", "192.168.10.0/24"]


def load(name):
    return json.loads((ROOT / "examples" / name).read_text(encoding="utf-8"))


@pytest.fixture
def pv():
    return load("report-policy-violation.json")


@pytest.fixture
def cs():
    return load("report-compromise-suspected.json")


@pytest.fixture
def state():
    return load("state-r2.json")


def errs(doc):
    return validate.validate_report(doc, LAN)


def assert_fails(errors, fragment):
    assert errors, "oczekiwano naruszenia, walidacja przeszła"
    assert any(fragment in e for e in errors), f"brak '{fragment}' w: {errors}"


# ------------------------------------------------------------------ pozytywne
def test_examples_valid(pv, cs, state):
    assert errs(pv) == []
    assert errs(cs) == []
    assert validate.validate_state(state) == []


# ------------------------------------------------- prywatność (R6, ADR-001)
def test_lan_host_field_rejected_by_structure(cs):
    cs["findings"][0]["evidence"]["l2_observation"]["lan_source"] = "10.20.0.57"
    assert_fails(errs(cs), "lan_source")


def test_lan_destination_rejected(cs):
    cs["findings"][0]["evidence"]["l2_observation"]["destination"] = "10.20.0.57"
    assert_fails(errs(cs), "prefiksu LAN")


def test_lan_check_is_per_installation_not_rfc1918(cs):
    # C2 w labie stoi w VLAN30 realnego routera, czyli w RFC1918. Nie może to
    # być odrzucane, o ile adres nie należy do LAN instalacji.
    cs["findings"][0]["evidence"]["l2_observation"]["destination"] = "192.168.30.10"
    assert errs(cs) == []


@pytest.mark.parametrize("version", ["v1.4.0", "v0.1.2-lab", "v0.2.0-lab.rc1", "v0.2.0-lab.rc12"])
def test_policy_version_accepted(pv, state, version):
    pv["policy"]["universal_version"] = version
    state["policy"]["universal_version"] = version
    assert errs(pv) == []
    assert validate.validate_state(state) == []


@pytest.mark.parametrize("version", ["0.1.2-lab", "v0.1.2-test", "v0.1.2-lab.rc", "v0.1.2-lab.rc1x", "v0.1-lab"])
def test_policy_version_rejected(pv, version):
    pv["policy"]["universal_version"] = version
    assert errs(pv)


def test_unredacted_preshared_key_rejected(pv):
    pv["findings"][1]["evidence"]["observed"]["preshared-key"] = "tajne"
    assert_fails(errs(pv), "preshared-key")


def test_unredacted_secret_rejected(pv):
    pv["findings"][1]["evidence"]["observed"]["password"] = "hunter2"
    assert_fails(errs(pv), "niezredagowana")


def test_unknown_top_level_field_rejected(pv):
    pv["raw_export"] = "/export verbose ..."
    assert_fails(errs(pv), "raw_export")


# ----------------------------------------------------------------- R1 i R2
def test_posture_mismatch(pv):
    pv["verdict"]["posture"] = "no-violations"
    assert_fails(errs(pv), "wg R1")


def test_divergence_forces_compromise_suspected(cs):
    cs["verdict"]["posture"] = "policy-violation"
    assert_fails(errs(cs), "compromise-suspected")


def test_coverage_must_be_partial_when_required_l2_missing(pv):
    pv["collection"]["l2"]["status"] = "unavailable"
    assert_fails(errs(pv), "wg R2")


def test_no_findings_and_partial_is_inconclusive(pv):
    pv["findings"], pv["actions"] = [], []
    pv["verdict"].update(findings_total=0, findings_new=0)
    pv["collection"]["l2"]["status"] = "unavailable"
    pv["verdict"]["coverage"] = "partial"
    pv["verdict"]["posture"] = "no-violations"
    assert_fails(errs(pv), "'inconclusive'")
    pv["verdict"]["posture"] = "inconclusive"
    assert errs(pv) == []


def test_degraded_optional_l3_keeps_full_coverage(pv):
    assert pv["collection"]["l3"]["status"] == "degraded"
    assert pv["verdict"]["coverage"] == "full"
    assert errs(pv) == []


def test_l3_can_never_be_required(pv):
    pv["collection"]["l3"]["required"] = True
    assert_fails(errs(pv), "collection/l3")


# ------------------------------------------------------- rozbieżność, R4
def test_divergence_requires_l1_contradiction(cs):
    cs["findings"][0]["trust"]["contradicted_by"] = []
    assert errs(cs)


def test_divergence_requires_l1_claim(cs):
    del cs["findings"][0]["evidence"]["l1_claim"]
    assert errs(cs)


def test_access_lost_must_be_ioc(pv):
    f = pv["findings"][0]
    f.update(rule="integrity.management-access-lost", ioc=False, also_matched=[])
    f["evidence"] = {"type": "access", "stage": "l1-auth", "result": "rejected",
                     "local_ref": f["evidence"]["local_ref"]}
    assert errs(pv)


# ------------------------------------------------------- R8, dwa tory
def test_local_finding_cannot_be_auto_remediated(pv):
    pv["actions"].append({
        "action_id": "A-02", "fingerprint": pv["findings"][1]["fingerprint"],
        "type": "auto-remediate", "status": "succeeded", "reason": "x",
        "started_at": "2026-10-21T15:14:05.800Z", "finished_at": "2026-10-21T15:14:06.100Z",
        "external_ref": None,
        "verification": {"performed": True, "layers": ["L1"], "result": "resolved"},
        "local_ref": None,
    })
    assert_fails(errs(pv), "R8")


def test_compromise_indicator_cannot_be_auto_remediated(cs):
    a = cs["actions"][0]
    a.update(type="auto-remediate",
             verification={"performed": True, "layers": ["L1"], "result": "resolved"})
    assert_fails(errs(cs), "R8")


def test_what_if_allows_skipped_but_not_executed(pv):
    pv["policy"]["evaluation_mode"] = "what-if"
    a = pv["actions"][0]
    a.update(type="none", status="skipped", started_at=None, finished_at=None, verification=None, local_ref=None)
    assert errs(pv) == []
    a.update(type="auto-remediate", status="failed", started_at="2026-10-21T15:14:05.120Z",
             finished_at="2026-10-21T15:14:05.700Z")
    assert errs(pv)


def test_new_finding_requires_exactly_one_action(pv):
    pv["actions"] = []
    assert_fails(errs(pv), "dokładnie jednej akcji")


def test_remediation_succeeded_requires_resolved_verification(pv):
    pv["actions"][0]["verification"]["result"] = "still-present"
    assert errs(pv)


def test_none_action_must_be_skipped(pv):
    pv["actions"][0].update(type="none", verification=None)
    assert errs(pv)


def test_what_if_actions_only_proposed(pv):
    pv["policy"]["evaluation_mode"] = "what-if"
    assert errs(pv)
    a = pv["actions"][0]
    a.update(status="proposed", started_at=None, finished_at=None, verification=None, local_ref=None)
    assert errs(pv) == []


def test_action_must_reference_finding(pv):
    pv["actions"][0]["fingerprint"] = "sha256:" + "0" * 64
    assert_fails(errs(pv), "brak findingu")


# -------------------------------------------------- liczniki i odnośniki
def test_counter_mismatch(pv):
    pv["verdict"]["findings_new"] = 2
    assert_fails(errs(pv), "findings_new")


def test_local_rule_prefix_must_match_source(pv):
    pv["findings"][1]["rule_source"] = "universal"
    assert_fails(errs(pv), "rule_source")


def test_first_report_has_no_predecessor(cs):
    cs["integrity"]["previous_report_sha256"] = "a" * 64
    assert errs(cs)


# ------------------------------------------------------------------ stan
def test_state_posture_derived_from_open_findings(state):
    state["posture"] = "no-violations"
    assert_fails(validate.validate_state(state), "wg R1")


def test_state_indicator_forces_compromise(state):
    state["open_findings"][0]["compromise_indicator"] = True
    assert_fails(validate.validate_state(state), "compromise-suspected")


# ----------------------------------------------------------- łańcuch (R7)
def _write_chain(tmp_path, base, n):
    paths = []
    prev = None
    for seq in range(1, n + 1):
        doc = copy.deepcopy(base)
        doc["integrity"] = {"report_seq": seq,
                            "previous_report_sha256": hashlib.sha256(prev).hexdigest() if prev else None}
        raw = (json.dumps(doc, indent=2) + "\n").encode()
        p = tmp_path / "2026" / "10" / f"{seq:04d}.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(raw)
        paths.append(p)
        prev = raw
    return paths


def test_chain_valid(tmp_path, pv):
    _write_chain(tmp_path, pv, 3)
    assert validate.validate_chain(tmp_path) == []


def test_chain_tamper_detected(tmp_path, pv):
    paths = _write_chain(tmp_path, pv, 3)
    doc = json.loads(paths[1].read_text())
    doc["verdict"]["posture"] = "no-violations"
    paths[1].write_text(json.dumps(doc, indent=2) + "\n")
    assert_fails(validate.validate_chain(tmp_path), "zerwany łańcuch")


def test_chain_gap_detected(tmp_path, pv):
    paths = _write_chain(tmp_path, pv, 3)
    paths[1].unlink()
    assert_fails(validate.validate_chain(tmp_path), "luka")


def test_chain_ignores_what_if(tmp_path, pv):
    _write_chain(tmp_path, pv, 2)
    wi = tmp_path / "what-if" / "x.json"
    wi.parent.mkdir()
    wi.write_text(json.dumps(pv))
    assert validate.validate_chain(tmp_path) == []


# ---------------------------------------------------------------- CLI
def test_cli_exit_codes(tmp_path, pv):
    good = ROOT / "examples" / "report-policy-violation.json"
    assert validate.main(["report", str(good), "--lan-prefix", LAN[0]]) == 0
    bad = tmp_path / "bad.json"
    pv["verdict"]["posture"] = "no-violations"
    bad.write_text(json.dumps(pv))
    assert validate.main(["report", str(bad)]) == 1
    broken = tmp_path / "broken.json"
    broken.write_text("{")
    assert validate.main(["report", str(broken)]) == 2

"""Wykonanie akcji: symulator zapisu RouterOS zamiast routera, prawdziwy git na repo bare."""
import copy
import json
import subprocess

import pytest
import yaml
from librouteros.exceptions import TrapError

import test_agent as base
import oracle_eval as oe
import validate_report as validate
from test_agent import MockApi, ROOT, SECRET, SOCKS_ON, SOCKS_RULE, git, lab, router  # noqa: F401
from test_publish import remote  # noqa: F401
from agent import __main__ as cli
from agent import proposal
from agent.static_eval import evaluate, ignored_attrs

DRIFT_RULE = "local.drift.scheduler"
TASK = [{".id": "*7", "name": "zadanie", "interval": "1h"}]


class SimMenu:
    def __init__(self, sim, parts):
        self.sim = sim
        self.parts = parts

    def __iter__(self):
        return iter(copy.deepcopy(self.sim.data[self.parts]))

    def __call__(self, cmd, **kwargs):
        assert cmd == "set"
        self.sim.writes.append((self.parts, dict(kwargs)))
        if self.sim.write_error:
            raise self.sim.write_error
        if self.sim.ignore_writes:
            return iter(())
        rows = self.sim.data[self.parts]
        row_id = kwargs.pop(".id", None)
        target = next(r for r in rows if r.get(".id") == row_id) if row_id else rows[0]
        target.update(kwargs)
        return iter(())


class Sim:
    """Wspólne dane routera: monitor czyta, remediate zapisuje."""

    def __init__(self, data):
        self.data = copy.deepcopy(data)
        self.writes = []
        self.write_error = None
        self.ignore_writes = False
        self.connect_error = None
        self.monitor_error = None
        self.monitor_calls = 0
        self.closed = 0

    def path(self, *parts):
        return SimMenu(self, parts)

    def close(self):
        self.closed += 1

    def remediate(self, ctx, password):
        assert password == "HASLO-REMEDIATE"
        if self.connect_error:
            raise self.connect_error
        return self

    def monitor(self, ctx, password):
        self.monitor_calls += 1
        if self.monitor_error and self.monitor_calls > 1:
            raise self.monitor_error
        return MockApi(self.data)


@pytest.fixture
def full(remote):  # noqa: F811
    (remote.lab.paths.etc_dir / "r2" / "remediate.pass").write_text("HASLO-REMEDIATE\n", encoding="utf-8")

    def run(sim, *extra):
        return cli.main(["--router", "r2", "--once", *extra], paths=remote.lab.paths, clock=remote.clock,
                        connector=sim.monitor, remediate_connector=sim.remediate)

    remote.full = run
    return remote


def github_origin(remote):
    """Adres jak na węźle, a transport na lokalne repo bare."""
    url = "git@github.com:lab/site-lab.git"
    git(remote.lab.site, "config", f"url.{remote.bare}.insteadOf", url)
    git(remote.lab.site, "remote", "set-url", "origin", url)


def only_action(rep, rule):
    finding = next(f for f in rep["findings"] if f["rule"] == rule)
    return next(a for a in rep["actions"] if a["fingerprint"] == finding["fingerprint"])


def state_of(remote, branch="main"):
    return json.loads((remote.checkout(branch) / "state" / "r2.json").read_text(encoding="utf-8"))


# --- naprawa ---
def test_socks_is_repaired_and_verified(full):
    sim = Sim(router(**SOCKS_ON))
    assert full.full(sim) == 0
    assert sim.writes == [(("ip", "socks"), {"enabled": "no"})]
    assert sim.closed == 1
    rep = full.reports()[-1]
    assert validate.validate_report(rep) == []
    action = only_action(rep, SOCKS_RULE)
    assert (action["type"], action["status"]) == ("auto-remediate", "succeeded")
    assert action["verification"] == {"performed": True, "layers": ["L1"], "result": "resolved"}
    assert action["started_at"] and action["finished_at"]
    assert rep["policy"]["evaluation_mode"] == "enforce"
    assert rep["verdict"]["posture"] == "policy-violation"
    state = state_of(full)
    assert state["open_findings"] == [] and state["posture"] == "inconclusive"
    manifest = yaml.safe_load((ROOT / "scenarios/policy/policy-socks-enabled.yml").read_text(encoding="utf-8"))
    assert oe.oracle_eval(manifest, rep, state) == []


def test_repaired_finding_gives_no_further_report(full):
    sim = Sim(router(**SOCKS_ON))
    assert full.full(sim) == 0
    full.later()
    assert full.full(sim) == 0
    full.assert_chain(1)
    assert len(sim.writes) == 1


def test_reappearing_violation_is_new_again(full):
    sim = Sim(router(**SOCKS_ON))
    assert full.full(sim) == 0
    sim.data[("ip", "socks")][0]["enabled"] = True
    full.later()
    assert full.full(sim) == 0
    assert len(sim.writes) == 2
    assert only_action(full.reports()[-1], SOCKS_RULE)["status"] == "succeeded"


def test_service_row_selected_by_rule_not_session(full):
    services = copy.deepcopy(base.CLEAN[("ip", "service")])
    next(s for s in services if s["name"] == "telnet")["disabled"] = False
    services.insert(0, {".id": "*F", "name": "telnet", "connection": "true", "disabled": False})
    sim = Sim(router(ip__service=services))
    assert full.full(sim) == 0
    assert sim.writes == [(("ip", "service"), {"disabled": "yes", ".id": "*3"})]
    assert only_action(full.reports()[-1], "policy.services.telnet.disabled")["status"] == "succeeded"


def test_several_repairs_share_one_session(full):
    sim = Sim(router(ip__socks=[{"enabled": True, "port": 1080}], ip__upnp=[{"enabled": True}]))
    assert full.full(sim) == 0
    assert len(sim.writes) == 2 and sim.closed == 1
    assert {a["status"] for a in full.reports()[-1]["actions"]} == {"succeeded"}


def test_v7_socks_listener_is_not_drift(full, capsys):
    """RC na r1: włączony SOCKS dodaje gniazdo w /ip/service. Jedna zmiana, jeden finding."""
    sim = Sim(router())
    assert full.full(sim) == 0
    sim.data[("ip", "socks")][0]["enabled"] = True
    listener = {".id": "*A", "name": "socks", "port": 1080, "proto": "tcp", "disabled": False}
    sim.data[("ip", "service")].append(listener)
    capsys.readouterr()
    full.later()
    assert full.full(sim) == 0
    rep = full.reports()[-1]
    assert [f["rule"] for f in rep["findings"]] == [SOCKS_RULE]
    assert [a["type"] for a in rep["actions"]] == ["auto-remediate"]
    assert "otwarte=0 nowe=1 naprawione=1 rozwiązane=0" in capsys.readouterr().out
    sim.data[("ip", "service")].remove(listener)
    full.later()
    assert full.full(sim) == 0
    full.assert_chain(2)


def test_stale_listener_rows_in_baseline_are_not_drift(full):
    """Baseline r1 ma jeszcze wiersze gniazd: wypadają przy wczytaniu, bez PR."""
    path = full.lab.site / "routers" / "r2" / "baseline-state.yml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    doc["services"].append({"name": "dhcp", "port": 67, "proto": "udp", "disabled": False})
    full.operator_commit("routers/r2/baseline-state.yml", yaml.safe_dump(doc))
    sim = Sim(router())
    assert full.full(sim) == 0
    assert full.reports()[-1]["findings"] == []


def test_listener_row_with_rule_name_is_not_selected(full):
    services = copy.deepcopy(base.CLEAN[("ip", "service")])
    next(s for s in services if s["name"] == "telnet")["disabled"] = False
    services.append({".id": "*B", "name": "telnet", "port": 23, "proto": "tcp"})
    sim = Sim(router(ip__service=services))
    assert full.full(sim) == 0
    assert sim.writes == [(("ip", "service"), {"disabled": "yes", ".id": "*3"})]


def test_counter_is_zero_outside_full_mode(full, capsys):
    sim = Sim(router(**SOCKS_ON))
    assert full.full(sim, "--no-remediate") == 0
    assert "naprawione=0" in capsys.readouterr().out


# --- niepowodzenia i brak ponawiania ---
def test_rejected_write_fails_once_without_retry(full):
    sim = Sim(router(**SOCKS_ON))
    sim.write_error = TrapError(message="not enough permissions")
    assert full.full(sim) == 0
    rep = full.reports()[-1]
    assert validate.validate_report(rep) == []
    action = only_action(rep, SOCKS_RULE)
    assert action["status"] == "failed"
    assert action["verification"] == {"performed": False, "layers": [], "result": "not-verifiable"}
    assert "act.remediate-failed" in {e["code"] for e in rep["run"]["errors"]}
    assert len(state_of(full)["open_findings"]) == 1

    full.later()
    assert full.full(sim) == 0
    assert len(sim.writes) == 1                              # D5: bez ponawiania
    assert full.reports()[-1]["actions"] == []


def test_write_without_effect_is_still_present(full):
    sim = Sim(router(**SOCKS_ON))
    sim.ignore_writes = True
    assert full.full(sim) == 0
    action = only_action(full.reports()[-1], SOCKS_RULE)
    assert action["status"] == "failed"
    assert action["verification"] == {"performed": True, "layers": ["L1"], "result": "still-present"}
    assert len(state_of(full)["open_findings"]) == 1


def test_failed_verification_read_is_not_verifiable(full):
    sim = Sim(router(**SOCKS_ON))
    sim.monitor_error = OSError("brak łączności")
    assert full.full(sim) == 0
    rep = full.reports()[-1]
    assert validate.validate_report(rep) == []
    action = only_action(rep, SOCKS_RULE)
    assert action["status"] == "failed" and action["verification"]["result"] == "not-verifiable"
    assert len(sim.writes) == 1


def test_later_clean_read_resolves_as_remediation(full):
    sim = Sim(router(**SOCKS_ON))
    sim.monitor_error = OSError("brak łączności")
    assert full.full(sim) == 0
    sim.monitor_error = None
    full.later()
    assert full.full(sim) == 0
    rep = full.reports()[-1]
    assert [r["resolved_by"] for r in rep["resolved"]] == ["remediation"]
    assert state_of(full)["open_findings"] == []


def test_rejected_remediate_login_fails_action(full):
    sim = Sim(router(**SOCKS_ON))
    sim.connect_error = TrapError(message="invalid user name or password (6)")
    assert full.full(sim) == 0
    rep = full.reports()[-1]
    assert validate.validate_report(rep) == []
    assert only_action(rep, SOCKS_RULE)["status"] == "failed"
    assert sim.writes == []
    assert not [f for f in rep["findings"] if f["rule"] == "integrity.management-access-lost"]


def test_missing_remediate_password_fails_action(full):
    (full.lab.paths.etc_dir / "r2" / "remediate.pass").unlink()
    sim = Sim(router(**SOCKS_ON))
    assert full.full(sim) == 0
    assert only_action(full.reports()[-1], SOCKS_RULE)["status"] == "failed"


def test_password_never_in_evidence_or_report(full):
    sim = Sim(router(**SOCKS_ON))
    sim.connect_error = OSError("brak trasy")
    assert full.full(sim) == 0
    for path in full.out().rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            assert "HASLO-REMEDIATE" not in text and SECRET not in text


def test_evidence_records_remediation(full):
    sim = Sim(router(**SOCKS_ON))
    assert full.full(sim) == 0
    action = only_action(full.reports()[-1], SOCKS_RULE)
    run_id, name = action["local_ref"].removeprefix("ev:").split("/")
    log = json.loads((full.out() / "evidence" / run_id / f"{name}.json").read_text(encoding="utf-8"))
    assert log["actions"][0]["result"] == "applied" and log["actions"][0]["verified"] is True


# --- akcje bez zmian na routerze ---
def test_rule_without_remediate_changes_nothing(full):
    services = copy.deepcopy(base.CLEAN[("ip", "service")])
    services[0]["address"] = ""
    sim = Sim(router(ip__service=services))
    assert full.full(sim) == 0
    assert sim.writes == []
    action = only_action(full.reports()[-1], "policy.mgmt.winbox.not-public")
    assert (action["type"], action["status"]) == ("none", "skipped")


def test_cloud_ddns_has_no_remediation(full):
    sim = Sim(router(ip__cloud=[{"ddns-enabled": True}]))
    assert full.full(sim) == 0
    assert sim.writes == []
    action = only_action(full.reports()[-1], "policy.services.cloud-ddns.disabled")
    assert (action["type"], action["status"]) == ("none", "skipped")


def test_no_remediate_writes_nothing(full):
    sim = Sim(router(**SOCKS_ON))
    assert full.full(sim, "--no-remediate") == 0
    assert sim.writes == []
    assert only_action(full.reports()[-1], SOCKS_RULE)["status"] == "skipped"


def test_dry_run_writes_nothing(full):
    sim = Sim(router(**SOCKS_ON))
    assert full.full(sim, "--dry-run") == 0
    assert sim.writes == []
    assert full.commits() == 1


def set_pin(remote, version):
    site = yaml.safe_load((remote.lab.site / "site.yml").read_text(encoding="utf-8"))
    site["policy"]["universal_version"] = version
    remote.operator_commit("site.yml", yaml.safe_dump(site))


def test_version_mismatch_holds_repair_on_main(full):
    set_pin(full, "v9.9.9-lab")
    sim = Sim(router(**SOCKS_ON))
    assert full.full(sim) == 0
    assert sim.writes == []
    rep = full.reports()[-1]
    assert validate.validate_report(rep) == []
    action = only_action(rep, SOCKS_RULE)
    assert action["status"] == "skipped" and "wstrzymane" in action["reason"]
    assert len(state_of(full)["open_findings"]) == 1


def test_version_mismatch_does_not_hold_test_branch(full):
    set_pin(full, "v9.9.9-lab")
    sim = Sim(router(**SOCKS_ON))
    assert full.full(sim, "--publish-branch", "test/iter3") == 0
    assert len(sim.writes) == 1
    assert only_action(full.reports("test/iter3")[-1], SOCKS_RULE)["status"] == "succeeded"


def test_invalid_plan_blocks_router_change(full, monkeypatch, capsys):
    monkeypatch.setattr(cli, "validate_report", lambda doc: ["atrapa błędu"])
    sim = Sim(router(**SOCKS_ON))
    assert full.full(sim) == 1
    assert sim.writes == [] and sim.monitor_calls == 1
    assert "[KONTRAKT]" in capsys.readouterr().err
    assert not (full.out() / "state.json").exists()


def test_invalid_final_report_keeps_evidence(full, monkeypatch):
    real = validate.validate_report
    calls = []

    def second_fails(doc):
        calls.append(doc)
        return real(doc) if len(calls) == 1 else ["atrapa błędu"]

    monkeypatch.setattr(cli, "validate_report", second_fails)
    sim = Sim(router(**SOCKS_ON))
    assert full.full(sim) == 1
    assert len(sim.writes) == 1
    assert list((full.out() / "evidence").rglob("remediation.json"))
    assert not (full.out() / "state.json").exists()


# --- PR driftu ---
def branches(remote):
    out = subprocess.run(["git", "-C", str(remote.bare), "for-each-ref", "--format=%(refname:short)", "refs/heads/agent"],
                         capture_output=True, text=True, check=True)
    return out.stdout.split()


def test_drift_pushes_branch_with_baseline_change_only(full):
    github_origin(full)
    sim = Sim(router())
    assert full.full(sim) == 0
    sim.data[("system", "scheduler")] = copy.deepcopy(TASK)
    full.later()
    assert full.full(sim) == 0
    rep = full.reports()[-1]
    assert validate.validate_report(rep) == []
    action = only_action(rep, DRIFT_RULE)
    run_id = rep["run"]["run_id"]
    assert (action["type"], action["status"]) == ("open-pr", "succeeded")
    assert action["external_ref"] == f"https://github.com/lab/site-lab/compare/main...agent/r2/{run_id}?expand=1"
    assert branches(full) == [f"agent/r2/{run_id}"]
    assert sim.writes == []

    bare = str(full.bare)
    out = subprocess.run(["git", "-C", bare, "diff", "--name-only", f"agent/r2/{run_id}~1", f"agent/r2/{run_id}"],
                         capture_output=True, text=True, check=True).stdout.split()
    assert out == ["routers/r2/baseline-state.yml"]
    diff = subprocess.run(["git", "-C", bare, "diff", f"agent/r2/{run_id}~1", f"agent/r2/{run_id}"],
                          capture_output=True, text=True, check=True).stdout
    changed = [line for line in diff.splitlines() if line[:1] in "+-" and line[:3] not in ("+++", "---")]
    assert changed == ["-scheduler: []", "+scheduler:", "+- interval: 1h", "+  name: zadanie"]
    message = subprocess.run(["git", "-C", bare, "log", "-1", "--format=%(trailers:key=Base,valueonly)", f"agent/r2/{run_id}"],
                             capture_output=True, text=True, check=True).stdout.strip()
    assert message == "main"
    assert len(state_of(full)["open_findings"]) == 1


def test_merging_proposal_accepts_drift(full):
    github_origin(full)
    sim = Sim(router())
    assert full.full(sim) == 0
    sim.data[("system", "scheduler")] = copy.deepcopy(TASK)
    full.later()
    assert full.full(sim) == 0
    branch = branches(full)[0]
    root = full.checkout()
    git(root, "fetch", "-q", "origin", branch)
    git(root, "merge", "-q", "--no-edit", "FETCH_HEAD")
    git(root, "push", "-q", "origin", "main")
    full.later()
    assert full.full(sim) == 0
    rep = full.reports()[-1]
    assert [r["resolved_by"] for r in rep["resolved"]] == ["policy-change"]
    assert state_of(full)["open_findings"] == []


def test_new_drift_findings_share_one_branch(full):
    github_origin(full)
    sim = Sim(router())
    assert full.full(sim) == 0
    sim.data[("system", "scheduler")] = copy.deepcopy(TASK)
    sim.data[("ppp", "secret")] = [{".id": "*1", "name": "vpn", "password": SECRET}]
    full.later()
    assert full.full(sim) == 0
    actions = full.reports()[-1]["actions"]
    assert len(actions) == 2 and len({a["external_ref"] for a in actions}) == 1
    assert len(branches(full)) == 1
    out = subprocess.run(["git", "-C", str(full.bare), "grep", "-c", SECRET, branches(full)[0]], capture_output=True, text=True)
    assert out.returncode == 1


def test_persisting_drift_opens_no_second_branch(full):
    github_origin(full)
    sim = Sim(router())
    assert full.full(sim) == 0
    sim.data[("system", "scheduler")] = copy.deepcopy(TASK)
    full.later()
    assert full.full(sim) == 0
    full.later()
    assert full.full(sim) == 0
    assert len(branches(full)) == 1


def test_proposal_failure_does_not_lose_repair(full):
    # origin lokalny zamiast GitHuba: PR nie powstanie, naprawa i raport muszą przejść.
    sim = Sim(router())
    assert full.full(sim) == 0
    sim.data[("ip", "socks")][0]["enabled"] = True
    sim.data[("system", "scheduler")] = copy.deepcopy(TASK)
    full.later()
    assert full.full(sim) == 0
    rep = full.reports()[-1]
    assert validate.validate_report(rep) == []
    assert only_action(rep, SOCKS_RULE)["status"] == "succeeded"
    assert only_action(rep, DRIFT_RULE)["status"] == "failed"
    assert "act.pr-failed" in {e["code"] for e in rep["run"]["errors"]}
    assert branches(full) == []


def test_sync_failure_repairs_but_opens_no_pr(full):
    github_origin(full)
    sim = Sim(router())
    assert full.full(sim) == 0
    git(full.lab.site, "config", "--unset", f"url.{full.bare}.insteadOf")
    git(full.lab.site, "remote", "set-url", "origin", "/nie/ma/repo.git")
    sim.data[("ip", "socks")][0]["enabled"] = True
    sim.data[("system", "scheduler")] = copy.deepcopy(TASK)
    full.later()
    assert full.full(sim) == 1
    assert len(sim.writes) == 1
    assert len(full.pending()) == 1
    rep = json.loads(full.pending()[0].read_text(encoding="utf-8"))
    assert only_action(rep, SOCKS_RULE)["status"] == "succeeded"
    assert only_action(rep, DRIFT_RULE)["status"] == "failed"


def test_test_branch_proposal_targets_test_branch(full):
    github_origin(full)
    sim = Sim(router())
    assert full.full(sim, "--publish-branch", "test/iter3") == 0
    sim.data[("system", "scheduler")] = copy.deepcopy(TASK)
    full.later()
    assert full.full(sim, "--publish-branch", "test/iter3") == 0
    action = only_action(full.reports("test/iter3")[-1], DRIFT_RULE)
    assert "/compare/test/iter3...agent/r2/" in action["external_ref"]
    assert full.commits("main") == 1


# --- alert ---
def test_local_rule_gets_alert_succeeded(full):
    policy = base.LOCAL_POLICY + """\
rules:
  - id: local.mgmt.socks-port
    title: "Port SOCKS bez zmian"
    severity: low
    reason: "Wymóg instalacji"
    check: { path: /ip/socks, assert: { port: "1081" } }
"""
    full.lab.write_site("routers/r2/local-policy.yml", policy)
    git(full.lab.site, "push", "-q", "origin", "main")
    sim = Sim(router())
    assert full.full(sim) == 0
    rep = full.reports()[-1]
    assert validate.validate_report(rep) == []
    action = only_action(rep, "local.mgmt.socks-port")
    assert (action["type"], action["status"]) == ("alert", "succeeded")
    assert action["external_ref"] is None and action["started_at"]
    assert branches(full) == []


def test_access_lost_gets_alert_succeeded(full):
    def rejected(ctx, password):
        raise TrapError(message="invalid user name or password (6)")

    assert cli.main(["--router", "r2", "--once"], paths=full.lab.paths, clock=full.clock, connector=rejected) == 0
    rep = full.reports()[-1]
    assert validate.validate_report(rep) == []
    action = only_action(rep, "integrity.management-access-lost")
    assert (action["type"], action["status"]) == ("alert", "succeeded")


def test_alert_is_only_proposed_with_no_remediate(full):
    def rejected(ctx, password):
        raise TrapError(message="invalid user name or password (6)")

    assert cli.main(["--router", "r2", "--once", "--no-remediate"], paths=full.lab.paths, clock=full.clock,
                    connector=rejected) == 0
    assert only_action(full.reports()[-1], "integrity.management-access-lost")["status"] == "proposed"


# --- propozycja baseline ---
def violations_for(baseline, state, local=None):
    return evaluate(state, [], local or {}, baseline).violations


def render(baseline, state, local=None):
    local = local or {}
    text = yaml.safe_dump(baseline, sort_keys=True, default_flow_style=False, allow_unicode=True)
    return yaml.safe_load(proposal.render(text, state, violations_for(baseline, state, local), ignored_attrs(local)))


def test_proposal_adds_removes_and_changes():
    baseline = {"scheduler": [{"name": "a", "interval": "1d"}, {"name": "b", "interval": "1h"}], "users": [{"name": "m"}]}
    state = {"scheduler": [{"name": "a", "interval": "2d"}, {"name": "c", "interval": "1h"}], "users": [{"name": "m"}]}
    doc = render(baseline, state)
    assert doc["scheduler"] == [{"name": "a", "interval": "2d"}, {"name": "c", "interval": "1h"}]
    assert doc["users"] == [{"name": "m"}]


def test_proposal_result_has_no_drift():
    baseline = {"scheduler": [{"name": "a", "interval": "1d"}], "firewall_filter": [{"chain": "input", "action": "drop"}]}
    state = {"scheduler": [], "firewall_filter": [{"chain": "input", "action": "accept"}]}
    assert violations_for(render(baseline, state), state) == []


def test_proposal_keeps_unrelated_file_content_identical():
    baseline = {"scheduler": [{"name": "a", "interval": "1d"}], "users": [{"name": "m", "comment": "zażółć"}]}
    state = {"scheduler": [{"name": "a", "interval": "2d"}], "users": [{"name": "m", "comment": "zażółć"}]}
    text = yaml.safe_dump(baseline, sort_keys=True, default_flow_style=False, allow_unicode=True)
    out = proposal.render(text, state, violations_for(baseline, state), {})
    assert out == text.replace("interval: 1d", "interval: 2d")


def test_proposal_with_ignored_attribute_keeps_row_key():
    local = {"drift": {"ignore": [{"resource": "firewall_filter", "attrs": ["comment"], "reason": "powod"}]}}
    baseline = {"firewall_filter": [{"chain": "input", "action": "drop", "comment": "BL"}]}
    state = {"firewall_filter": [{"chain": "input", "action": "drop", "comment": "BL"},
                                 {"chain": "input", "action": "accept"}]}
    doc = render(baseline, state, local)
    assert {r["action"] for r in doc["firewall_filter"]} == {"drop", "accept"}

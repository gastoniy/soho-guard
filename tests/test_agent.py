"""Pełny cykl agenta na atrapach: MockApi zamiast routera, repo Git w tmp_path."""
import copy
import fcntl
import json
import re
import ssl
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml
from librouteros.exceptions import ConnectionClosed, TrapError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import oracle_eval as oe  # noqa: E402
import validate_report as validate  # noqa: E402
from agent import l1_router, report  # noqa: E402
from agent import __main__ as cli  # noqa: E402
from agent.config import ConfigError, Paths, read_release  # noqa: E402
from agent.findings import fingerprint, render_values  # noqa: E402
from agent.normalize import build_state, fetch_resources  # noqa: E402

TAG = "v0.2.0-lab.rc1"
COMMIT = "a" * 40
SECRET = "HASLO-ATRAPA-123"
LOCAL_POLICY = """\
schema_version: "1.0"
drift:
  overrides:
    - { resource: ppp_secrets, id: local.ppp.secrets, severity: medium }
  ignore:
    - resource: firewall_filter
      attrs: [comment]
      reason: "Komentarz nie zmienia działania reguły"
"""

CLEAN = {
    ("system", "identity"): [{"name": "R2"}],
    ("system", "resource"): [{"version": "6.49.19 (long-term)", "uptime": "1d"}],
    ("ip", "socks"): [{"enabled": False, "port": 1080}],
    ("ip", "service"): [
        {".id": "*1", "name": "winbox", "disabled": False, "address": "10.100.2.0/24", "port": 8291},
        {".id": "*2", "name": "api-ssl", "disabled": False, "address": "10.100.2.0/24", "port": 8729},
        {".id": "*3", "name": "telnet", "disabled": True, "address": "", "port": 23},
        {".id": "*4", "name": "ftp", "disabled": True, "address": "", "port": 21},
        {".id": "*5", "name": "api", "disabled": True, "address": "", "port": 8728},
        {".id": "*6", "name": "www", "disabled": True, "address": "", "port": 80},
    ],
    ("ip", "smb"): [{"enabled": False}],
    ("tool", "bandwidth-server"): [{"enabled": False}],
    ("ip", "proxy"): [{"enabled": False}],
    ("ip", "upnp"): [{"enabled": False}],
    ("ip", "cloud"): [{"ddns-enabled": False}],
    ("ip", "neighbor", "discovery-settings"): [{"discover-interface-list": "MGMT"}],
    ("ip", "ssh"): [{"strong-crypto": True}],
    ("user",): [{".id": "*1", "name": "monitor", "disabled": False}],
    ("system", "scheduler"): [],
    ("ip", "firewall", "filter"): [{".id": "*1", "chain": "input", "action": "drop", "comment": "BL"}],
    ("ip", "firewall", "raw"): [],
    ("ip", "firewall", "mangle"): [],
    ("ppp", "secret"): [],
    ("ip", "firewall", "connection", "tracking"): [{"enabled": "auto", "active-ipv4": True}],
    ("ip", "firewall", "connection"): [],
}
WAN = "192.168.20.22"
DYNAMIC_BASELINE = {"schema_version": "1.0", "router_id": "r2",
                    "dns": {"allowed_resolvers": ["1.1.1.1", "9.9.9.9"], "alert_on_other_resolver": True}}
ZEEK_FIXTURES = ROOT / "tests" / "fixtures" / "zeek"


def zeek_header(kind: str) -> tuple[str, list[str]]:
    lines = (ZEEK_FIXTURES / f"{kind}.log").read_text(encoding="utf-8").splitlines(keepends=True)
    header = "".join(line for line in lines if line.startswith("#") and not line.startswith("#close"))
    fields = next(line for line in lines if line.startswith("#fields")).rstrip("\n").split("\t")[1:]
    return header, fields


def zeek_text(kind: str, rows: list[dict]) -> str:
    """Plik w formacie Zeeka: kolumny z nagłówka wzorca, brakujące pola jako '-'."""
    header, fields = zeek_header(kind)
    body = "".join("\t".join(str(row.get(f, "-")) for f in fields) + "\n" for row in rows)
    return header + body


class MockApi:
    def __init__(self, data):
        self.data = data

    def path(self, *parts):
        if parts not in self.data:
            raise KeyError("/".join(parts) + ": no such command")
        value = self.data[parts]
        if isinstance(value, Exception):
            raise value
        return [dict(x) for x in value]

    def close(self):
        pass


def router(**changes):
    data = copy.deepcopy(CLEAN)
    data.update({tuple(k.split("__")): v for k, v in changes.items()})
    return data


def git(cwd, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                   cwd=cwd, check=True, capture_output=True)


@dataclass
class Lab:
    paths: Paths
    site: Path

    @property
    def out(self) -> Path:
        return self.paths.data_dir / "dry-run" / "r2"

    @property
    def reports_dir(self) -> Path:
        return self.out / "reports" / "what-if"

    def run(self, data=None, *extra, connector=None):
        connector = connector or (lambda ctx, password: MockApi(CLEAN if data is None else data))
        return cli.main(["--router", "r2", "--once", "--dry-run", *extra], paths=self.paths, connector=connector)

    def state(self) -> dict:
        return json.loads((self.out / "state.json").read_text(encoding="utf-8"))

    def reports(self) -> list[dict]:
        files = sorted(self.reports_dir.rglob("*.json")) if self.reports_dir.exists() else []
        return [json.loads(p.read_text(encoding="utf-8")) for p in files]

    @property
    def zeek_current(self) -> Path:
        return self.paths.zeek_dir / "current"

    def zeek(self, kind: str, rows: list[dict]):
        (self.zeek_current / f"{kind}.log").write_text(zeek_text(kind, rows), encoding="utf-8")

    def write_site(self, relative, text):
        (self.site / relative).write_text(text, encoding="utf-8")
        git(self.site, "add", "-A")
        git(self.site, "commit", "-qm", "zmiana")


@pytest.fixture
def lab(tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    (app / "RELEASE").write_text(f"tag={TAG}\ncommit={COMMIT}\n", encoding="utf-8")
    (app / "policy").symlink_to(ROOT / "policy")
    etc = tmp_path / "etc"
    (etc / "r2").mkdir(parents=True)
    (etc / "r2" / "monitor.pass").write_text(SECRET + "\n", encoding="utf-8")
    site = tmp_path / "site"
    (site / "routers" / "r2").mkdir(parents=True)
    (site / "site.yml").write_text(yaml.safe_dump({
        "site_id": "lab", "policy": {"universal_version": TAG}, "heartbeat": {"interval_s": 1800},
        "routers": [{"router_id": "r2", "profile": "ros6", "path": "routers/r2"}]}), encoding="utf-8")
    (site / "routers/r2/inventory.yml").write_text(yaml.safe_dump({
        "router_id": "r2", "profile": "ros6", "local_policy": "routers/r2/local-policy.yml",
        "dynamic_baseline": "routers/r2/dynamic-baseline.yml",
        "addressing": {"mgmt_address": "10.100.2.1", "agent_source": "10.100.2.10",
                       "wan_address": f"{WAN}/24"}}), encoding="utf-8")
    (site / "routers/r2/dynamic-baseline.yml").write_text(yaml.safe_dump(DYNAMIC_BASELINE), encoding="utf-8")
    (site / "routers/r2/local-policy.yml").write_text(LOCAL_POLICY, encoding="utf-8")
    baseline = build_state(fetch_resources(MockApi(CLEAN)))
    (site / "routers/r2/baseline-state.yml").write_text(yaml.safe_dump(baseline), encoding="utf-8")
    git(site, "init", "-q")
    git(site, "add", "-A")
    git(site, "commit", "-qm", "start")
    zeek = tmp_path / "zeek"
    (zeek / "current").mkdir(parents=True)
    for kind in ("conn", "dns"):
        (zeek / "current" / f"{kind}.log").write_text(zeek_text(kind, []), encoding="utf-8")
    return Lab(Paths(app_dir=app, etc_dir=etc, data_dir=tmp_path / "data", site_dir=site, zeek_dir=zeek), site)


def only(reports, rule):
    return [f for f in reports[-1]["findings"] if f["rule"] == rule]


def action_of(rep, finding):
    return next(a for a in rep["actions"] if a["fingerprint"] == finding["fingerprint"])


def error_codes(rep):
    return {e["code"] for e in rep["run"]["errors"]}


SOCKS_ON = {"ip__socks": [{"enabled": True, "port": 1080}]}
SOCKS_RULE = "policy.services.socks.disabled"


# --- przebieg czysty ---
def test_clean_first_run_reports_inconclusive_until_l2(lab):
    assert lab.run() == 0
    reports = lab.reports()
    assert len(reports) == 1
    rep = reports[0]
    assert validate.validate_report(rep) == []
    assert validate.validate_state(lab.state()) == []
    assert rep["findings"] == [] and rep["actions"] == []
    assert rep["verdict"]["posture"] == "inconclusive" and rep["verdict"]["coverage"] == "partial"
    assert rep["collection"]["l1"]["status"] == "ok"
    l2 = rep["collection"]["l2"]
    assert l2["status"] == "degraded" and l2["sources"] == ["zeek"] and l2["note"] == cli.LAYER_PENDING["l2"]
    assert rep["policy"]["evaluation_mode"] == "what-if"
    assert rep["policy"]["universal_version"] == TAG and rep["policy"]["universal_commit"] == COMMIT
    assert re.fullmatch(r"[0-9a-f]{40}", rep["policy"]["local_commit"])
    assert rep["target"]["identity_reported"] == "R2" and rep["target"]["profile_used"] == "ros6"
    assert rep["run"]["agent_version"] == "0.2.0" and rep["run"]["trigger"] == "manual"
    assert rep["integrity"] == {"report_seq": 1, "previous_report_sha256": None}


def test_unchanged_second_run_has_no_report(lab):
    assert lab.run() == 0
    assert lab.run() == 0
    assert len(lab.reports()) == 1
    state = lab.state()
    assert state["last_run"]["run_seq"] == 2
    assert state["last_report"]["report_seq"] == 1


def test_trigger_recorded(lab):
    assert lab.run(None, "--trigger", "timer") == 0
    assert lab.reports()[0]["run"]["trigger"] == "timer"


def test_nothing_written_to_site_repo(lab):
    assert lab.run(router(**SOCKS_ON)) == 0
    out = subprocess.run(["git", "status", "--porcelain"], cwd=lab.site, capture_output=True, text=True, check=True)
    assert out.stdout == ""


# --- naruszenie uniwersalne: POL-003 ---
def test_universal_violation_is_described_not_executed(lab):
    assert lab.run(router(**SOCKS_ON)) == 0
    rep = lab.reports()[-1]
    assert rep["verdict"]["posture"] == "policy-violation"
    finding = only([rep], SOCKS_RULE)[0]
    assert finding["status"] == "new" and finding["severity"] == "critical"
    assert finding["evidence"]["expected"] == {"enabled": "no"}
    assert finding["evidence"]["observed"] == {"enabled": "yes"}
    assert finding["also_matched"] == ["local.drift.socks"]
    assert finding["fingerprint"] == fingerprint(SOCKS_RULE, "/ip/socks", "socks")
    action = action_of(rep, finding)
    assert action["type"] == "auto-remediate" and action["status"] == "proposed"
    assert "enabled=no" in action["reason"]
    assert action["started_at"] is None and action["verification"] is None
    assert validate.validate_report(rep) == []


def test_pol003_oracle_differs_only_by_unexecuted_remediation(lab):
    assert lab.run(router(**SOCKS_ON)) == 0
    manifest = yaml.safe_load((ROOT / "scenarios/policy/policy-socks-enabled.yml").read_text(encoding="utf-8"))
    problems = oe.oracle_eval(manifest, lab.reports()[-1], lab.state())
    # Wykonanie remediacji i jej weryfikacja dochodzą w iteracji 3.
    assert len(problems) == 2
    assert any("auto-remediate.status" in p for p in problems)
    assert any("end_state=baseline" in p for p in problems)


def test_rule_without_remediate_gets_none_skipped(lab):
    services = copy.deepcopy(CLEAN[("ip", "service")])
    services[0]["address"] = ""
    assert lab.run(router(ip__service=services)) == 0
    rep = lab.reports()[-1]
    finding = only([rep], "policy.mgmt.winbox.not-public")[0]
    action = action_of(rep, finding)
    assert action["type"] == "none" and action["status"] == "skipped"
    assert validate.validate_report(rep) == []


def test_active_admin_finding(lab):
    users = [{"name": "admin", "disabled": False}, {"name": "monitor", "disabled": False}]
    assert lab.run(router(user=users)) == 0
    rep = lab.reports()[-1]
    finding = only([rep], "policy.accounts.default-admin.disabled")[0]
    assert finding["evidence"]["expected"] is None
    assert validate.validate_report(rep) == []


# --- cykl życia findingu i łańcuch ---
def test_new_persisting_resolved_and_chain(lab):
    bad = router(**SOCKS_ON)
    assert lab.run(bad) == 0
    first_seen = only(lab.reports(), SOCKS_RULE)[0]["first_seen_at"]
    assert lab.state()["posture"] == "policy-violation"

    assert lab.run(bad) == 0
    assert len(lab.reports()) == 1
    assert lab.state()["open_findings"][0]["first_seen_at"] == first_seen

    assert lab.run() == 0
    reports = lab.reports()
    assert len(reports) == 2
    resolved = reports[-1]["resolved"][0]
    assert resolved["rule"] == SOCKS_RULE and resolved["resolved_by"] == "external-change"
    assert resolved["first_seen_at"] == first_seen
    assert lab.state()["open_findings"] == []
    assert validate.validate_chain(lab.reports_dir) == []
    assert lab.state()["last_report"]["report_seq"] == 2


def test_persisting_finding_in_later_report(lab):
    bad = router(**SOCKS_ON)
    assert lab.run(bad) == 0
    users = [{"name": "nowy", "disabled": False}, {"name": "monitor", "disabled": False}]
    assert lab.run(router(user=users, **SOCKS_ON)) == 0
    rep = lab.reports()[-1]
    assert only([rep], SOCKS_RULE)[0]["status"] == "persisting"
    assert only([rep], "local.drift.users")[0]["status"] == "new"
    assert len(rep["actions"]) == 1
    assert validate.validate_report(rep) == []
    assert validate.validate_chain(lab.reports_dir) == []


# --- drift i polityka lokalna: SITE-007, BEN-002 ---
def test_site007_oracle_passes(lab):
    data = router(ppp__secret=[{".id": "*1", "name": "vpn", "password": SECRET, "service": "any"}])
    assert lab.run(data) == 0
    rep = lab.reports()[-1]
    finding = only([rep], "local.ppp.secrets")[0]
    assert action_of(rep, finding)["type"] == "open-pr"
    assert rep["verdict"]["posture"] == "site-drift"
    assert validate.validate_report(rep) == []
    manifest = yaml.safe_load((ROOT / "scenarios/site/site-ppp-secret.yml").read_text(encoding="utf-8"))
    assert oe.oracle_eval(manifest, rep, lab.state()) == []


def test_ben002_comment_change_is_not_drift(lab):
    rule_row = [{".id": "*9", "chain": "input", "action": "drop", "comment": "inny komentarz"}]
    assert lab.run(router(ip__firewall__filter=rule_row)) == 0
    assert lab.reports()[-1]["findings"] == []


def test_new_firewall_rule_is_drift(lab):
    rows = copy.deepcopy(CLEAN[("ip", "firewall", "filter")]) + [{"chain": "input", "action": "accept"}]
    assert lab.run(router(ip__firewall__filter=rows)) == 0
    finding = only(lab.reports(), "local.drift.firewall-filter")[0]
    assert finding["evidence"]["expected"] is None
    assert finding["evidence"]["observed"]["action"] == "accept"


@pytest.mark.parametrize("menu,rule,row", [
    ("ip__firewall__raw", "local.drift.firewall-raw",
     {".id": "*1", "chain": "output", "protocol": "icmp", "dst-address": "8.8.4.4", "action": "notrack"}),
    ("ip__firewall__mangle", "local.drift.firewall-mangle",
     {".id": "*1", "chain": "prerouting", "action": "mark-routing", "new-routing-mark": "tunel"}),
])
def test_raw_and_mangle_rule_is_drift(lab, menu, rule, row):
    """notrack ukrywa sesję w tablicy połączeń: przyczyna rozbieżności musi być widoczna w fazie statycznej."""
    assert lab.run(router(**{menu: [row]})) == 0
    finding = only(lab.reports(), rule)[0]
    assert finding["evidence"]["expected"] is None and finding["evidence"]["observed"]["action"] == row["action"]
    assert action_of(lab.reports()[-1], finding)["type"] == "open-pr"


def test_local_rule_finding(lab):
    policy = LOCAL_POLICY + """\
rules:
  - id: local.mgmt.socks-port
    title: "Port SOCKS bez zmian"
    severity: low
    reason: "Wymóg instalacji"
    check: { path: /ip/socks, assert: { port: "1081" } }
"""
    lab.write_site("routers/r2/local-policy.yml", policy)
    assert lab.run() == 0
    rep = lab.reports()[-1]
    finding = only([rep], "local.mgmt.socks-port")[0]
    assert finding["rule_source"] == "local" and finding["ioc"] is False
    assert rep["verdict"]["posture"] == "site-drift"


def test_accepted_baseline_change_resolves_as_policy_change(lab):
    data = router(ppp__secret=[{"name": "vpn", "service": "any"}])
    assert lab.run(data) == 0
    lab.write_site("routers/r2/baseline-state.yml",
                   yaml.safe_dump(build_state(fetch_resources(MockApi(data)))))
    assert lab.run(data) == 0
    resolved = lab.reports()[-1]["resolved"][0]
    assert resolved["rule"] == "local.ppp.secrets" and resolved["resolved_by"] == "policy-change"


def test_rule_removed_from_policy_resolves_as_policy_change(lab):
    assert lab.run() == 0
    state = lab.state()
    state["open_findings"] = [{"fingerprint": "sha256:" + "b" * 64, "rule": "policy.stara.regula",
                               "rule_source": "universal", "severity": "low", "compromise_indicator": False,
                               "first_seen_at": "2026-01-01T00:00:00.000Z"}]
    (lab.out / "state.json").write_text(json.dumps(state), encoding="utf-8")
    assert lab.run() == 0
    assert lab.reports()[-1]["resolved"][0]["resolved_by"] == "policy-change"


# --- awarie L1 ---
def test_auth_rejected_is_access_lost(lab):
    def rejected(ctx, password):
        raise TrapError("invalid user name or password (6)")
    assert lab.run(connector=rejected) == 0
    rep = lab.reports()[-1]
    finding = only([rep], "integrity.management-access-lost")[0]
    assert finding["evidence"]["type"] == "access" and finding["severity"] == "critical"
    assert action_of(rep, finding)["type"] == "alert"
    assert rep["verdict"]["posture"] == "compromise-suspected"
    assert rep["collection"]["l1"]["status"] == "unavailable"
    assert rep["target"]["identity_reported"] is None
    assert validate.validate_report(rep) == []


def test_access_restored_resolves_finding(lab):
    def rejected(ctx, password):
        raise TrapError("invalid user name or password (6)")
    assert lab.run(connector=rejected) == 0
    assert lab.run() == 0
    assert lab.reports()[-1]["resolved"][0]["rule"] == "integrity.management-access-lost"
    assert lab.state()["open_findings"] == []


@pytest.mark.parametrize("exc,code", [
    (TimeoutError("timed out"), "l1.unreachable"),
    (ConnectionRefusedError("refused"), "l1.unreachable"),
    (ssl.SSLCertVerificationError("certificate verify failed"), "l1.tls-verify-failed"),
    (ssl.SSLError("handshake"), "l1.tls-error"),
    (ConnectionClosed("closed"), "l1.connect-failed"),
])
def test_sensor_failure_is_never_compromise(lab, exc, code):
    def failing(ctx, password):
        raise exc
    assert lab.run(connector=failing) == 0
    rep = lab.reports()[-1]
    assert rep["findings"] == []
    assert rep["verdict"]["posture"] == "inconclusive"
    assert code in error_codes(rep)
    assert validate.validate_report(rep) == []


def test_missing_password_file_is_not_auth_rejection(lab):
    (lab.paths.etc_dir / "r2" / "monitor.pass").unlink()
    called = []
    assert lab.run(connector=lambda ctx, password: called.append(1)) == 0
    rep = lab.reports()[-1]
    assert not called
    assert "l1.credentials-unavailable" in error_codes(rep)
    assert rep["verdict"]["posture"] == "inconclusive"


def test_outage_keeps_open_findings(lab):
    assert lab.run(router(**SOCKS_ON)) == 0

    def down(ctx, password):
        raise TimeoutError("timed out")
    assert lab.run(connector=down) == 0
    rep = lab.reports()[-1]
    assert rep["resolved"] == [] and rep["findings"] == []
    state = lab.state()
    assert [f["rule"] for f in state["open_findings"]] == [SOCKS_RULE]
    assert state["posture"] == "policy-violation"
    assert validate.validate_state(state) == []


def test_read_failure_degrades_and_does_not_resolve(lab):
    assert lab.run(router(**SOCKS_ON)) == 0
    assert lab.run(router(ip__socks=RuntimeError("timeout"))) == 0
    rep = lab.reports()[-1]
    assert rep["collection"]["l1"]["status"] == "degraded"
    assert "nie oceniono" in rep["collection"]["l1"]["note"]
    assert "l1.read-failed" in error_codes(rep)
    assert rep["resolved"] == []
    assert [f["rule"] for f in lab.state()["open_findings"]] == [SOCKS_RULE]


def test_missing_menu_on_old_version_is_not_error(lab):
    assert lab.run() == 0     # CLEAN nie ma wireguard: brak menu nie jest błędem
    rep = lab.reports()[-1]
    assert rep["run"]["errors"] == [] and rep["collection"]["l1"]["status"] == "ok"


# --- błędy przebiegu ---
def test_version_mismatch_reported_once_and_evaluation_continues(lab):
    site = yaml.safe_load((lab.site / "site.yml").read_text(encoding="utf-8"))
    site["policy"]["universal_version"] = "v0.1.0-lab"
    lab.write_site("site.yml", yaml.safe_dump(site))
    assert lab.run(router(**SOCKS_ON)) == 0
    rep = lab.reports()[-1]
    assert "policy.version-mismatch" in error_codes(rep)
    assert rep["policy"]["universal_version"] == TAG
    assert only([rep], SOCKS_RULE)
    assert lab.run(router(**SOCKS_ON)) == 0
    assert len(lab.reports()) == 1


def test_new_error_kind_triggers_report(lab):
    assert lab.run() == 0
    assert lab.run(router(ip__smb=RuntimeError("x"))) == 0
    assert len(lab.reports()) == 2


@pytest.mark.parametrize("content", [None, "schema_version: '9'\n", "rules: [zly\n"])
def test_invalid_local_policy_keeps_monitoring(lab, content):
    path = lab.site / "routers/r2/local-policy.yml"
    if content is None:
        path.unlink()
    else:
        path.write_text(content, encoding="utf-8")
    assert lab.run(router(**SOCKS_ON)) == 0
    rep = lab.reports()[-1]
    assert "local-policy.invalid" in error_codes(rep)
    assert rep["collection"]["l1"]["status"] == "degraded"
    assert only([rep], SOCKS_RULE)
    assert validate.validate_report(rep) == []


def test_invalid_baseline_lowers_coverage_without_false_drift(lab):
    (lab.site / "routers/r2/baseline-state.yml").write_text("nie: [poprawny\n", encoding="utf-8")
    assert lab.run() == 0
    rep = lab.reports()[-1]
    assert "baseline.invalid" in error_codes(rep)
    assert rep["findings"] == []
    assert rep["collection"]["l1"]["status"] == "degraded"


def test_contract_failure_writes_nothing(lab, monkeypatch, capsys):
    monkeypatch.setattr(cli, "validate_report", lambda doc: ["naruszenie"])
    assert lab.run() == 1
    assert "naruszenie" in capsys.readouterr().err
    assert not (lab.out / "state.json").exists()
    assert lab.reports() == []
    assert not (lab.out / "evidence").exists()


# --- sekrety (R6) ---
def test_secrets_never_reach_output_files(lab, capsys):
    data = router(ppp__secret=[{"name": "vpn", "password": SECRET}],
                  interface__wireguard__peers=[{"public-key": "PUB", "preshared-key": SECRET}])
    assert lab.run(data) == 0
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err
    files = [p for p in lab.out.rglob("*") if p.is_file()]
    assert files
    for path in files:
        assert SECRET not in path.read_text(encoding="utf-8"), path


def test_password_read_without_newline_and_not_in_errors(lab):
    seen = []

    def rejected(ctx, password):
        seen.append(password)
        raise TrapError("invalid user name or password (6)")
    assert lab.run(connector=rejected) == 0
    assert seen == [SECRET]
    assert SECRET not in json.dumps(lab.reports()[-1])


def test_evidence_file_is_private(lab):
    assert lab.run() == 0
    run_id = lab.reports()[-1]["run"]["run_id"]
    path = lab.out / "evidence" / run_id / "l1.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert "socks" in json.loads(path.read_text(encoding="utf-8"))


def test_public_key_is_redacted_in_report_values():
    values = render_values({"public-key": "PUB", "enabled": True, "brak": None, "Zla": "x"})
    assert re.fullmatch(r"redacted:sha256:[0-9a-f]{8}", values["public-key"])
    assert values["enabled"] == "yes"
    assert set(values) == {"public-key", "enabled"}


# --- CLI i konfiguracja ---
@pytest.mark.parametrize("argv,fragment", [
    (["--router", "r2", "--dry-run"], "wymagane --once"),
    (["--router", "r2", "--once", "--dry-run", "--no-remediate"], "nie publikuje"),
    (["--router", "r2", "--once", "--dry-run", "--publish-branch", "test/x"], "nie publikuje"),
    (["--router", "r2", "--once", "--no-remediate", "--publish-branch", "main"], "test/<nazwa>"),
    (["--router", "r2", "--once", "--no-remediate", "--publish-branch", "test/../x"], "test/<nazwa>"),
])
def test_cli_rejects_unavailable_modes(lab, capsys, argv, fragment):
    with pytest.raises(SystemExit) as info:
        cli.main(argv, paths=lab.paths)
    assert info.value.code == 2
    assert fragment in capsys.readouterr().err


@pytest.mark.parametrize("router_id", ["../r2", "R2", "nie-ma"])
def test_bad_router_is_config_error(lab, router_id):
    assert cli.main(["--router", router_id, "--once", "--dry-run"], paths=lab.paths) == 1
    assert not (lab.paths.data_dir / "dry-run").exists()


def test_placeholder_address_is_config_error(lab, capsys):
    inv = yaml.safe_load((lab.site / "routers/r2/inventory.yml").read_text(encoding="utf-8"))
    inv["addressing"]["mgmt_address"] = "CHANGE_ME"
    lab.write_site("routers/r2/inventory.yml", yaml.safe_dump(inv))
    assert lab.run() == 1
    assert "mgmt_address" in capsys.readouterr().err


def test_busy_lock_exits_without_output(lab):
    lock_path = lab.paths.data_dir / "r2" / "run.lock"
    lock_path.parent.mkdir(parents=True)
    with open(lock_path, "a", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        assert lab.run() == 3
    assert not (lab.out / "state.json").exists()


def test_corrupt_previous_state_stops_cycle(lab):
    assert lab.run() == 0
    (lab.out / "state.json").write_text("{zepsuty", encoding="utf-8")
    assert lab.run() == 1
    assert len(lab.reports()) == 1


@pytest.mark.parametrize("text,fragment", [
    (None, "brak pliku RELEASE"),
    ("tag=main\ncommit=" + COMMIT + "\n", "tag"),
    ("tag=v1.0.0-lab\ncommit=xyz\n", "commit"),
])
def test_release_file_errors(tmp_path, text, fragment):
    if text is not None:
        (tmp_path / "RELEASE").write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError, match=fragment):
        read_release(tmp_path)


@pytest.mark.parametrize("tag,version", [("v0.2.0-lab", "0.2.0"), ("v0.2.0-lab.rc3", "0.2.0"), ("v1.2.3", "1.2.3")])
def test_agent_version_from_tag(tmp_path, tag, version):
    (tmp_path / "RELEASE").write_text(f"tag={tag}\ncommit={COMMIT}\n", encoding="utf-8")
    assert read_release(tmp_path) == (tag, COMMIT, version)


def test_ulid_and_timestamp_match_schema():
    moment = datetime(2026, 11, 6, 12, 0, 0, 5000, tzinfo=timezone.utc)
    assert report.timestamp(moment) == "2026-11-06T12:00:00.005Z"
    first = report.new_ulid(moment)
    assert re.fullmatch(r"[0-9A-HJKMNP-TV-Z]{26}", first)
    assert first[:10] == report.new_ulid(moment)[:10]
    assert first < report.new_ulid(datetime(2026, 11, 6, 12, 0, 1, tzinfo=timezone.utc))


# --- połączenie L1 ---
def test_connect_uses_api_ssl_with_ca_verification(lab, monkeypatch):
    import librouteros

    from agent.config import load_context
    captured = {}
    cafiles = []
    real = ssl.create_default_context

    def fake_context(cafile=None):
        cafiles.append(cafile)
        return real()

    monkeypatch.setattr(ssl, "create_default_context", fake_context)
    monkeypatch.setattr(librouteros, "connect", lambda **kw: captured.update(kw) or "api")
    ctx = load_context("r2", lab.paths)
    assert l1_router.connect_monitor(ctx, SECRET) == "api"
    assert captured["port"] == 8729 and captured["host"] == "10.100.2.1"
    assert captured["username"] == "monitor" and captured["saddr"] == "10.100.2.10"
    assert captured["encoding"] == "latin-1"
    assert cafiles == [str(lab.paths.etc_dir / "ca.crt")]
    wrapper = captured["ssl_wrapper"]
    assert wrapper.keywords == {"server_hostname": "10.100.2.1"}
    assert wrapper.func.__self__.verify_mode == ssl.CERT_REQUIRED
    assert wrapper.func.__self__.check_hostname is True


def test_api_closed_after_read(lab):
    closed = []

    class Tracking(MockApi):
        def close(self):
            closed.append(True)
    assert lab.run(connector=lambda ctx, password: Tracking(CLEAN)) == 0
    assert closed == [True]


def test_fetch_resources_failed_excludes_missing_menu():
    failed = {}
    raw = fetch_resources(MockApi({("ip", "socks"): RuntimeError("timeout")}), failed=failed)
    assert raw == {}
    assert failed == {"socks": "timeout"}

"""Testy harnessu (iteracje 1–2) — bez sieci, routerów i GitHuba.

Repo instalacji: prawdziwe repo Git w tmp_path (origin bare + klon „agenta” + klon harnessu),
raporty i stan w formacie agenta (z examples/), wzorce bramki. Router: atrapa Ansible ze stanem
obiektów i atrapa SSH (eksport). GitHub: atrapa `gh`.
Zegar: atrapa przesuwana przez sleep(), z zaplanowanymi zdarzeniami („agent publikuje raport”).
"""
import copy
import json
import logging
import os
import random
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from harness import REPO_ROOT, HarnessError, UsageError
from harness import __main__ as cli
from harness import campaign as campaign_mod
from harness import config as config_mod
from harness import summary as summary_mod
from harness import artifacts, gate, generate, probes, reset, results, scenario, sitelab, timing
from harness.config import Config, RouterCfg, TimingCfg
from harness.router import Ansible, Ssh
from harness.scenario import Context, run_scenario

EX = REPO_ROOT / "examples"
POL003 = REPO_ROOT / "scenarios" / "policy" / "policy-socks-enabled.yml"
BEN002 = REPO_ROOT / "scenarios" / "benign" / "benign-firewall-comment.yml"
SITE007 = REPO_ROOT / "scenarios" / "site" / "site-ppp-secret.yml"
RULE = "policy.services.socks.disabled"
T_START = datetime(2026, 11, 13, 10, 1, 0, tzinfo=timezone.utc)


def ts(t: datetime) -> str:
    return timing.iso(t)


# ---------------------------------------------------------------- atrapy
class FakeClock:
    def __init__(self, start: datetime):
        self.t = start
        self.events: list[tuple[datetime, callable]] = []

    def now(self):
        return self.t

    def at(self, when: datetime, fn):
        self.events.append((when, fn))
        self.events.sort(key=lambda e: e[0])

    def sleep(self, seconds):
        target = self.t + timedelta(seconds=max(seconds, 0))
        while self.events and self.events[0][0] <= target:
            when, fn = self.events.pop(0)
            self.t = max(self.t, when)
            fn()
        self.t = target

    def sleep_until(self, when):
        self.sleep((when - self.t).total_seconds())


GATE_READS = {
    "user": [{"name": "ansible", "group": "bl-ansible", "address": "192.0.2.0/24",
              "disabled": False, "last-logged-in": "nov/13/2026 10:00:00"},
             {"name": "monitor", "group": "bl-monitor", "address": "192.0.2.0/24",
              "disabled": "no"}],
    "user ssh-keys": [{"user": "ansible", "key-owner": "ansible@host", "bits": 4096}],
    "certificate": [{"name": "bl-api.crt_0", "common-name": "192.0.2.2", "fingerprint": "ab12",
                     "trusted": False, "private-key": True, "expires-after": "51w"}],
    "file": [{"name": "flash", "type": "directory", "size": 0},
             {"name": "flash/pub", "type": "directory"}],
}
EXPORT_PATTERN = """# nov/13/2026 15:03:03 by RouterOS 6.49.19
# software id =
#
/ip firewall filter add action=accept chain=input comment="BL: in icmp" protocol=icmp
#error exporting /ip firewall calea
/ip socks set enabled=no
"""


class FakeAnsible:
    """Router: `ip socks`, reguła input/icmp, sekrety PPP i obiekty bramki; playbooki zmieniają stan."""

    def __init__(self, enabled=False, apply_effect=True, fail_tags=()):
        self.enabled = enabled
        self.icmp_comment = probes.BEN002_COMMENT_BASELINE
        self.ppp: list[str] = []
        self.proxy = False
        self.api_disabled = True
        self.winbox_address = "192.0.2.0/24"
        self.users: list[str] = []
        self.covert = None               # DYN-011a: cel reguły raw notrack (None = brak)
        self.extras: list[tuple[str, dict | None]] = []     # (tag, extra) wywołań playbooków
        self.extra_user = False          # obiekt spoza wzorca bramki
        self.export_extra: list[str] = []
        self.leave_after_revert = False  # revert „zapomina” o zmianie → bramka po teardownie
        self.apply_effect = apply_effect
        self.fail_tags = set(fail_tags)
        self.calls: list[str] = []

    def read(self, router, path):
        self.calls.append("read")
        if path == "ip socks":
            return [{"enabled": self.enabled, "port": 1080}]
        if path == "ip firewall filter":
            return [{"chain": "input", "protocol": "icmp", "action": "accept",
                     "comment": self.icmp_comment},
                    {"chain": "input", "action": "drop", "comment": "BL: in drop all"}]
        if path == "ppp secret":
            return [{".id": "*1", "name": n, "service": "any", "password": "S3cr3tValue"}
                    for n in self.ppp]
        if path == "ip proxy":
            return [{"enabled": self.proxy, "port": 8080}]
        if path == "ip service":
            rows = [{"name": "api", "disabled": self.api_disabled, "port": 8728},
                    {"name": "api-ssl", "disabled": False, "port": 8729},
                    {"name": "winbox", "disabled": False, "port": 8291}]
            if self.winbox_address:          # RouterOS pomija puste pole
                rows[2]["address"] = self.winbox_address
            return rows
        if path == "user":
            return [{"name": "ansible", "group": "bl-ansible"}] + \
                [{"name": n, "group": "read", "disabled": True} for n in self.users]
        raise AssertionError(path)

    def read_many(self, router, paths, raw=False):
        if list(paths) == list(gate.OBJECT_FIELDS):
            assert raw                               # bramka: print bez modelu wersji (v6)
            self.calls.append("gate")
            reads = copy.deepcopy(GATE_READS)
            if self.extra_user:
                reads["user"].append({"name": "intruder", "group": "full", "disabled": False})
            return reads
        return {p: self.read(router, p) for p in paths}

    def playbook(self, playbook, router, tags=None, extra=None):
        self.calls.append(tags)
        self.extras.append((tags, extra))
        if tags in self.fail_tags:
            raise HarnessError(f"{playbook} [{tags}]: kod 2")
        if tags == "apply" and not self.apply_effect:
            return
        apply = tags == "apply"
        name = Path(playbook).stem
        if name == "socks-enabled":
            self.enabled = apply
        elif name == "add-allowed-firewall-comment":
            self.icmp_comment = (probes.BEN002_COMMENT_APPLIED if apply
                                 else probes.BEN002_COMMENT_BASELINE)
        elif name == "ppp-secret-add":
            if apply:
                self.ppp.append(probes.SITE007_SECRET)
            else:
                self.ppp = [n for n in self.ppp if n != probes.SITE007_SECRET]
        elif name == "proxy-enabled":
            self.proxy = apply
        elif name == "api-plain-enabled":
            self.api_disabled = not apply
        elif name == "winbox-public":
            self.winbox_address = "" if apply else extra["probe_pre"]["address"]
        elif name == "user-add":
            if apply:
                self.users.append(probes.SITE008_USER)
            else:
                self.users = [n for n in self.users if n != probes.SITE008_USER]
        elif name == "covert-icmp":
            self.covert = (extra or {}).get("covert_target") if apply else None
        else:
            raise AssertionError(playbook)
        if tags == "revert" and self.leave_after_revert:
            self.extra_user = True


class FakeSsh:
    """Eksport = wzorzec z innym nagłówkiem (data), CRLF jak z RouterOS, plus ewentualne linie."""

    def __init__(self, ans: FakeAnsible):
        self.ans = ans
        self.runs: list[str] = []        # zdalne polecenia (generate: :execute, :put …)

    def run(self, router, remote, opts=(), timeout=None, input=None, check=True):
        self.ans.calls.append("ssh")
        self.runs.append(remote)
        out = "1\n" if remote.startswith(":put") else ""
        return subprocess.CompletedProcess([remote], 0, out, "")

    def export(self, router):
        body = EXPORT_PATTERN.split("\n", 3)[3]
        text = "# nov/14/2026 09:00:00 by RouterOS 6.49.19\n# software id =\n#\n" + body
        text += "".join(ln + "\n" for ln in self.ans.export_extra)
        return text.replace("\n", "\r\n")


class FakeGitHub:
    def __init__(self):
        self.prs: dict[str, list[dict]] = {}
        self.issues: list[dict] = []
        self.closed: list[tuple[str, int, str]] = []

    def prs_for_branch(self, branch):
        return self.prs.get(branch, [])

    def issues_for_report(self, path):
        return [i for i in self.issues if path in i.get("body", "")]

    def close_pr(self, n, comment):
        self.closed.append(("pr", n, comment))

    def close_issue(self, n, comment):
        self.closed.append(("issue", n, comment))


def git(cwd, *args, when: datetime | None = None):
    env = dict(os.environ, GIT_AUTHOR_NAME="soho-agent", GIT_AUTHOR_EMAIL="a@lab.invalid",
               GIT_COMMITTER_NAME="soho-agent", GIT_COMMITTER_EMAIL="a@lab.invalid")
    if when is not None:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = when.isoformat()
    return subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True,
                          text=True, env=env).stdout


def state_doc(**over):
    st = json.loads((EX / "state-r2.json").read_text(encoding="utf-8"))
    st.update(site_id="lab", posture="no-violations", coverage="full", open_findings=[],
              policy={"universal_version": "v0.7.1-lab"})
    st.update(over)
    return st


SITE_YML = {
    "schema_version": "1.0", "site_id": "lab",
    "policy": {"universal_version": "v0.7.1-lab"},
    "heartbeat": {"interval_s": 1800},
    "routers": [{"router_id": "r1", "profile": "ros7", "path": "routers/r1"},
                {"router_id": "r2", "profile": "ros6", "path": "routers/r2"}],
}


def report_doc(first_seen: datetime, rule=RULE, finished: datetime | None = None, seq=6):
    rep = copy.deepcopy(json.loads((EX / "report-policy-violation.json").read_text(encoding="utf-8")))
    rep["findings"] = rep["findings"][:1]
    f = rep["findings"][0]
    f["rule"], f["first_seen_at"] = rule, ts(first_seen)
    rep["run"]["run_seq"] = seq
    rep["run"]["agent_version"] = "0.7.1"
    fin = finished or first_seen + timedelta(seconds=2)
    rep["actions"][0]["finished_at"] = ts(fin)
    return rep


class SiteRepo:
    """origin (bare) ← klon agenta (zapis) ; klon harnessu (tylko fetch)."""

    def __init__(self, tmp: Path, state: dict):
        self.origin = tmp / "origin.git"
        self.agent = tmp / "agent"
        self.clone = tmp / "harness-clone"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(self.origin)], check=True)
        subprocess.run(["git", "clone", "-q", str(self.origin), str(self.agent)], check=True,
                       capture_output=True)
        git(self.agent, "checkout", "-q", "-b", "main")
        (self.agent / "site.yml").write_text(yaml.safe_dump(SITE_YML), encoding="utf-8")
        for rid in ("r1", "r2"):
            d = self.agent / "routers" / rid
            d.mkdir(parents=True)
            (d / "export.rsc").write_text(EXPORT_PATTERN, encoding="utf-8")
            (d / "gate-objects.yml").write_text(
                gate.dump_objects(rid, gate.project(GATE_READS), T_START), encoding="utf-8")
        self.commit_state(state, T_START - timedelta(minutes=30), "init")
        subprocess.run(["git", "clone", "-q", str(self.origin), str(self.clone)], check=True,
                       capture_output=True)

    def commit_state(self, state, when, msg, report=None, router="r2"):
        (self.agent / "state").mkdir(exist_ok=True)
        (self.agent / "state" / f"{router}.json").write_text(json.dumps(state), encoding="utf-8")
        if report is not None:
            d = self.agent / "reports" / router / "2026" / "11"
            d.mkdir(parents=True, exist_ok=True)
            seq = report["run"]["run_seq"]
            (d / f"{seq:06d}-{report['run']['run_id']}.json").write_text(json.dumps(report),
                                                                          encoding="utf-8")
        git(self.agent, "add", "-A")
        git(self.agent, "commit", "-q", "-m", msg, when=when)
        git(self.agent, "push", "-q", "origin", "main")


def make_cfg(tmp: Path, clone: Path, **timing_over) -> Config:
    return Config(
        path=tmp / "harness.yml", site_lab_clone=clone, site_lab_remote="origin",
        site_lab_branch="main", inventory=tmp / "inventory.ini",
        vault_password_file=tmp / "vault.pass", ca_path=tmp / "ca.crt",
        results_dir=tmp / "results",
        routers={"r2": RouterCfg("r2", "192.0.2.2", tmp / "vault-r2.yml"),
                 "r1": RouterCfg("r1", "192.0.2.1", tmp / "vault-r1.yml")},
        timing=TimingCfg(**timing_over),
    )


@pytest.fixture
def lab(tmp_path):
    repo = SiteRepo(tmp_path, state_doc())
    clock = FakeClock(T_START)
    ans = FakeAnsible()
    cfg = make_cfg(tmp_path, repo.clone)
    ctx = Context(cfg=cfg, ansible=ans, site=sitelab.SiteLab(repo.clone), clock=clock,
                  rng=random.Random(1), ssh=FakeSsh(ans), github=FakeGitHub())
    return repo, clock, ans, ctx


def agent_detects(repo, clock, ans, first_seen, commit_at=None, remediate=True, rule=RULE):
    """Zdarzenie: agent wykrywa naruszenie, naprawia (opcjonalnie) i publikuje raport + stan."""
    commit_at = commit_at or first_seen + timedelta(seconds=10)

    def fire():
        if remediate:
            ans.enabled = False
        repo.commit_state(state_doc(), commit_at, "agent(r2): raport policy-violation",
                          report=report_doc(first_seen, rule=rule))
    clock.at(commit_at, fire)


APPLY_AT = T_START + timedelta(seconds=100 - 60)   # siatka 10:00:00 + offset 100 s = 10:01:40


# ---------------------------------------------------------------- przebieg scenariusza
def test_pol003_pass(lab):
    repo, clock, ans, ctx = lab
    agent_detects(repo, clock, ans, first_seen=APPLY_AT + timedelta(seconds=212))
    res = run_scenario(ctx, POL003, offset_s=100)

    assert res["verdict"] == "pass", res["reasons"]
    assert ans.calls == ["gate", "read", "apply", "read", "read", "revert", "gate"]
    assert res["timing"]["t0"] == ts(APPLY_AT)
    assert res["timing"]["planned_offset_s"] == 100
    assert res["timing"]["t0_grid_offset_s"] == 100
    assert res["timing"]["t0_in_avoid_window"] is False
    assert res["metrics"] == {"mttd_s": 212.0, "budget_s": 420, "notify_s": 222.0,
                              "remediate_s": 214.0}
    assert res["report"]["posture"] == "policy-violation"
    assert res["report"]["actions"][0]["verification"] == "resolved"
    assert res["router_read"]["end"]["enabled"] is False
    assert res["site_lab"]["sha_before"] != res["site_lab"]["sha_after"]
    assert res["site_lab"]["report_commit"] == res["site_lab"]["sha_after"]
    assert res["versions"] == {"agent": "0.7.1", "policy_pin": "v0.7.1-lab",
                               "policy_deployed": "v0.7.1-lab"}
    assert res["target"] == {"router_id": "r2", "manifest_router_id": "r2",
                             "target_override": False, "profile": "ros6"}
    assert res["teardown"] == {"ok": True, "revert": "ok", "error": None, "reset": None,
                               "resolved": None,
                               "gate": {"ok": True, "export_diff": [], "objects_diff": []}}
    assert res["gate_before"]["ok"] is True
    assert res["preconditions"]["ok"] is True
    assert res["artifacts"][0]["status"] == "not-expected"   # auto-remediate: bez PR/issue


def test_pol003_target_override_records_profile(lab, tmp_path):
    repo, clock, ans, ctx = lab
    repo.commit_state(state_doc(router_id="r1"), T_START - timedelta(minutes=20), "r1", router="r1")
    first_seen = APPLY_AT + timedelta(seconds=200)

    def fire():
        ans.enabled = False
        repo.commit_state(state_doc(router_id="r1"), first_seen + timedelta(seconds=9), "agent(r1)",
                          report=report_doc(first_seen), router="r1")
    clock.at(first_seen + timedelta(seconds=9), fire)
    res = run_scenario(ctx, POL003, target="r1", offset_s=100)
    assert res["verdict"] == "pass", res["reasons"]
    assert res["target"] == {"router_id": "r1", "manifest_router_id": "r2",
                             "target_override": True, "profile": "ros7"}


def test_precondition_open_findings_invalid(tmp_path):
    st = state_doc(posture="site-drift",
                   open_findings=[{"rule": "local.ppp.secrets", "fingerprint": "sha256:x"}])
    repo = SiteRepo(tmp_path, st)
    ans = FakeAnsible()
    clock = FakeClock(T_START)
    ctx = Context(make_cfg(tmp_path, repo.clone), ans, sitelab.SiteLab(repo.clone),
                  clock, random.Random(1), ssh=FakeSsh(ans))
    res = run_scenario(ctx, POL003, offset_s=100)
    assert res["verdict"] == "invalid"
    assert clock.now() >= T_START + timedelta(seconds=900)   # czekał do precondition_wait_s
    assert any("open_findings" in r for r in res["reasons"])
    assert any("posture" in r for r in res["reasons"])
    assert ans.calls == []                       # nic nie dotknięto na routerze
    assert res["teardown"]["revert"] is None


def test_router_not_in_baseline_invalid(lab):
    repo, clock, ans, ctx = lab
    ans.enabled = True
    res = run_scenario(ctx, POL003, offset_s=100)
    assert res["verdict"] == "invalid"
    assert ans.calls == ["gate", "read"]


def test_timeout_without_report(lab):
    repo, clock, ans, ctx = lab
    res = run_scenario(ctx, POL003, offset_s=100)
    assert res["verdict"] == "timeout"
    assert clock.now() >= APPLY_AT + timedelta(seconds=420 + 120)
    assert ans.calls[-2:] == ["revert", "gate"]
    assert res["teardown"]["ok"] is True


def test_other_rule_is_not_detection(lab):
    repo, clock, ans, ctx = lab
    agent_detects(repo, clock, ans, APPLY_AT + timedelta(seconds=200),
                  rule="policy.services.telnet.disabled")
    assert run_scenario(ctx, POL003, offset_s=100)["verdict"] == "timeout"


def test_report_from_before_apply_is_ignored(lab):
    repo, clock, ans, ctx = lab
    # raport z findingiem sprzed apply (np. poprzednie powtórzenie), opublikowany po t0
    old = report_doc(APPLY_AT - timedelta(seconds=30))
    clock.at(APPLY_AT + timedelta(seconds=40),
             lambda: repo.commit_state(state_doc(), APPLY_AT + timedelta(seconds=40), "old",
                                       report=old))
    assert run_scenario(ctx, POL003, offset_s=100)["verdict"] == "timeout"


def test_end_state_not_baseline_fails(lab):
    repo, clock, ans, ctx = lab
    agent_detects(repo, clock, ans, APPLY_AT + timedelta(seconds=212), remediate=False)
    res = run_scenario(ctx, POL003, offset_s=100)
    assert res["verdict"] == "fail"
    assert any("end_state=baseline" in r for r in res["reasons"])
    assert res["teardown"]["revert"] == "ok"


def test_mttd_over_budget_fails(lab):
    repo, clock, ans, ctx = lab
    agent_detects(repo, clock, ans, APPLY_AT + timedelta(seconds=450))  # w oknie grace (120 s)
    res = run_scenario(ctx, POL003, offset_s=100)
    assert res["verdict"] == "fail"
    assert any("MTTD 450.0 s > budżet 420 s" in r for r in res["reasons"])


def test_apply_not_confirmed_is_error(lab):
    repo, clock, ans, ctx = lab
    ans.apply_effect = False
    res = run_scenario(ctx, POL003, offset_s=100)
    assert res["verdict"] == "error"
    assert "niepotwierdzony" in res["reasons"][0]
    assert ans.calls[-2:] == ["revert", "gate"]   # teardown także po błędzie


def test_revert_failure_keeps_verdict(lab):
    repo, clock, ans, ctx = lab
    ans.fail_tags = {"revert"}
    agent_detects(repo, clock, ans, APPLY_AT + timedelta(seconds=212))
    res = run_scenario(ctx, POL003, offset_s=100)
    assert res["verdict"] == "pass"               # werdykt agenta bez zmian (decyzja 2026-11-14)
    assert res["teardown"]["ok"] is False and res["teardown"]["revert"] == "error"
    assert res["teardown"]["gate"] is None        # bramki po nieudanym revert nie ma sensu robić


def test_unknown_target_is_usage_error(lab):
    repo, clock, ans, ctx = lab
    with pytest.raises(UsageError):
        run_scenario(ctx, POL003, target="r9", offset_s=100)


def test_result_written_as_json(lab, tmp_path):
    repo, clock, ans, ctx = lab
    agent_detects(repo, clock, ans, APPLY_AT + timedelta(seconds=212))
    res = run_scenario(ctx, POL003, offset_s=100)
    p = results.write(res, tmp_path / "out")
    assert p.name.endswith("-POL-003-r2.json")
    doc = json.loads(p.read_text(encoding="utf-8"))
    assert doc["verdict"] == "pass" and doc["manifest"]["path"] == "scenarios/policy/policy-socks-enabled.yml"
    assert not list((tmp_path / "out").glob("*.tmp"))


# ---------------------------------------------------------------- timing
def test_grid_offset_and_window():
    cfg = TimingCfg()
    t = datetime(2026, 11, 13, 10, 5, 12, tzinfo=timezone.utc)
    assert timing.grid_offset(t) == 12
    assert timing.in_avoid_window(t, cfg)
    assert not timing.in_avoid_window(t + timedelta(seconds=20), cfg)


def test_plan_apply_never_in_avoid_window_or_margin():
    cfg = TimingCfg()
    rng = random.Random(7)
    now = T_START
    for i in range(500):
        now += timedelta(seconds=rng.uniform(0, 400))
        t, off = timing.plan_apply(now, cfg, rng)
        assert t > now and (t - now).total_seconds() <= cfg.cycle_s
        assert cfg.avoid_window_s <= timing.grid_offset(t) <= cfg.cycle_s - cfg.apply_margin_s
        assert abs(timing.grid_offset(t) - off) < 1e-6


def test_plan_apply_fixed_offset_next_cycle():
    cfg = TimingCfg()
    now = datetime(2026, 11, 13, 10, 3, 0, tzinfo=timezone.utc)   # offset 180 s
    t, off = timing.plan_apply(now, cfg, random.Random(), fixed_offset_s=100)
    assert t == datetime(2026, 11, 13, 10, 6, 40, tzinfo=timezone.utc) and off == 100
    with pytest.raises(UsageError):
        timing.plan_apply(now, cfg, random.Random(), fixed_offset_s=10)
    with pytest.raises(UsageError):
        timing.plan_apply(now, cfg, random.Random(), fixed_offset_s=250)


def test_parse_ts_and_iso_roundtrip():
    t = timing.parse_ts("2026-11-13T13:50:18.144Z")
    assert t.tzinfo is not None and timing.iso(t) == "2026-11-13T13:50:18.144Z"


# ---------------------------------------------------------------- site-lab
def test_reports_since_order_and_commit_time(tmp_path):
    repo = SiteRepo(tmp_path, state_doc())
    s = sitelab.SiteLab(repo.clone)
    base = s.fetch()
    t1, t2 = T_START + timedelta(minutes=5), T_START + timedelta(minutes=10)
    repo.commit_state(state_doc(), t1, "a", report=report_doc(t1, seq=6))
    repo.commit_state(state_doc(last_run={"run_id": "x", "run_seq": 99, "finished_at": ts(t1)}),
                      t1 + timedelta(minutes=2), "stan bez raportu")
    repo.commit_state(state_doc(), t2, "b", report=report_doc(t2, seq=7))
    head = s.fetch()
    refs = s.reports_since(base, head, "r2")
    assert [r.path.rsplit("/", 1)[1][:6] for r in refs] == ["000006", "000007"]
    assert refs[0].committed_at == t1 and refs[1].committed_at == t2
    assert s.reports_since(base, head, "r1") == []
    det = s.find_detection(base, head, "r2", RULE, t1 + timedelta(seconds=1))
    assert det.ref == refs[1]


def test_harness_does_not_touch_clone_worktree(tmp_path):
    repo = SiteRepo(tmp_path, state_doc())
    s = sitelab.SiteLab(repo.clone)
    before = git(repo.clone, "rev-parse", "HEAD")
    repo.commit_state(state_doc(), T_START, "x", report=report_doc(T_START))
    s.fetch()
    assert git(repo.clone, "rev-parse", "HEAD") == before
    assert git(repo.clone, "status", "--porcelain") == ""


@pytest.mark.parametrize("over,expect,needle", [
    ({"open_findings": [{"rule": "r"}]}, {}, "open_findings"),
    ({"posture": "policy-violation"}, {}, "posture"),
    ({"policy": {"universal_version": "v0.7.0-lab"}}, {}, "pin site.yml"),
    ({"coverage": "partial"}, {"coverage": "full"}, "coverage"),
])
def test_preconditions(over, expect, needle):
    errs = sitelab.preconditions(SITE_YML, state_doc(**over), expect)
    assert len(errs) == 1 and needle in errs[0]


def test_preconditions_ok_and_partial_coverage_allowed_without_expect():
    assert sitelab.preconditions(SITE_YML, state_doc(), {"coverage": "full"}) == []
    assert sitelab.preconditions(SITE_YML, state_doc(coverage="partial"), {}) == []


def test_router_profile():
    assert sitelab.router_profile(SITE_YML, "r1") == "ros7"
    with pytest.raises(HarnessError):
        sitelab.router_profile(SITE_YML, "r9")


# ---------------------------------------------------------------- probes
def test_probe_bool_normalization():
    row = probes.select([{"enabled": "yes"}], {})
    assert probes.matches(row, {"enabled": True}) == []
    assert probes.matches({"enabled": "false"}, {"enabled": True})
    with pytest.raises(HarnessError):
        probes.select([{"name": "a"}, {"name": "a"}], {"name": "a"})
    with pytest.raises(HarnessError):
        probes.get("XXX-999")


# ---------------------------------------------------------------- Ansible (atrapa ansible-playbook)
FAKE_PLAYBOOK = """#!{py}
import json, sys
from pathlib import Path
argv = sys.argv[1:]
Path({log!r}).open("a").write(json.dumps(argv) + "\\n")
evars = [json.loads(argv[i + 1]) for i, a in enumerate(argv) if a == "-e" and not argv[i + 1].startswith("@")]
out = evars[0].get("read_out")
if out:
    Path(out).write_text(json.dumps({{p: [{{"enabled": False, "port": 1080}}] for p in evars[0]["read_paths"]}}))
sys.exit({code})
"""


def _fake_bin(tmp_path, code=0):
    log = tmp_path / "calls.log"
    p = tmp_path / "ansible-playbook"
    p.write_text(FAKE_PLAYBOOK.format(py=sys.executable, log=str(log), code=code), encoding="utf-8")
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return p, log


def test_ansible_read_and_command_line(tmp_path):
    binp, log = _fake_bin(tmp_path)
    cfg = make_cfg(tmp_path, tmp_path)
    cfg = Config(**{**cfg.__dict__, "ansible_playbook": str(binp)})
    a = Ansible(cfg)
    rows = a.read(cfg.router("r2"), "ip socks")
    assert rows == [{"enabled": False, "port": 1080}]
    a.playbook("playbooks/policy/socks-enabled.yml", cfg.router("r2"), "apply")
    calls = [json.loads(ln) for ln in log.read_text().splitlines()]
    read_argv, apply_argv = calls
    assert read_argv[-1] == "playbooks/common/read.yml" and "--tags" not in read_argv
    read_vars = json.loads(read_argv[read_argv.index("-e", read_argv.index("-e") + 1) + 1])
    assert read_vars["read_paths"] == ["ip socks"] and read_vars["read_raw"] is False
    assert apply_argv[-3:] == ["--tags", "apply", "playbooks/policy/socks-enabled.yml"]
    assert apply_argv[apply_argv.index("--vault-password-file") + 1] == str(tmp_path / "vault.pass")
    assert f"@{tmp_path / 'vault-r2.yml'}" in apply_argv
    evars = json.loads(apply_argv[apply_argv.index("-e", apply_argv.index("-e") + 1) + 1])
    assert evars == {"router_id": "r2", "router_host": "192.0.2.2", "router_api_port": 8729,
                     "router_ca_path": str(tmp_path / "ca.crt")}
    assert not any("pw" in x or "password=" in x for x in apply_argv[:-1]
                   if x not in ("--vault-password-file",))


def test_ansible_failure_is_harness_error(tmp_path):
    binp, _ = _fake_bin(tmp_path, code=2)
    cfg = make_cfg(tmp_path, tmp_path)
    a = Ansible(Config(**{**cfg.__dict__, "ansible_playbook": str(binp)}))
    with pytest.raises(HarnessError, match="kod 2"):
        a.playbook("playbooks/policy/socks-enabled.yml", cfg.router("r2"), "apply")
    with pytest.raises(HarnessError, match="brak playbooka"):
        a.playbook("playbooks/policy/nope.yml", cfg.router("r2"), "apply")


SCENARIO_PLAYBOOKS = ["policy/socks-enabled.yml", "benign/add-allowed-firewall-comment.yml",
                      "site/ppp-secret-add.yml", "policy/proxy-enabled.yml",
                      "policy/api-plain-enabled.yml", "policy/winbox-public.yml", "site/user-add.yml"]


@pytest.mark.parametrize("pb", SCENARIO_PLAYBOOKS)
def test_playbooks_have_apply_and_revert_tags(pb):
    doc = yaml.safe_load((REPO_ROOT / "playbooks" / pb).read_text(encoding="utf-8"))
    tags = [set(t.get("tags", [])) for t in doc[0]["tasks"]]
    assert {"apply"} in tags and {"revert", "never"} in tags     # D-D
    assert all(t <= {"apply"} or {"revert", "never"} <= t for t in tags)
    for t in doc[0]["tasks"]:
        assert t.get("no_log") in ("{{ harness_no_log }}", True)


def test_scenario_manifests_point_to_existing_playbooks_and_probes():
    for mp in sorted((REPO_ROOT / "scenarios").glob("*/*.yml")):
        m = yaml.safe_load(mp.read_text(encoding="utf-8"))
        if m["class"] in ("dynamic", "control") or m["apply"].get("none"):
            continue                                   # dynamika: iteracja 4–5; BEN-001 bez odczytu
        assert (REPO_ROOT / m["apply"]["playbook"]).is_file(), m["id"]
        probe = probes.get(m["id"])
        assert m["apply"]["playbook"].removeprefix("playbooks/") in SCENARIO_PLAYBOOKS, m["id"]
        assert probe.applied is not None, m["id"]


def test_probe_constants_match_playbooks():
    ben = (REPO_ROOT / "playbooks/benign/add-allowed-firewall-comment.yml").read_text(encoding="utf-8")
    assert f'"{probes.BEN002_COMMENT_BASELINE}"' in ben and f'"{probes.BEN002_COMMENT_APPLIED}"' in ben
    site = (REPO_ROOT / "playbooks/site/ppp-secret-add.yml").read_text(encoding="utf-8")
    assert f"site007_name: {probes.SITE007_SECRET}" in site
    tasks = yaml.safe_load(site)[0]["tasks"]
    with_pw = [t for t in tasks if "password=" in json.dumps(t)]
    assert with_pw and all(t["no_log"] is True for t in with_pw)   # zadanie z hasłem zawsze no_log
    user = (REPO_ROOT / "playbooks/site/user-add.yml").read_text(encoding="utf-8")
    assert f"site008_name: {probes.SITE008_USER}" in user
    with_pw = [t for t in yaml.safe_load(user)[0]["tasks"] if "password=" in json.dumps(t)]
    assert with_pw and all(t["no_log"] is True for t in with_pw)
    winbox = (REPO_ROOT / "playbooks/policy/winbox-public.yml").read_text(encoding="utf-8")
    assert "probe_pre.address" in winbox          # revert: adres sprzed apply (zależny od routera)


# ---------------------------------------------------------------- konfiguracja
def test_example_config_loads():
    cfg = config_mod.load(REPO_ROOT / "harness" / "harness.example.yml")
    assert cfg.router("r2").mgmt_address == "192.0.2.2"
    assert cfg.router("r1").mgmt_return_timeout_s == 180
    assert set(cfg.router("r2").upload) == {"bl-api.crt", "bl-api.key", "ansible_rsa.pub",
                                            "monitor_rsa.pub"}
    assert cfg.build_dir is not None and cfg.ssh_known_hosts is not None
    assert cfg.timing.reset_offset_s == 40
    assert cfg.router("r2").vault_file.is_absolute()
    assert cfg.timing.cycle_s == 300
    with pytest.raises(UsageError):
        cfg.router("r9")


@pytest.mark.parametrize("mutate,needle", [
    (lambda d: d.pop("site_lab"), "site_lab"),
    (lambda d: d["routers"]["r2"].pop("vault_file"), "routers.r2.vault_file"),
    (lambda d: d["timing"].update(avoid_window_s=400), "avoid_window_s"),
    (lambda d: d["timing"].update(bogus=1), "nieznane"),
    (lambda d: d["routers"]["r2"]["upload"].update({"baseline.rsc": "/path/x"}), "renderuje"),
    (lambda d: d["routers"]["r2"].update(upload=["a"]), "upload musi"),
])
def test_config_errors(tmp_path, mutate, needle):
    doc = yaml.safe_load((REPO_ROOT / "harness" / "harness.example.yml").read_text(encoding="utf-8"))
    mutate(doc)
    p = tmp_path / "harness.yml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    with pytest.raises(UsageError, match=needle):
        config_mod.load(p)


def test_config_rejects_duplicate_keys(tmp_path):
    text = (REPO_ROOT / "harness" / "harness.example.yml").read_text(encoding="utf-8")
    text += "routers:\n  r1:\n    mgmt_address: 192.0.2.1\n    vault_file: /path/v.yml\n"
    p = tmp_path / "harness.yml"
    p.write_text(text, encoding="utf-8")
    with pytest.raises(UsageError, match="zduplikowany klucz 'routers'"):
        config_mod.load(p)


# ---------------------------------------------------------------- CLI
def _cli(lab, argv, tmp_path):
    repo, clock, ans, ctx = lab
    cfg_path = tmp_path / "harness.yml"
    cfg_path.write_text((REPO_ROOT / "harness" / "harness.example.yml").read_text(), encoding="utf-8")
    return cli.main(["--config", str(cfg_path), *argv], context_factory=lambda cfg, seed: ctx)


def test_cli_pass_exit_0(lab, tmp_path, capsys):
    repo, clock, ans, ctx = lab
    agent_detects(repo, clock, ans, APPLY_AT + timedelta(seconds=212))
    assert _cli(lab, ["run", str(POL003), "--offset", "100"], tmp_path) == 0
    out = capsys.readouterr().out
    assert "POL-003 r2: pass mttd=212.0s" in out
    assert len(list(ctx.cfg.results_dir.glob("*.json"))) == 1


def test_cli_timeout_exit_1(lab, tmp_path):
    assert _cli(lab, ["run", str(POL003), "--offset", "100"], tmp_path) == 1


def test_cli_invalid_exit_3_stops_repeats(lab, tmp_path):
    repo, clock, ans, ctx = lab
    ans.enabled = True
    assert _cli(lab, ["run", str(POL003), "--offset", "100", "--repeat", "3"], tmp_path) == 3
    assert ans.calls == ["gate", "read"]
    assert len(list(ctx.cfg.results_dir.glob("*.json"))) == 1


def test_cli_bad_manifest_exit_2(lab, tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("schema_version: '1.0.0'\nid: X\n", encoding="utf-8")
    assert _cli(lab, ["run", str(bad)], tmp_path) == 2


def test_cli_missing_config_exit_2(tmp_path):
    assert cli.main(["--config", str(tmp_path / "nope.yml"), "run", str(POL003)]) == 2


def test_cli_bad_offset_exit_2_before_router(lab, tmp_path):
    repo, clock, ans, ctx = lab
    assert _cli(lab, ["run", str(POL003), "--offset", "5"], tmp_path) == 2
    assert ans.calls == []


def test_harness_does_not_import_agent():
    for p in (REPO_ROOT / "harness").glob("*.py"):
        src = p.read_text(encoding="utf-8")
        assert "from agent" not in src and "import agent" not in src, p.name


def test_result_records_seed_and_repeat(lab, tmp_path):
    repo, clock, ans, ctx = lab
    ctx.seed = 1
    agent_detects(repo, clock, ans, APPLY_AT + timedelta(seconds=212))
    assert _cli(lab, ["run", str(POL003), "--offset", "100"], tmp_path) == 0
    doc = json.loads(next(ctx.cfg.results_dir.glob("*.json")).read_text(encoding="utf-8"))
    assert doc["timing"]["rng_seed"] == 1
    assert doc["repeat"] == {"index": 1, "of": 1}


def test_build_context_always_has_seed(tmp_path):
    cfg = config_mod.load(REPO_ROOT / "harness" / "harness.example.yml")
    assert isinstance(cli.build_context(cfg, None).seed, int)
    a, b = cli.build_context(cfg, 42), cli.build_context(cfg, 42)
    assert a.seed == 42 and a.rng.random() == b.rng.random()


def test_harness_commit_dirty_on_untracked_code(monkeypatch, tmp_path):
    repo = tmp_path / "sg"
    (repo / "harness").mkdir(parents=True)
    (repo / "README").write_text("x")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    git(repo, "add", "-A"); git(repo, "commit", "-q", "-m", "init")
    monkeypatch.setattr(results, "REPO_ROOT", repo)
    assert not results.harness_commit().endswith("-dirty")
    (repo / "README").write_text("y")                    # poza CODE_PATHS
    assert not results.harness_commit().endswith("-dirty")
    (repo / "harness" / "new.py").write_text("")         # nieśledzony kod harnessu
    assert results.harness_commit().endswith("-dirty")


def test_example_and_defaults_have_no_local_paths():
    """Wzorzec i wartości domyślne nie mogą zawierać ścieżek ani adresów konkretnej instalacji."""
    import re
    for p in [*(REPO_ROOT / "harness").glob("*.py"), REPO_ROOT / "harness" / "harness.example.yml",
              REPO_ROOT / "requirements-harness.txt", *(REPO_ROOT / "playbooks").rglob("*.yml")]:
        src = p.read_text(encoding="utf-8")
        assert not re.search(r"~/|/home/|10\.\d+\.\d+\.\d+|192\.168\.", src), p.name
    assert config_mod.DEFAULT_PATH == REPO_ROOT / "harness" / "harness.yml"


# ================================================================ iteracja 2
# ---------------------------------------------------------------- bramka (H5)
def test_export_body_skips_only_header():
    text = "# date\r\n# software id =\r\n#\r\n/a b\r\n#error exporting /x\r\n/c\r\n\r\n"
    assert gate.export_body(text) == ["/a b", "#error exporting /x", "/c"]
    with pytest.raises(HarnessError):
        gate.export_body("# h\njunk\n/a\n")


def test_diff_export_ignores_header_and_crlf_but_not_error_lines():
    actual = "# inna data\r\n# software id =\r\n#\r\n" + EXPORT_PATTERN.split("\n", 3)[3].replace("\n", "\r\n")
    assert gate.diff_export(actual, EXPORT_PATTERN) == []
    new_err = actual + "#error exporting /interface bridge calea\r\n"
    assert gate.diff_export(new_err, EXPORT_PATTERN) == ["@@ -3,0 +4 @@",       # numeracja treści
                                                         "+#error exporting /interface bridge calea"]
    changed = actual.replace("enabled=no", "enabled=yes")
    d = gate.diff_export(changed, EXPORT_PATTERN)
    assert "-/ip socks set enabled=no" in d and "+/ip socks set enabled=yes" in d


def test_objects_projection_roundtrip_and_diff():
    proj = gate.project(GATE_READS)
    assert proj["user"][0] == {"name": "ansible", "group": "bl-ansible", "address": "192.0.2.0/24",
                               "disabled": "false"}               # bez last-logged-in
    assert proj["user"][1]["disabled"] == "false"                 # "no" → "false"
    assert "expires-after" not in proj["certificate"][0] and "size" not in proj["file"][0]
    ref = gate.load_objects_ref(gate.dump_objects("r2", proj, T_START), "r2")
    assert gate.diff_objects(proj, ref) == []
    extra = copy.deepcopy(GATE_READS)
    extra["user ssh-keys"].append({"user": "admin", "key-owner": "x", "bits": 2048})
    del extra["file"][1]
    d = gate.diff_objects(gate.project(extra), ref)
    assert any(x.startswith("+ user ssh-keys:") and "admin" in x for x in d)
    assert any(x.startswith("- file:") and "flash/pub" in x for x in d)


@pytest.mark.parametrize("text,needle", [
    ("schema_version: '1'\nrouter_id: r1\nobjects: {}\n", "router_id"),
    ("schema_version: '1'\nrouter_id: r2\nobjects: {user: []}\n", "brak menu"),
    ("[", "błędny YAML"),
])
def test_objects_ref_validation(text, needle):
    with pytest.raises(HarnessError, match=needle):
        gate.load_objects_ref(text, "r2")


def test_gate_before_apply_mismatch_is_invalid(lab):
    repo, clock, ans, ctx = lab
    ans.extra_user = True
    res = run_scenario(ctx, POL003, offset_s=100)
    assert res["verdict"] == "invalid" and "przed apply" in res["reasons"][0]
    assert res["gate_before"]["objects_diff"] == [
        '+ user: {"disabled": "false", "group": "full", "name": "intruder"}']
    assert ans.calls == ["gate"]                  # router nietknięty


def test_gate_export_mismatch_before_apply(lab):
    repo, clock, ans, ctx = lab
    ans.export_extra = ["/ip service set telnet disabled=no"]
    res = run_scenario(ctx, POL003, offset_s=100)
    assert res["verdict"] == "invalid"
    assert "+/ip service set telnet disabled=no" in res["gate_before"]["export_diff"]


def test_teardown_gate_mismatch_keeps_verdict_and_cli_aborts(lab, tmp_path, capsys):
    repo, clock, ans, ctx = lab
    ans.leave_after_revert = True
    agent_detects(repo, clock, ans, APPLY_AT + timedelta(seconds=212))
    assert _cli(lab, ["run", str(POL003), "--offset", "100", "--repeat", "2"], tmp_path) == 3
    doc = json.loads(next(ctx.cfg.results_dir.glob("*.json")).read_text(encoding="utf-8"))
    assert doc["verdict"] == "pass"
    assert doc["teardown"]["ok"] is False and doc["teardown"]["revert"] == "ok"
    assert "po revert" in doc["teardown"]["error"]
    assert doc["teardown"]["gate"]["objects_diff"]
    assert "TEARDOWN-NIEZGODNY" in capsys.readouterr().out
    assert len(list(ctx.cfg.results_dir.glob("*.json"))) == 1      # drugie powtórzenie przerwane


def test_missing_gate_reference_is_error(lab):
    repo, clock, ans, ctx = lab
    (repo.agent / "routers" / "r2" / "gate-objects.yml").unlink()
    repo.commit_state(state_doc(), T_START - timedelta(minutes=10), "bez wzorca")
    res = run_scenario(ctx, POL003, offset_s=100)
    assert res["verdict"] == "error" and "--dump-objects" in res["reasons"][0]
    assert "apply" not in ans.calls


# ---------------------------------------------------------------- H8 z czekaniem
def test_preconditions_wait_until_agent_resolves(lab):
    repo, clock, ans, ctx = lab
    repo.commit_state(state_doc(posture="site-drift", open_findings=[{"rule": "local.ppp.secrets"}]),
                      T_START - timedelta(minutes=5), "drift")
    clock.at(T_START + timedelta(seconds=200),
             lambda: repo.commit_state(state_doc(), T_START + timedelta(seconds=200), "resolved"))
    first_seen = T_START + timedelta(seconds=200 + 400)

    def fire():
        ans.enabled = False
        repo.commit_state(state_doc(), first_seen + timedelta(seconds=10), "raport",
                          report=report_doc(first_seen))
    clock.at(first_seen + timedelta(seconds=10), fire)
    res = run_scenario(ctx, POL003, offset_s=100)
    assert res["verdict"] == "pass", res["reasons"]
    assert timing.parse_ts(res["timing"]["t0"]) > T_START + timedelta(seconds=200)


# ---------------------------------------------------------------- H10 (BEN-002)
HB_AT = datetime(2026, 11, 13, 9, 51, 15, tzinfo=timezone.utc)    # ostatni heartbeat
HB_NEXT = datetime(2026, 11, 13, 10, 25, 20, tzinfo=timezone.utc)  # przewidywany (siatka + 20 s)
BEN_APPLY = datetime(2026, 11, 13, 10, 11, 40, tzinfo=timezone.utc)


def h10_state(seq, at):
    return state_doc(last_run={"run_id": f"R{seq}", "run_seq": seq, "finished_at": ts(at)},
                     heartbeat={"at": ts(at), "interval_s": 1800})


@pytest.fixture
def h10(tmp_path):
    repo = SiteRepo(tmp_path, h10_state(100, HB_AT))
    clock = FakeClock(T_START)
    ans = FakeAnsible()
    ctx = Context(make_cfg(tmp_path, repo.clone), ans, sitelab.SiteLab(repo.clone), clock,
                  random.Random(1), ssh=FakeSsh(ans), github=FakeGitHub())
    return repo, clock, ans, ctx


def heartbeat_at(repo, clock, when, seq, report=None):
    clock.at(when, lambda: repo.commit_state(h10_state(seq, when - timedelta(seconds=5)), when,
                                             f"heartbeat {seq}", report=report))


def test_predict_heartbeat_and_plan_h10():
    assert timing.predict_heartbeat(HB_AT, 1800) == HB_NEXT
    cfg = TimingCfg()
    t, off, hb = timing.plan_h10(T_START, HB_AT, 1800, cfg, random.Random(), fixed_offset_s=100)
    assert (t, off, hb) == (BEN_APPLY, 100, HB_NEXT)
    lead = (hb - t).total_seconds()
    assert 570 <= lead <= 870                     # ok. 12 min przed heartbeatem
    late = HB_NEXT - timedelta(minutes=5)          # za późno → następny heartbeat
    t2, _, hb2 = timing.plan_h10(late, HB_AT, 1800, cfg, random.Random(), fixed_offset_s=100)
    assert hb2 == HB_NEXT + timedelta(seconds=1800) and t2 > late


def test_predict_heartbeat_borderline_takes_earlier_cycle():
    # lab 2026-11-14 r2: heartbeat 20:00:17.073, kolejny commit 20:30:20 (nie 20:35:20)
    prev = datetime(2026, 11, 14, 20, 0, 17, 73000, tzinfo=timezone.utc)
    assert timing.predict_heartbeat(prev, 1800) == datetime(2026, 11, 14, 20, 30, 20,
                                                            tzinfo=timezone.utc)


def test_plan_h10_random_lead_bounds():
    cfg = TimingCfg()
    rng = random.Random(3)
    for i in range(200):
        now = T_START + timedelta(seconds=rng.uniform(0, 1800))
        t, off, hb = timing.plan_h10(now, HB_AT, 1800, cfg, rng)
        assert t > now and not timing.in_avoid_window(t, cfg)
        assert 480 <= (hb - t).total_seconds() <= 990


def test_ben002_pass_on_heartbeat_window(h10):
    repo, clock, ans, ctx = h10
    heartbeat_at(repo, clock, HB_NEXT, 105)
    res = run_scenario(ctx, BEN002, offset_s=100)
    assert res["verdict"] == "pass", res["reasons"]
    assert res["timing"]["t0"] == ts(BEN_APPLY)
    assert res["timing"]["predicted_heartbeat_at"] == ts(HB_NEXT)
    assert res["window"]["base_run_seq"] == 100 and res["window"]["closing_run_seq"] == 105
    assert res["window"]["reports"] == []
    assert res["metrics"] == {"window_s": (HB_NEXT - BEN_APPLY).total_seconds()}
    assert ans.icmp_comment == probes.BEN002_COMMENT_BASELINE          # revert
    assert ans.calls == ["gate", "read", "apply", "read", "revert", "gate"]
    assert res["artifacts"] is None


def test_ben002_window_needs_run_seq_plus_two(h10):
    repo, clock, ans, ctx = h10
    heartbeat_at(repo, clock, BEN_APPLY + timedelta(seconds=200), 101)   # +1: okno trwa
    heartbeat_at(repo, clock, HB_NEXT + timedelta(minutes=5), 107)
    res = run_scenario(ctx, BEN002, offset_s=100)
    assert res["verdict"] == "pass" and res["window"]["closing_run_seq"] == 107


def test_ben002_window_needs_two_cycles_after_t0(h10):
    # stan bazowy sprzed wielu cykli: run_seq +6 już w pierwszym cyklu po t0 nie zamyka okna
    repo, clock, ans, ctx = h10
    heartbeat_at(repo, clock, BEN_APPLY + timedelta(seconds=230), 106)   # cykl 10:15 = 1. po t0
    heartbeat_at(repo, clock, HB_NEXT, 107)
    res = run_scenario(ctx, BEN002, offset_s=100)
    assert res["verdict"] == "pass", res["reasons"]
    assert res["window"]["closing_run_seq"] == 107
    assert res["window"]["closing_cycles_after_t0"] == 3


def test_cycles_after():
    t0 = datetime(2026, 11, 14, 20, 21, 56, tzinfo=timezone.utc)
    fin = lambda h, m, sec: datetime(2026, 11, 14, h, m, sec, tzinfo=timezone.utc)  # noqa: E731
    assert scenario.cycles_after(t0, fin(20, 25, 17), 300) == 1
    assert scenario.cycles_after(t0, fin(20, 30, 17), 300) == 2


def test_precondition_wait_logs_only_changes(tmp_path, caplog):
    st = state_doc(posture="site-drift", open_findings=[{"rule": "local.ppp.secrets"}])
    repo = SiteRepo(tmp_path, st)
    ans = FakeAnsible()
    clock = FakeClock(T_START)
    ctx = Context(make_cfg(tmp_path, repo.clone), ans, sitelab.SiteLab(repo.clone),
                  clock, random.Random(1), ssh=FakeSsh(ans))
    clock.at(T_START + timedelta(seconds=200),
             lambda: repo.commit_state(state_doc(), T_START + timedelta(seconds=200), "resolved"))
    with caplog.at_level(logging.INFO, logger="harness"):
        run_scenario(ctx, POL003, offset_s=100)
    msgs = [r.getMessage() for r in caplog.records]
    assert sum("niespełnione" in m for m in msgs) == 1
    assert any(m.startswith("warunki wstępne spełnione po") for m in msgs)


def test_ben002_new_finding_in_window_fails(h10):
    repo, clock, ans, ctx = h10
    rep = report_doc(BEN_APPLY + timedelta(seconds=210), rule="local.drift.firewall-filter", seq=103)
    clock.at(BEN_APPLY + timedelta(seconds=220),
             lambda: repo.commit_state(h10_state(103, BEN_APPLY + timedelta(seconds=215)),
                                       BEN_APPLY + timedelta(seconds=220), "drift", report=rep))
    heartbeat_at(repo, clock, HB_NEXT, 105)
    res = run_scenario(ctx, BEN002, offset_s=100)
    assert res["verdict"] == "fail"
    assert any("nowego findingu" in r for r in res["reasons"])
    assert len(res["window"]["reports"]) == 1


def test_ben002_timeout_without_state_commit(h10):
    repo, clock, ans, ctx = h10
    res = run_scenario(ctx, BEN002, offset_s=100)
    assert res["verdict"] == "timeout" and "okno H10" in res["reasons"][0]
    assert clock.now() >= BEN_APPLY + timedelta(seconds=2700)
    assert res["teardown"]["ok"] is True


# ---------------------------------------------------------------- SITE-007 + artefakty (H9)
def site_report(first_seen, seq=6, action="open-pr"):
    rep = report_doc(first_seen, rule="local.ppp.secrets", seq=seq)
    rep["findings"][0].update(rule_source="local")
    rep["verdict"]["posture"] = "site-drift"
    rep["actions"][0].update(type=action, status="succeeded", verification=None)
    return rep


def agent_drift(repo, clock, first_seen, action="open-pr"):
    rep = site_report(first_seen, action=action)
    commit_at = first_seen + timedelta(seconds=10)
    st = state_doc(posture="site-drift", open_findings=[{"rule": "local.ppp.secrets"}])
    clock.at(commit_at, lambda: repo.commit_state(st, commit_at, "agent(r2): site-drift", report=rep))
    return rep


def test_site007_pass_with_pr(lab):
    repo, clock, ans, ctx = lab
    rep = agent_drift(repo, clock, APPLY_AT + timedelta(seconds=212))
    branch = f"agent/r2/{rep['run']['run_id']}"
    ctx.github.prs[branch] = [{"number": 41, "url": "u", "state": "OPEN", "headRefName": branch}]
    res = run_scenario(ctx, SITE007, offset_s=100)
    assert res["verdict"] == "pass", res["reasons"]
    assert res["router_read"]["pre"] is None                       # baseline: brak sekretu
    assert res["router_read"]["end"]["name"] == probes.SITE007_SECRET   # end_state: unchanged
    assert ans.ppp == []                                            # revert usunął sekret
    art = res["artifacts"][0]
    assert art["status"] == "ok" and art["branch"] == branch and art["prs"][0]["number"] == 41
    assert ctx.github.closed == []                                  # domyślnie bez zamykania


def test_site007_artifact_missing_keeps_verdict(lab):
    repo, clock, ans, ctx = lab
    agent_drift(repo, clock, APPLY_AT + timedelta(seconds=212))
    res = run_scenario(ctx, SITE007, offset_s=100)
    assert res["verdict"] == "pass"
    assert res["artifacts"][0]["status"] == "artifact_missing"


def test_close_artifacts_only_from_this_run(lab):
    repo, clock, ans, ctx = lab
    rep = agent_drift(repo, clock, APPLY_AT + timedelta(seconds=212), action="alert")
    path = f"reports/r2/2026/11/{rep['run']['run_seq']:06d}-{rep['run']['run_id']}.json"
    ctx.github.issues = [{"number": 7, "url": "u", "state": "OPEN", "body": f"raport: {path}"},
                         {"number": 8, "url": "u", "state": "OPEN", "body": "inny raport"}]
    res = run_scenario(ctx, SITE007, offset_s=100, close_artifacts=True, run_id="h-test")
    assert res["verdict"] == "pass"
    assert res["artifacts"][0]["closed"] == ["issue#7"]
    assert ctx.github.closed == [("issue", 7, "harness h-test")]


def test_artifacts_expected_counts():
    rep = {"run": {"run_id": "R"}, "actions": [
        {"type": "alert", "status": "succeeded"}, {"type": "alert", "status": "failed"},
        {"type": "open-pr", "status": "succeeded"}, {"type": "auto-remediate", "status": "succeeded"}]}
    assert artifacts.expected(rep) == {"pr": True, "issues": 1}


def test_close_skips_closed_and_foreign_branch():
    gh = FakeGitHub()
    art = {"branch": "agent/r2/R", "prs": [
        {"number": 1, "state": "OPEN", "headRefName": "agent/r2/R"},
        {"number": 2, "state": "MERGED", "headRefName": "agent/r2/R"},
        {"number": 3, "state": "OPEN", "headRefName": "agent/r2/X"}],
        "issues": [{"number": 9, "state": "CLOSED"}]}
    assert artifacts.close(gh, art, "h1") == ["pr#1"]


# ---------------------------------------------------------------- SSH / gh (wiersz poleceń)
def test_ssh_export_command_and_errors(tmp_path):
    cfg = Config(**{**make_cfg(tmp_path, tmp_path).__dict__, "ssh_config": tmp_path / "ssh_config"})
    seen = []

    def runner(cmd, **kw):
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="/x\n", stderr="")
    s = Ssh(cfg, runner=runner)
    assert s.export(cfg.router("r2")) == "/x\n"
    assert seen[0] == ["ssh", "-F", str(tmp_path / "ssh_config"), "-l", "ansible", "-o",
                       "BatchMode=yes", "192.0.2.2", "/export terse hide-sensitive"]
    bad = Ssh(cfg, runner=lambda cmd, **kw: subprocess.CompletedProcess(cmd, 255, "", "denied"))
    with pytest.raises(HarnessError, match="kod 255"):
        bad.export(cfg.router("r2"))


def test_github_queries_filter_results(tmp_path):
    out = {"pr": json.dumps([{"number": 1, "headRefName": "agent/r2/R", "state": "OPEN", "url": "u"},
                             {"number": 2, "headRefName": "agent/r2/R2", "state": "OPEN", "url": "u"}]),
           "issue": json.dumps([{"number": 5, "state": "OPEN", "url": "u", "body": "x reports/a.json"},
                                {"number": 6, "state": "OPEN", "url": "u", "body": "reports/b.json"}])}
    calls = []

    def runner(cmd, **kw):
        calls.append((cmd, kw["cwd"]))
        return subprocess.CompletedProcess(cmd, 0, stdout=out[cmd[1]], stderr="")
    gh = artifacts.GitHub("gh", tmp_path, runner=runner)
    assert [p["number"] for p in gh.prs_for_branch("agent/r2/R")] == [1]
    assert gh.issues_for_report("reports/a.json") == [{"number": 5, "url": "u", "state": "OPEN"}]
    assert all(c[1] == str(tmp_path) for c in calls)
    assert all(c[0][2] == "list" for c in calls)                 # tylko odczyt


# ---------------------------------------------------------------- CLI gate, log
def test_cli_gate_ok_and_mismatch(lab, tmp_path, capsys):
    repo, clock, ans, ctx = lab
    assert _cli(lab, ["gate", "r2"], tmp_path) == 0
    assert "bramka zgodna" in capsys.readouterr().out
    ans.extra_user = True
    assert _cli(lab, ["gate", "r2"], tmp_path) == 3
    assert "intruder" in capsys.readouterr().out


def test_cli_gate_dump_objects(lab, tmp_path, capsys):
    assert _cli(lab, ["gate", "r2", "--dump-objects"], tmp_path) == 0
    text = capsys.readouterr().out
    assert text.startswith("# Wzorzec bramki H5")
    assert gate.load_objects_ref(text, "r2") == gate.project(GATE_READS)


def test_cli_writes_log_next_to_result(lab, tmp_path):
    repo, clock, ans, ctx = lab
    agent_detects(repo, clock, ans, APPLY_AT + timedelta(seconds=212))
    assert _cli(lab, ["run", str(POL003), "--offset", "100"], tmp_path) == 0
    res = next(ctx.cfg.results_dir.glob("*.json"))
    logf = res.with_name(res.name.split("-POL-003")[0] + ".log")
    text = logf.read_text(encoding="utf-8")
    assert "t0=" in text and "werdykt pass" in text


def test_config_requires_ssh(tmp_path):
    doc = yaml.safe_load((REPO_ROOT / "harness" / "harness.example.yml").read_text(encoding="utf-8"))
    doc.pop("ssh")
    p = tmp_path / "harness.yml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    with pytest.raises(UsageError, match="ssh"):
        config_mod.load(p)
    cfg = config_mod.load(REPO_ROOT / "harness" / "harness.example.yml")
    assert cfg.windows == {"benign": 2700, "control": 2700} and cfg.artifacts.timeout_s == 300


def test_diff_export_pattern_with_crlf():
    """Wzorce export.rsc w site-lab mają CRLF (jak wyjście RouterOS); router też zwraca CRLF."""
    pattern_crlf = EXPORT_PATTERN.replace("\n", "\r\n")
    actual = "# inna data\r\n# software id =\r\n#\r\n" + EXPORT_PATTERN.split("\n", 3)[3].replace("\n", "\r\n")
    assert gate.diff_export(actual, pattern_crlf) == []
    assert gate.diff_export(actual.replace("\r\n", "\n"), pattern_crlf) == []


def test_cli_gate_dump_to_output_only_on_success(lab, tmp_path):
    repo, clock, ans, ctx = lab
    out = tmp_path / "gate-objects.yml"
    assert _cli(lab, ["gate", "r2", "--dump-objects", "--output", str(out)], tmp_path) == 0
    assert gate.load_objects_ref(out.read_text(encoding="utf-8"), "r2") == gate.project(GATE_READS)

    def broken(*a, **kw):
        raise HarnessError("playbooks/common/read.yml [None]: kod 2")
    ans.read_many = broken
    out2 = tmp_path / "nowy.yml"
    assert _cli(lab, ["gate", "r2", "--dump-objects", "--output", str(out2)], tmp_path) == 3
    assert not out2.exists() and not list(tmp_path.glob("*.tmp"))
    assert _cli(lab, ["gate", "r2", "--output", str(out2)], tmp_path) == 2


def test_read_playbook_uses_print_for_raw():
    doc = yaml.safe_load((REPO_ROOT / "playbooks/common/read.yml").read_text(encoding="utf-8"))
    tasks = {t["name"]: t for t in doc[0]["tasks"]}
    assert "community.routeros.api" in tasks["Odczyt menu (print)"]
    assert set(tasks["Odczyt menu (print)"]["community.routeros.api"]) == {"path"}   # tylko print
    assert "community.routeros.api_info" in tasks["Odczyt menu (api_info)"]


def test_gate_summary_counts_changed_lines_only():
    g = gate.GateResult(ok=False, export_diff=["@@ -33 +33 @@", "-/a", "+/b"], objects_diff=["+ file: x"])
    assert g.summary() == "bramka niezgodna: eksport 2 linii różnic, obiekty 1 różnic"


# ---------------------------------------------------------------- poprawki po labie 2026-11-14
def test_site007_result_never_contains_secret_values(lab, tmp_path):
    repo, clock, ans, ctx = lab
    agent_drift(repo, clock, APPLY_AT + timedelta(seconds=212))
    res = run_scenario(ctx, SITE007, offset_s=100)
    assert res["router_read"]["confirm"] == {"name": probes.SITE007_SECRET}
    assert res["router_read"]["end"] == {"name": probes.SITE007_SECRET}
    p = results.write(res, tmp_path / "out")
    assert "S3cr3tValue" not in p.read_text(encoding="utf-8")
    assert "password" not in p.read_text(encoding="utf-8")


def test_probe_view_drops_sensitive_fields():
    pr = probes.Probe(path="x", where={"name": "a"}, applied={"password": "p", "comment": "c"},
                      baseline=None)
    assert probes.view({"name": "a", "password": "p", "comment": "c", "other": 1}, pr) == \
        {"comment": "c", "name": "a"}
    assert probes.view(None, pr) is None


def test_close_artifacts_skipped_when_teardown_failed(lab):
    repo, clock, ans, ctx = lab
    ans.leave_after_revert = True
    rep = agent_drift(repo, clock, APPLY_AT + timedelta(seconds=212))
    branch = f"agent/r2/{rep['run']['run_id']}"
    ctx.github.prs[branch] = [{"number": 42, "url": "u", "state": "OPEN", "headRefName": branch}]
    res = run_scenario(ctx, SITE007, offset_s=100, close_artifacts=True)
    assert res["teardown"]["ok"] is False
    assert res["artifacts"][0]["closed"] == [] and "teardown" in res["artifacts"][0]["close_skipped"]
    assert ctx.github.closed == []


class InterruptingClock(FakeClock):
    def __init__(self, start, after_s):
        super().__init__(start)
        self.limit = start + timedelta(seconds=after_s)

    def sleep(self, seconds):
        super().sleep(seconds)
        if self.t >= self.limit:
            raise KeyboardInterrupt


def test_ctrl_c_after_apply_runs_teardown_and_writes_result(lab, tmp_path):
    repo, clock, ans, ctx = lab
    ctx.clock = InterruptingClock(T_START, after_s=120)       # w trakcie czekania na raport
    assert _cli(lab, ["run", str(POL003), "--offset", "100"], tmp_path) == 3
    doc = json.loads(next(ctx.cfg.results_dir.glob("*.json")).read_text(encoding="utf-8"))
    assert doc["verdict"] == "error" and doc["interrupted"] is True
    assert "SIGINT" in doc["reasons"][0]
    assert ans.calls[-2:] == ["revert", "gate"] and ans.enabled is False


def test_ctrl_c_while_waiting_preconditions(lab, tmp_path):
    repo, clock, ans, ctx = lab
    repo.commit_state(state_doc(posture="site-drift", open_findings=[{"rule": "local.ppp.secrets"}]),
                      T_START - timedelta(minutes=5), "drift")
    ctx.clock = InterruptingClock(T_START, after_s=60)
    assert _cli(lab, ["run", str(POL003), "--offset", "100"], tmp_path) == 3
    doc = json.loads(next(ctx.cfg.results_dir.glob("*.json")).read_text(encoding="utf-8"))
    assert doc["verdict"] == "error" and ans.calls == []


def test_site007_revert_loop_does_not_use_dotted_selectattr():
    doc = yaml.safe_load((REPO_ROOT / "playbooks/site/ppp-secret-add.yml").read_text(encoding="utf-8"))
    remove = [t for t in doc[0]["tasks"] if "remove" in t.get("community.routeros.api", {})][0]
    assert "select('mapping')" in remove["loop"] and "selectattr('.id'" not in remove["loop"]



# ---------------------------------------------------------------- pełny reset (H4)
TEMPLATE_R2 = """{%- macro ros(s) -%}{{ s }}{%- endmacro -%}
# Harness wgrywa PRZED resetem:
#   baseline.rsc  bl-api.crt  bl-api.key  ansible_rsa.pub  monitor_rsa.pub
#   (komentarz) import file-name=commented.txt
:delay 15s
/certificate
import file-name=bl-api.crt passphrase=""
import file-name=bl-api.key passphrase="{{ ros(bl_api_key_pass) }}"
/user ssh-keys
import public-key-file=ansible_rsa.pub user=ansible
import public-key-file=monitor_rsa.pub user=monitor
:do { /file remove [find where name="baseline.rsc"] } on-error={}
"""
HOST_VARS_R2 = 'mgmt_ip: 192.0.2.2\nbl_api_key_pass: "{{ vault_r2_api_key_pass }}"\n'
RESET_FILES = {"baseline.rsc", "bl-api.crt", "bl-api.key", "ansible_rsa.pub", "monitor_rsa.pub"}
RESET_AT = datetime(2026, 11, 13, 10, 5, 40, tzinfo=timezone.utc)   # T_START+90 s → :05 + 40 s


class ResetRouter(FakeAnsible):
    """Router z /file: prepare wgrywa pliki, reset (SSH) wyłącza go na `down_s`, po powrocie skrypt
    baseline usuwa pliki resetu (o ile `script_completes`)."""

    def __init__(self, clock, down_s=200, resets=True, script_completes=True, skip_upload=(),
                 leave_rendered=False):
        super().__init__()
        self.clock = clock
        self.down_s, self.resets, self.script_completes = down_s, resets, script_completes
        self.skip_upload, self.leave_rendered = set(skip_upload), leave_rendered
        self.files = {"flash": 0}
        self.up = True
        self.prepare_extra = None
        self.template_seen = None

    def read_many(self, router, paths, raw=False):
        if list(paths) == ["file"]:
            assert raw
            self.calls.append("files")
            if not self.up:
                raise HarnessError("ansible-playbook: kod 2\nconnection refused")
            return {"file": [{"name": n, "size": str(sz)} for n, sz in self.files.items()]}
        if not self.up:
            raise HarnessError("router nieosiągalny")
        return super().read_many(router, paths, raw)

    def playbook(self, playbook, router, tags=None, extra=None):
        if Path(playbook).stem != "reset":
            return super().playbook(playbook, router, tags, extra)
        self.calls.append(tags)
        if tags == "prepare":
            self.prepare_extra = dict(extra)
            self.template_seen = Path(extra["reset_template"]).read_text(encoding="utf-8")
            if self.leave_rendered:
                Path(extra["reset_rendered"]).write_text("rendered", encoding="utf-8")
            for name in ["baseline.rsc"] + [u["dst"] for u in extra["reset_uploads"]]:
                if name not in self.skip_upload:
                    self.files[name] = 100
        elif tags == "cleanup":
            for n in extra["reset_names"]:
                self.files.pop(n, None)
        else:
            raise AssertionError(tags)

    def do_reset(self):
        if not self.resets:
            return
        self.up = False

        def back():
            self.up = True
            if self.script_completes:
                for n in RESET_FILES:
                    self.files.pop(n, None)
        self.clock.at(self.clock.now() + timedelta(seconds=self.down_s), back)


class ResetSsh(FakeSsh):
    def __init__(self, ans: ResetRouter, ssh_fail=0):
        super().__init__(ans)
        self.remote: list[str] = []
        self.ssh_fail = ssh_fail          # RouterOS 6: klucz hosta generowany po starcie

    def run(self, router, remote, opts=(), timeout=None, input=None, check=True):
        self.remote.append(remote)
        self.ans.calls.append("ssh-reset")
        assert remote.startswith("/system reset-configuration") and "keep-users=no" in remote
        self.sent_at = self.ans.clock.now()
        self.ans.do_reset()
        return subprocess.CompletedProcess([], 255, "", "connection closed")

    def forget_host(self, router):
        self.ans.calls.append("forget")

    def accept_new(self, router):
        self.ans.calls.append("accept-new")
        if self.ssh_fail:
            self.ssh_fail -= 1
            raise HarnessError("ssh r2 /system: kod 255: Received disconnect from 192.0.2.2 port 22:3:")

    def fingerprints(self, router):
        return ["256 SHA256:abc 192.0.2.2 (ED25519)"]


def reset_ctx(tmp_path, ssh_fail=0, **router_kw):
    repo = SiteRepo(tmp_path, state_doc())
    d = repo.agent / "routers" / "r2"
    (d / "baseline.rsc.j2").write_text(TEMPLATE_R2, encoding="utf-8")
    (d / "host_vars.yml").write_text(HOST_VARS_R2, encoding="utf-8")
    repo.commit_state(state_doc(), T_START - timedelta(minutes=20), "baseline")
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    upload = {}
    for n in sorted(RESET_FILES - {"baseline.rsc"}):
        (secrets_dir / n).write_text("x", encoding="utf-8")
        upload[n] = secrets_dir / n
    base = make_cfg(tmp_path, repo.clone)
    routers = dict(base.routers)
    routers["r2"] = RouterCfg("r2", "192.0.2.2", tmp_path / "vault-r2.yml",
                              mgmt_return_timeout_s=420, upload=upload)
    cfg = Config(**{**base.__dict__, "routers": routers, "build_dir": tmp_path / "build",
                    "ssh_config": tmp_path / "ssh_config", "ssh_known_hosts": tmp_path / "kh"})
    clock = FakeClock(T_START)
    ans = ResetRouter(clock, **router_kw)
    ssh = ResetSsh(ans, ssh_fail=ssh_fail)
    ctx = Context(cfg, ans, sitelab.SiteLab(repo.clone), clock, random.Random(1), ssh=ssh)
    return repo, ctx, ans, ssh


def test_required_files_from_template():
    assert reset.required_files(TEMPLATE_R2) == RESET_FILES       # komentarz pominięty


def test_required_files_real_templates_shape():
    r1 = 'import file-name=bl-api.crt passphrase=""\nimport public-key-file=ansible.pub user=ansible\n'
    assert reset.required_files(r1) == {"baseline.rsc", "bl-api.crt", "ansible.pub"}


def test_reset_ok(tmp_path):
    repo, ctx, ans, ssh = reset_ctx(tmp_path)
    res = reset.run_reset(ctx, "r2", "hR")
    assert res["ok"] is True, res["error"]
    assert ans.calls == ["prepare", "files", "ssh-reset", "forget"] + ["files"] * 21 \
        + ["accept-new", "gate"]
    assert ssh.sent_at == RESET_AT and res["timing"]["reset_sent_at"] == ts(RESET_AT)
    assert res["timing"]["offset_s"] == 40 and res["timing"]["reset_grid_offset_s"] == 40
    assert res["timing"]["mgmt_return_s"] == 200 and res["timing"]["ssh_ready_s"] == 200
    assert res["files"] == sorted(RESET_FILES)
    assert res["host_key"]["fingerprints"] == ["256 SHA256:abc 192.0.2.2 (ED25519)"]
    assert res["gate"]["ok"] is True and res["cleanup"] is None
    ex = ans.prepare_extra
    assert ex["baseline_rev"] == res["site_lab"]["sha"]
    assert [u["dst"] for u in ex["reset_uploads"]] == sorted(RESET_FILES - {"baseline.rsc"})
    assert Path(ex["reset_rendered"]).parent == tmp_path / "build"
    assert not Path(ex["reset_template"]).exists()               # katalog tymczasowy usunięty
    assert ans.template_seen == TEMPLATE_R2


def test_reset_upload_mismatch_is_usage_error(tmp_path):
    repo, ctx, ans, ssh = reset_ctx(tmp_path)
    r2 = ctx.cfg.router("r2")
    up = {k: v for k, v in r2.upload.items() if k != "monitor_rsa.pub"}
    ctx.cfg.routers["r2"] = RouterCfg("r2", r2.mgmt_address, r2.vault_file, upload=up)
    with pytest.raises(UsageError, match="monitor_rsa.pub"):
        reset.run_reset(ctx, "r2", "hR")
    assert ans.calls == []


def test_reset_missing_local_file_is_usage_error(tmp_path):
    repo, ctx, ans, ssh = reset_ctx(tmp_path)
    ctx.cfg.router("r2").upload["bl-api.key"].unlink()
    with pytest.raises(UsageError, match="bl-api.key"):
        reset.run_reset(ctx, "r2", "hR")
    assert ans.calls == []


def test_reset_incomplete_upload_cleans_up_without_reset(tmp_path):
    repo, ctx, ans, ssh = reset_ctx(tmp_path, skip_upload={"bl-api.key"})
    res = reset.run_reset(ctx, "r2", "hR")
    assert res["ok"] is False and "bl-api.key" in res["error"]
    assert "ssh-reset" not in ans.calls and "cleanup" in ans.calls
    assert res["cleanup"] == "ok" and not RESET_FILES & set(ans.files)


def test_reset_not_happening_times_out_and_cleans_up(tmp_path):
    repo, ctx, ans, ssh = reset_ctx(tmp_path, resets=False)
    res = reset.run_reset(ctx, "r2", "hR")
    assert res["ok"] is False and "MGMT nie wrócił w 420 s" in res["error"]
    assert "pliki resetu nadal" in res["error"]
    assert res["cleanup"] == "ok" and not RESET_FILES & set(ans.files)
    assert ctx.clock.now() >= RESET_AT + timedelta(seconds=420)


def test_reset_script_interrupted_is_failure(tmp_path):
    repo, ctx, ans, ssh = reset_ctx(tmp_path, script_completes=False)
    res = reset.run_reset(ctx, "r2", "hR")
    assert res["ok"] is False and "pliki resetu nadal" in res["error"]


def test_reset_gate_mismatch(tmp_path):
    repo, ctx, ans, ssh = reset_ctx(tmp_path)
    ans.extra_user = True
    res = reset.run_reset(ctx, "r2", "hR")
    assert res["ok"] is False and res["gate"]["ok"] is False
    assert "bramka niezgodna" in res["error"] and res["cleanup"] is None


def test_reset_shreds_leftover_rendered_file(tmp_path):
    repo, ctx, ans, ssh = reset_ctx(tmp_path, leave_rendered=True)
    res = reset.run_reset(ctx, "r2", "hR")
    assert res["ok"] is True, res["error"]
    assert not Path(ans.prepare_extra["reset_rendered"]).exists()


def test_reset_requires_build_dir(tmp_path):
    repo, ctx, ans, ssh = reset_ctx(tmp_path)
    ctx.cfg = Config(**{**ctx.cfg.__dict__, "build_dir": None})
    with pytest.raises(UsageError, match="build_dir"):
        reset.run_reset(ctx, "r2", "hR")


def test_cli_reset_requires_yes(tmp_path):
    repo, ctx, ans, ssh = reset_ctx(tmp_path)
    args = cli._parser().parse_args(["reset", "r2"])
    with pytest.raises(UsageError, match="--yes"):
        cli.cmd_reset(args, ctx)
    assert ans.calls == []


def test_cli_reset_writes_result(tmp_path, capsys):
    repo, ctx, ans, ssh = reset_ctx(tmp_path)
    args = cli._parser().parse_args(["reset", "r2", "--yes"])
    assert cli.cmd_reset(args, ctx) == cli.EXIT_OK
    out = list((tmp_path / "results").glob("*-reset-r2.json"))
    assert len(out) == 1 and json.loads(out[0].read_text())["ok"] is True
    assert list((tmp_path / "results").glob("*.log"))
    assert "reset ok" in capsys.readouterr().out


def test_ssh_known_hosts_commands(tmp_path):
    kh = tmp_path / "kh"
    cfg = Config(**{**make_cfg(tmp_path, tmp_path).__dict__, "ssh_config": tmp_path / "ssh_config",
                    "ssh_known_hosts": kh})
    seen = []

    def runner(cmd, **kw):
        seen.append(cmd)
        out = "# Host 192.0.2.2 found: line 1\n256 SHA256:abc 192.0.2.2 (ED25519)\n"
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")
    s = Ssh(cfg, runner=runner)
    r2 = cfg.router("r2")
    s.forget_host(r2)                      # brak pliku → nic do usunięcia
    assert seen == []
    kh.write_text("x\n")
    s.forget_host(r2)
    assert seen[-1] == ["ssh-keygen", "-R", "192.0.2.2", "-f", str(kh)]
    s.accept_new(r2)
    assert "StrictHostKeyChecking=accept-new" in seen[-1] and f"UserKnownHostsFile={kh}" in seen[-1]
    assert s.fingerprints(r2) == ["256 SHA256:abc 192.0.2.2 (ED25519)"]


def test_reset_playbook_protects_rendered_baseline():
    doc = yaml.safe_load((REPO_ROOT / "playbooks/common/reset.yml").read_text(encoding="utf-8"))
    prepare = [t for t in doc[0]["tasks"] if "prepare" in t.get("tags", [])][0]
    assert "never" in prepare["tags"]
    tpl = [t for t in prepare["block"] if "ansible.builtin.template" in t][0]
    assert tpl["no_log"] is True and tpl["ansible.builtin.template"]["mode"] == "0600"
    assert any("shred" in json.dumps(t) for t in prepare["always"])
    cleanup = [t for t in doc[0]["tasks"] if "cleanup" in t.get("tags", [])][0]
    assert "never" in cleanup["tags"]


def test_reset_waits_for_ssh_host_key_ros6(tmp_path):
    # lab 2026-11-15 r2: api-ssl po 47 s, SSH rozłącza przy wymianie kluczy, bo klucz w generowaniu;
    # ponawianie rzadkie (co ssh_retry_s), bo każda próba restartuje generowanie
    repo, ctx, ans, ssh = reset_ctx(tmp_path, ssh_fail=2)
    res = reset.run_reset(ctx, "r2", "hR")
    assert res["ok"] is True, res["error"]
    assert ans.calls.count("accept-new") == 3
    assert res["timing"]["ssh_ready_s"] == 200 + 2 * 150 and res["timing"]["mgmt_return_s"] == 200


def test_reset_ssh_never_ready(tmp_path):
    repo, ctx, ans, ssh = reset_ctx(tmp_path, ssh_fail=10**6)
    res = reset.run_reset(ctx, "r2", "hR")
    assert res["ok"] is False and "SSH niegotowy" in res["error"] and "kod 255" in res["error"]
    assert ctx.clock.now() >= RESET_AT + timedelta(seconds=200 + 600)
    assert ans.calls.count("accept-new") == 5           # 0, 150, 300, 450, 600 s po MGMT
    assert res["cleanup"] is None and res["gate"] is None


# ---------------------------------------------------------------- iteracja 3: nowe scenariusze
SCN = REPO_ROOT / "scenarios"
POL004 = SCN / "policy" / "policy-proxy-enabled.yml"
POL005 = SCN / "policy" / "policy-api-plain-enabled.yml"
POL006 = SCN / "policy" / "policy-winbox-public.yml"
SITE008 = SCN / "site" / "site-user-add.yml"
BEN001 = SCN / "benign" / "benign-background.yml"


@pytest.mark.parametrize("manifest,rule,fix,field", [
    (POL004, "policy.services.proxy.disabled", lambda a: setattr(a, "proxy", False), "enabled"),
    (POL005, "policy.services.api-plain.disabled",
     lambda a: setattr(a, "api_disabled", True), "disabled"),
])
def test_pol004_pol005_pass(lab, manifest, rule, fix, field):
    repo, clock, ans, ctx = lab
    first_seen = APPLY_AT + timedelta(seconds=200)

    def fire():
        fix(ans)
        repo.commit_state(state_doc(), first_seen + timedelta(seconds=10), "agent(r2)",
                          report=report_doc(first_seen, rule=rule))
    clock.at(first_seen + timedelta(seconds=10), fire)
    res = run_scenario(ctx, manifest, offset_s=100)
    assert res["verdict"] == "pass", res["reasons"]
    assert res["router_read"]["end"] == res["router_read"]["pre"]          # end_state: baseline
    assert field in res["router_read"]["confirm"]
    assert res["teardown"]["ok"] is True


def test_pol006_action_none_revert_restores_router_address(lab):
    repo, clock, ans, ctx = lab
    first_seen = APPLY_AT + timedelta(seconds=200)
    rep = report_doc(first_seen, rule="policy.mgmt.winbox.not-public")
    rep["actions"][0].update(type="none", status="skipped", verification=None)
    clock.at(first_seen + timedelta(seconds=10),
             lambda: repo.commit_state(state_doc(posture="policy-violation"),
                                       first_seen + timedelta(seconds=10), "agent(r2)", report=rep))
    res = run_scenario(ctx, POL006, offset_s=100)
    assert res["verdict"] == "pass", res["reasons"]
    assert res["router_read"]["pre"] == {"address": "192.0.2.0/24", "name": "winbox"}
    assert res["router_read"]["end"] == {"name": "winbox"}                 # unchanged: adres pusty
    revert_extra = [e for t, e in ans.extras if t == "revert"][0]
    assert revert_extra == {"probe_pre": {"address": "192.0.2.0/24", "name": "winbox"}}
    assert ans.winbox_address == "192.0.2.0/24" and res["teardown"]["ok"] is True


def test_pol006_baseline_requires_nonempty_address(lab):
    repo, clock, ans, ctx = lab
    ans.winbox_address = ""
    res = run_scenario(ctx, POL006, offset_s=100)
    assert res["verdict"] == "invalid" and "address" in res["reasons"][0]
    assert "apply" not in ans.calls


def test_site008_pass_on_r1_with_pr(lab):
    repo, clock, ans, ctx = lab
    repo.commit_state(state_doc(router_id="r1"), T_START - timedelta(minutes=20), "r1", router="r1")
    first_seen = APPLY_AT + timedelta(seconds=200)
    rep = report_doc(first_seen, rule="local.drift.users")
    rep["findings"][0].update(rule_source="local")
    rep["verdict"]["posture"] = "site-drift"
    rep["actions"][0].update(type="open-pr", status="succeeded", verification=None)
    commit_at = first_seen + timedelta(seconds=10)
    st = state_doc(router_id="r1", posture="site-drift", open_findings=[{"rule": "local.drift.users"}])
    clock.at(commit_at, lambda: repo.commit_state(st, commit_at, "agent(r1)", report=rep, router="r1"))
    branch = f"agent/r1/{rep['run']['run_id']}"
    ctx.github.prs[branch] = [{"number": 7, "state": "OPEN", "headRefName": branch, "url": "u"}]
    res = run_scenario(ctx, SITE008, close_artifacts=True, offset_s=100)
    assert res["verdict"] == "pass", res["reasons"]
    assert res["target"]["router_id"] == "r1" and res["router_read"]["pre"] is None
    assert res["router_read"]["confirm"] == {"group": "read", "name": probes.SITE008_USER}
    assert ans.users == [] and res["artifacts"][0]["closed"] == ["pr#7"]


def test_ben001_apply_none_window_and_gate_only_teardown(h10):
    repo, clock, ans, ctx = h10
    st = h10_state(100, HB_AT) | {"router_id": "r1"}
    repo.commit_state(st, T_START - timedelta(minutes=20), "r1", router="r1")
    when = HB_NEXT
    clock.at(when, lambda: repo.commit_state(h10_state(105, when - timedelta(seconds=5))
                                             | {"router_id": "r1"}, when, "hb", router="r1"))
    res = run_scenario(ctx, BEN001, offset_s=100)
    assert res["verdict"] == "pass", res["reasons"]
    assert res["timing"]["t0"] == ts(BEN_APPLY)            # t0 = zaplanowany moment
    assert ans.calls == ["gate", "gate"]                    # bez apply/revert i bez odczytu obiektu
    assert res["teardown"]["revert"] == "skipped" and res["teardown"]["ok"] is True
    assert res["router_read"]["path"] is None


def test_probe_field_semantics():
    assert probes.matches({"address": "10.0.0.0/24"}, {"address": probes.NONEMPTY}) == []
    assert probes.matches({"address": ""}, {"address": probes.NONEMPTY})
    assert probes.matches({}, {"address": probes.NONEMPTY})
    assert probes.matches({}, {"address": ""}) == []
    assert probes.matches({"address": "x"}, {"address": ""})


# ---------------------------------------------------------------- kampania
class AutoAgent:
    """Agent atrapy: 200 s po apply POL-003 wykrywa, naprawia i publikuje raport (kolejne run_seq)."""

    def __init__(self, repo, clock, ans, router="r2"):
        self.repo, self.clock, self.ans, self.router = repo, clock, ans, router
        self.seq = 10
        orig = ans.playbook

        def playbook(pb, router_cfg, tags=None, extra=None):
            orig(pb, router_cfg, tags, extra)
            if tags == "apply" and Path(pb).stem == "socks-enabled":
                self.schedule()
        ans.playbook = playbook

    def schedule(self):
        self.seq += 1
        seq = self.seq
        first_seen = self.clock.now() + timedelta(seconds=200)
        rep = report_doc(first_seen, seq=seq)
        rep["run"]["run_id"] = f"RUN{seq:04d}"

        def fire():
            self.ans.enabled = False
            self.repo.commit_state(state_doc(), first_seen + timedelta(seconds=10), f"agent {seq}",
                                   report=rep, router=self.router)
        self.clock.at(first_seen + timedelta(seconds=10), fire)


def write_plan(tmp_path, **doc):
    p = tmp_path / "plan.yml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return p


def test_campaign_runs_repeats_and_writes_summary(lab, tmp_path):
    repo, clock, ans, ctx = lab
    AutoAgent(repo, clock, ans)
    plan = campaign_mod.load_plan(write_plan(tmp_path, campaign_id="t", close_artifacts=True, steps=[
        {"manifest": "scenarios/policy/policy-socks-enabled.yml", "repeat": 3}]), ctx.cfg)
    summ = campaign_mod.run_campaign(ctx, plan, "hC")
    assert summ["aborted"] is None and summ["counts"] == {"pass": 3}
    assert [r["index"] for r in summ["runs"]] == [1, 2, 3]
    offs = []
    for r in summ["runs"]:
        doc = json.loads((ctx.cfg.results_dir / r["path"]).read_text())
        assert doc["campaign"] == {"id": "t", "run_id": "hC", "step": 1, "index": r["index"], "of": 3}
        offs.append(doc["timing"]["planned_offset_s"])
    assert len(set(offs)) == 3                                  # losowe przesunięcie per przebieg
    saved = json.loads((ctx.cfg.results_dir / "hC-campaign-t.json").read_text())
    assert saved["counts"] == {"pass": 3} and saved["finished_at"]
    assert (ctx.cfg.results_dir / f"{summ['runs'][0]['run_id']}.log").is_file()


def test_campaign_aborts_on_invalid(tmp_path):
    st = state_doc(posture="site-drift", open_findings=[{"rule": "local.ppp.secrets"}])
    repo = SiteRepo(tmp_path, st)
    ans = FakeAnsible()
    ctx = Context(make_cfg(tmp_path, repo.clone), ans, sitelab.SiteLab(repo.clone),
                  FakeClock(T_START), random.Random(1), ssh=FakeSsh(ans))
    plan = campaign_mod.load_plan(write_plan(tmp_path, campaign_id="t", steps=[
        {"manifest": "scenarios/policy/policy-socks-enabled.yml", "repeat": 5}]), ctx.cfg)
    summ = campaign_mod.run_campaign(ctx, plan, "hC")
    assert len(summ["runs"]) == 1 and summ["runs"][0]["verdict"] == "invalid"
    assert "invalid" in summ["aborted"]


def fake_reset(results, ok=True):
    def run(ctx, router_id, run_id):
        results.append(router_id)
        return {"result_version": "1", "kind": "reset", "run_id": run_id, "router_id": router_id,
                "ok": ok, "error": None if ok else "bramka niezgodna",
                "timing": {"mgmt_return_s": 47.0, "ssh_ready_s": 47.1}}
    return run


@pytest.mark.parametrize("reset_ok,runs,aborted", [(True, 2, False), (False, 1, True)])
def test_campaign_full_reset_after_teardown_mismatch(lab, tmp_path, monkeypatch, reset_ok, runs,
                                                    aborted):
    repo, clock, ans, ctx = lab
    AutoAgent(repo, clock, ans)
    done = []
    reset = fake_reset(done, ok=reset_ok)

    def reset_and_fix(ctx_, rid, run_id):          # pełny reset usuwa pozostałość po revert
        ans.extra_user = False
        return reset(ctx_, rid, run_id)
    monkeypatch.setattr(campaign_mod, "run_reset", reset_and_fix)
    orig = ans.playbook

    def leave_once(pb, r, tags=None, extra=None):
        orig(pb, r, tags, extra)
        if tags == "revert" and not done:
            ans.extra_user = True                  # revert „zapomina” → bramka po teardownie
    ans.playbook = leave_once
    plan = campaign_mod.load_plan(write_plan(tmp_path, campaign_id="t", steps=[
        {"manifest": "scenarios/policy/policy-socks-enabled.yml", "repeat": 2}]), ctx.cfg)
    summ = campaign_mod.run_campaign(ctx, plan, "hC")
    assert summ["runs"][0]["teardown_ok"] is False
    assert done == ["r2"] and summ["resets"][0]["reason"].startswith("teardown ")
    assert len(summ["runs"]) == runs and bool(summ["aborted"]) is aborted


def test_campaign_reset_at_start_failure_aborts(lab, tmp_path, monkeypatch):
    repo, clock, ans, ctx = lab
    done = []
    monkeypatch.setattr(campaign_mod, "run_reset", fake_reset(done, ok=False))
    r2 = ctx.cfg.router("r2")
    ctx.cfg.routers["r2"] = RouterCfg("r2", r2.mgmt_address, r2.vault_file,
                                      upload={"x": tmp_path / "x"})
    ctx.cfg = Config(**{**ctx.cfg.__dict__, "build_dir": tmp_path / "b",
                        "ssh_known_hosts": tmp_path / "kh"})
    plan = campaign_mod.load_plan(write_plan(tmp_path, campaign_id="t", reset_at_start=["r2"], steps=[
        {"manifest": "scenarios/policy/policy-socks-enabled.yml"}]), ctx.cfg)
    summ = campaign_mod.run_campaign(ctx, plan, "hC")
    assert done == ["r2"] and summ["runs"] == [] and "na starcie" in summ["aborted"]


@pytest.mark.parametrize("doc,needle", [
    ({"campaign_id": "t", "steps": [], "bogus": 1}, "nieznane klucze"),
    ({"campaign_id": "Zły ID", "steps": [{"manifest": "x"}]}, "campaign_id"),
    ({"campaign_id": "t", "steps": [{"manifest": "scenarios/policy/policy-socks-enabled.yml",
                                     "repeat": 0}]}, "repeat"),
    ({"campaign_id": "t", "steps": [{"manifest": "scenarios/policy/policy-socks-enabled.yml",
                                     "target": "r9"}]}, "r9"),
    ({"campaign_id": "t", "steps": [{"manifest": "scenarios/policy/policy-socks-enabled.yml",
                                     "offset": 5}]}, "przesunięcie|offset"),
    ({"campaign_id": "t", "reset_at_start": ["r2"],
      "steps": [{"manifest": "scenarios/policy/policy-socks-enabled.yml"}]}, "build_dir"),
])
def test_campaign_plan_errors(lab, tmp_path, doc, needle):
    repo, clock, ans, ctx = lab
    with pytest.raises(UsageError, match=needle):
        campaign_mod.load_plan(write_plan(tmp_path, **doc), ctx.cfg)


def test_campaign_plan_duplicate_key(lab, tmp_path):
    repo, clock, ans, ctx = lab
    p = tmp_path / "plan.yml"
    p.write_text("campaign_id: a\ncampaign_id: b\nsteps: []\n", encoding="utf-8")
    with pytest.raises(UsageError, match="zduplikowany"):
        campaign_mod.load_plan(p, ctx.cfg)


def test_campaign_order_warnings(lab, tmp_path):
    repo, clock, ans, ctx = lab
    plan = campaign_mod.load_plan(write_plan(tmp_path, campaign_id="t", steps=[
        {"manifest": "scenarios/policy/policy-socks-enabled.yml", "target": "r1"},
        {"manifest": "scenarios/policy/policy-socks-enabled.yml", "target": "r2"},
        {"manifest": "scenarios/benign/benign-background.yml"},
        {"manifest": "scenarios/policy/policy-proxy-enabled.yml"}]), ctx.cfg)
    w = plan["order_warnings"]
    assert len(w) == 2 and "najpierw r2" in w[0] and "statyka → benign" in w[1]


def test_repo_campaign_plans_are_valid(lab):
    repo, clock, ans, ctx = lab
    for p in sorted((REPO_ROOT / "harness" / "campaigns").glob("*.yml")):
        plan = campaign_mod.load_plan(p, config_mod.load(REPO_ROOT / "harness" / "harness.example.yml"))
        assert plan["order_warnings"] == [], p.name


def test_cli_campaign_check_touches_nothing(lab, tmp_path, capsys):
    repo, clock, ans, ctx = lab
    code = _cli(lab, ["campaign", str(REPO_ROOT / "harness/campaigns/static-new.yml"), "--check"],
                tmp_path)
    assert code == cli.EXIT_OK and ans.calls == []
    out = capsys.readouterr().out
    assert "SITE-008 r1 ×1" in out and "BEN-001 r1 ×1" in out


# ---------------------------------------------------------------- zestawienie
def _row(mid, rid, verdict, mttd=None, **kw):
    return {"run_id": f"h-{mid}-{rid}-{mttd}", "campaign": "", "manifest_id": mid, "router_id": rid,
            "verdict": verdict, "mttd_s": mttd, "notify_s": kw.get("notify"),
            "remediate_s": kw.get("remediate"), "window_s": kw.get("window"),
            "t0_grid_offset_s": 100.0, "teardown_ok": True, "started_at": "2026-11-15T10:00:00Z"}


def test_summary_aggregates():
    rows = [_row("POL-003", "r2", "pass", m, notify=m + 2) for m in
            (100, 110, 120, 130, 140, 150, 160, 170, 180, 300)]
    rows.append(_row("POL-003", "r2", "timeout"))
    rows.append(_row("BEN-002", "r1", "pass", window=800))
    aggs = {(a["manifest_id"], a["router_id"]): a for a in summary_mod.aggregate(rows)}
    a = aggs[("POL-003", "r2")]
    assert a["n"] == 11 and a["pass"] == 10 and a["timeout"] == 1
    assert (a["mttd_min"], a["mttd_median"], a["mttd_p90"], a["mttd_max"]) == (100, 145, 180, 300)
    assert a["notify_median"] == 147
    assert aggs[("BEN-002", "r1")]["window_median"] == 800 and aggs[("BEN-002", "r1")]["mttd_p90"] is None
    md = summary_mod.markdown(rows, list(aggs.values()))
    assert "| POL-003 | r2 | 11 | 10 |" in md


def test_summary_collects_campaign_and_writes_csv(lab, tmp_path):
    repo, clock, ans, ctx = lab
    AutoAgent(repo, clock, ans)
    plan = campaign_mod.load_plan(write_plan(tmp_path, campaign_id="t", steps=[
        {"manifest": "scenarios/policy/policy-socks-enabled.yml", "repeat": 2}]), ctx.cfg)
    campaign_mod.run_campaign(ctx, plan, "hC")
    rd = ctx.cfg.results_dir
    docs = summary_mod.collect([rd / "hC-campaign-t.json"])
    assert len(docs) == 2 and all(d["campaign"]["id"] == "t" for d in docs)
    assert len(summary_mod.collect([rd])) == 2                 # katalog: bez wyniku kampanii
    out = tmp_path / "runs.csv"
    assert cli.main(["summary", str(rd), "--csv", str(out)]) == cli.EXIT_OK
    lines = out.read_text().splitlines()
    assert lines[0].startswith("run_id,campaign,manifest_id") and len(lines) == 3


# ================================================================ DYN-011a (iteracja 4)
DYN011A = REPO_ROOT / "scenarios" / "dynamic" / "dynamic-c2-divergence.yml"
DIV_RULE = "integrity.divergence.connections"
DRIFT_RULE = "local.drift.firewall-raw"


def dyn_report(rule, first_seen, run_id, seq, posture, rule_source, phase, action):
    rep = copy.deepcopy(json.loads((EX / "report-policy-violation.json").read_text(encoding="utf-8")))
    rep["run"].update(run_id=run_id, run_seq=seq, agent_version="0.7.1")
    rep["verdict"]["posture"] = posture
    f = rep["findings"][0]
    f.update(rule=rule, status="new", rule_source=rule_source, phase=phase,
             first_seen_at=ts(first_seen), fingerprint=f"sha256:{run_id}")
    rep["findings"] = rep["findings"][:1]
    rep["actions"] = [{"action_id": "a1", "fingerprint": f["fingerprint"], "type": action,
                       "status": "succeeded", "finished_at": ts(first_seen + timedelta(seconds=2)),
                       "verification": None}]
    return rep


def dyn_cfg(tmp_path, clone, addresses=("192.0.2.60", "192.0.2.61", "192.0.2.62"), **timing_over):
    cfg = make_cfg(tmp_path, clone, **timing_over)
    return Config(**{**cfg.__dict__, "endpoints": {"c2-lab": tuple(addresses)}})


def dyn_ctx(tmp_path, github=None, **timing_over):
    repo = SiteRepo(tmp_path, state_doc())
    repo.commit_state(state_doc(router_id="r1"), T_START - timedelta(minutes=20), "r1 init",
                      router="r1")
    clock = FakeClock(T_START)
    ans = FakeAnsible()
    cfg = dyn_cfg(tmp_path, repo.clone, **timing_over)
    ctx = Context(cfg=cfg, ansible=ans, site=sitelab.SiteLab(repo.clone), clock=clock,
                  rng=random.Random(1), ssh=FakeSsh(ans), github=github)
    return repo, clock, ans, ctx


def test_dyn011a_pass(tmp_path, monkeypatch):
    gh = FakeGitHub()
    repo, clock, ans, ctx = dyn_ctx(tmp_path, github=gh)
    # pełny reset w teardownie — atrapa (pełna maszyneria resetu ma własne testy)
    monkeypatch.setattr(scenario, "run_reset", lambda c, rid, run_id: {
        "ok": True, "error": None, "interrupted": False,
        "gate": {"ok": True, "export_diff": [], "objects_diff": []}})
    monkeypatch.setattr(scenario, "write_reset", lambda res, d: Path("reset.json"))

    t0 = T_START + timedelta(seconds=40)           # grid 10:00:00 + offset 100 = 10:01:40
    drift_at = t0 + timedelta(seconds=160)
    div_at = t0 + timedelta(seconds=1800)
    resolved_at = div_at + timedelta(seconds=300)
    drift_rid, div_rid = "01M7DRIFT0000000000000000", "01M7DIVERG0000000000000AB"

    def fire_drift():
        st = state_doc(router_id="r1", posture="site-drift",
                       open_findings=[{"rule": DRIFT_RULE, "fingerprint": "sha256:d"}])
        repo.commit_state(st, drift_at, "agent(r1): drift", router="r1",
                          report=dyn_report(DRIFT_RULE, drift_at, drift_rid, 7, "site-drift",
                                            "local", "static", "open-pr"))

    def fire_div():
        st = state_doc(router_id="r1", posture="compromise-suspected",
                       open_findings=[{"rule": DIV_RULE, "fingerprint": f"sha256:{div_rid}"}])
        repo.commit_state(st, div_at, "agent(r1): divergence", router="r1",
                          report=dyn_report(DIV_RULE, div_at, div_rid, 9, "compromise-suspected",
                                            "universal", "dynamic", "alert"))

    def fire_resolved():
        repo.commit_state(state_doc(router_id="r1"), resolved_at, "agent(r1): resolved", router="r1")

    clock.at(drift_at, fire_drift)
    clock.at(div_at, fire_div)
    clock.at(resolved_at, fire_resolved)
    gh.prs[f"agent/r1/{drift_rid}"] = [{"number": 51, "state": "OPEN",
                                        "headRefName": f"agent/r1/{drift_rid}"}]
    gh.issues = [{"number": 77, "state": "OPEN",
                  "body": f"reports/r1/2026/11/000009-{div_rid}.json"}]

    res = run_scenario(ctx, DYN011A, target="r1", offset_s=100, close_artifacts=True)

    assert res["verdict"] == "pass", res["reasons"]
    assert res["generate"]["from"] == "router"
    assert res["generate"]["target"] == "192.0.2.60"             # gen_index 0 → pierwszy adres
    assert res["timing"]["t0"] == ts(t0)
    assert res["metrics"]["mttd_s"] == 1800.0
    assert ans.covert is None                                    # revert usunął regułę raw
    assert any(r.startswith(":execute") and "count=1200" in r for r in ctx.ssh.runs)
    # efekt uboczny zapisany, nie zmienia werdyktu
    assert res["side_effects"] == [{"rule": DRIFT_RULE,
                                    "report": f"reports/r1/2026/11/000007-{drift_rid}.json"}]
    # teardown: pełny reset + rozwiązanie findingu
    assert res["teardown"]["reset"]["ok"] is True
    assert res["teardown"]["resolved"]["ok"] is True
    assert res["teardown"]["ok"] is True
    # H9: zamknięty PR driftu i issue rozbieżności
    assert {("pr", 51), ("issue", 77)} == {(k, n) for k, n, _ in gh.closed}


def test_dyn011a_resolve_timeout(tmp_path, monkeypatch):
    repo, clock, ans, ctx = dyn_ctx(tmp_path, resolve_timeout_s=600)
    monkeypatch.setattr(scenario, "run_reset", lambda c, rid, run_id: {
        "ok": True, "error": None, "interrupted": False,
        "gate": {"ok": True, "export_diff": [], "objects_diff": []}})
    monkeypatch.setattr(scenario, "write_reset", lambda res, d: Path("reset.json"))
    t0 = T_START + timedelta(seconds=40)
    div_at = t0 + timedelta(seconds=1800)

    def fire_div():
        st = state_doc(router_id="r1", posture="compromise-suspected",
                       open_findings=[{"rule": DIV_RULE, "fingerprint": "sha256:x"}])
        repo.commit_state(st, div_at, "agent(r1): divergence", router="r1",
                          report=dyn_report(DIV_RULE, div_at, "01M7DIV2", 9, "compromise-suspected",
                                            "universal", "dynamic", "alert"))
    clock.at(div_at, fire_div)
    res = run_scenario(ctx, DYN011A, target="r1", offset_s=100)      # finding nigdy nie znika
    assert res["verdict"] == "pass"                 # sam scenariusz ok
    assert res["teardown"]["resolved"]["ok"] is False
    assert res["teardown"]["ok"] is False
    assert "nierozwiązany" in res["teardown"]["error"]


def test_generate_pick_target_round_robin(tmp_path):
    cfg = dyn_cfg(tmp_path, tmp_path)
    assert [generate.pick_target(cfg, "c2-lab", i) for i in range(4)] == \
        ["192.0.2.60", "192.0.2.61", "192.0.2.62", "192.0.2.60"]
    with pytest.raises(UsageError, match="endpoints.nieznany"):
        generate.pick_target(cfg, "nieznany", 0)


def test_generate_router_requires_job(tmp_path):
    repo, clock, ans, ctx = dyn_ctx(tmp_path)
    ctx.ssh.run = lambda *a, **k: subprocess.CompletedProcess(["x"], 0, "0\n", "")
    with pytest.raises(HarnessError, match="ping nie wystartował"):
        generate.run_generate(ctx, {"id": "DYN-011a", "generate":
                              {"from": "router", "to_endpoint": "c2-lab", "behavior": "x"}},
                              ctx.cfg.router("r1"), "192.0.2.60")


def test_config_endpoints_parsed(tmp_path):
    doc = yaml.safe_load((REPO_ROOT / "harness" / "harness.example.yml").read_text(encoding="utf-8"))
    p = tmp_path / "harness.yml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    cfg = config_mod.load(p)
    assert cfg.endpoint("c2-lab") == ("192.0.2.60", "192.0.2.61", "192.0.2.62")
    doc["endpoints"] = {"c2-lab": {"addresses": []}}
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    with pytest.raises(UsageError, match="addresses"):
        config_mod.load(p)

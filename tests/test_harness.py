"""Testy harnessu (iteracja 1) — bez sieci, routerów i GitHuba.

Repo instalacji: prawdziwe repo Git w tmp_path (origin bare + klon „agenta” + klon harnessu),
raporty i stan w formacie agenta (z examples/). Router: atrapa Ansible ze stanem obiektu.
Zegar: atrapa przesuwana przez sleep(), z zaplanowanymi zdarzeniami („agent publikuje raport”).
"""
import copy
import json
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
from harness import config as config_mod
from harness import probes, results, sitelab, timing
from harness.config import Config, RouterCfg, TimingCfg
from harness.router import Ansible
from harness.scenario import Context, run_scenario

EX = REPO_ROOT / "examples"
POL003 = REPO_ROOT / "scenarios" / "policy" / "policy-socks-enabled.yml"
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


class FakeAnsible:
    """Router z jednym obiektem `ip socks`; apply/revert zmieniają `enabled`."""

    def __init__(self, enabled=False, apply_effect=True, fail_tags=()):
        self.enabled = enabled
        self.apply_effect = apply_effect
        self.fail_tags = set(fail_tags)
        self.calls: list[str] = []

    def read(self, router, path):
        assert path == "ip socks"
        self.calls.append("read")
        return [{"enabled": self.enabled, "port": 1080}]

    def playbook(self, playbook, router, tags=None, extra=None):
        assert playbook == "playbooks/policy/socks-enabled.yml"
        self.calls.append(tags)
        if tags in self.fail_tags:
            raise HarnessError(f"{playbook} [{tags}]: kod 2")
        if tags == "apply" and self.apply_effect:
            self.enabled = True
        elif tags == "revert":
            self.enabled = False


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
                  rng=random.Random(1))
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
    assert ans.calls == ["read", "apply", "read", "read", "revert"]
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
    assert res["teardown"]["revert"] == "ok"
    assert res["preconditions"]["ok"] is True


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
    ctx = Context(make_cfg(tmp_path, repo.clone), ans, sitelab.SiteLab(repo.clone),
                  FakeClock(T_START), random.Random(1))
    res = run_scenario(ctx, POL003, offset_s=100)
    assert res["verdict"] == "invalid"
    assert any("open_findings" in r for r in res["reasons"])
    assert any("posture" in r for r in res["reasons"])
    assert ans.calls == []                       # nic nie dotknięto na routerze
    assert res["teardown"]["revert"] is None


def test_router_not_in_baseline_invalid(lab):
    repo, clock, ans, ctx = lab
    ans.enabled = True
    res = run_scenario(ctx, POL003, offset_s=100)
    assert res["verdict"] == "invalid"
    assert ans.calls == ["read"]


def test_timeout_without_report(lab):
    repo, clock, ans, ctx = lab
    res = run_scenario(ctx, POL003, offset_s=100)
    assert res["verdict"] == "timeout"
    assert clock.now() >= APPLY_AT + timedelta(seconds=420 + 120)
    assert ans.calls[-1] == "revert"
    assert res["teardown"]["revert"] == "ok"


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
    assert ans.calls[-1] == "revert"              # teardown także po błędzie


def test_revert_failure_turns_pass_into_error(lab):
    repo, clock, ans, ctx = lab
    ans.fail_tags = {"revert"}
    agent_detects(repo, clock, ans, APPLY_AT + timedelta(seconds=212))
    res = run_scenario(ctx, POL003, offset_s=100)
    assert res["verdict"] == "error"
    assert res["oracle"]["violations"] == []      # wynik oracle'a zachowany w wyniku
    assert res["teardown"]["revert"] == "error"


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
    Path(out).write_text(json.dumps([{{"enabled": False, "port": 1080}}]))
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


def test_playbooks_have_apply_and_revert_tags():
    doc = yaml.safe_load((REPO_ROOT / "playbooks/policy/socks-enabled.yml").read_text(encoding="utf-8"))
    tags = [set(t.get("tags", [])) for t in doc[0]["tasks"]]
    assert {"apply"} in tags and {"revert", "never"} in tags
    for t in doc[0]["tasks"]:
        assert t.get("no_log") == "{{ harness_no_log }}"


# ---------------------------------------------------------------- konfiguracja
def test_example_config_loads():
    cfg = config_mod.load(REPO_ROOT / "harness" / "harness.example.yml")
    assert cfg.router("r2").mgmt_address == "192.0.2.2"
    assert cfg.router("r1").mgmt_return_timeout_s == 300
    assert cfg.router("r2").vault_file.is_absolute()
    assert cfg.timing.cycle_s == 300
    with pytest.raises(UsageError):
        cfg.router("r9")


@pytest.mark.parametrize("mutate,needle", [
    (lambda d: d.pop("site_lab"), "site_lab"),
    (lambda d: d["routers"]["r2"].pop("vault_file"), "routers.r2.vault_file"),
    (lambda d: d["timing"].update(avoid_window_s=400), "avoid_window_s"),
    (lambda d: d["timing"].update(bogus=1), "nieznane"),
])
def test_config_errors(tmp_path, mutate, needle):
    doc = yaml.safe_load((REPO_ROOT / "harness" / "harness.example.yml").read_text(encoding="utf-8"))
    mutate(doc)
    p = tmp_path / "harness.yml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    with pytest.raises(UsageError, match=needle):
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
    assert ans.calls == ["read"]
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

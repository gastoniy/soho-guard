"""Publikacja na prawdziwym gicie: lokalne repo bare zamiast GitHuba, bez sieci."""
import fcntl
import json
import shutil
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

import test_agent as base
from test_agent import MockApi, SECRET, SOCKS_ON, SOCKS_RULE, git, lab, router  # noqa: F401
from agent import __main__ as cli
from agent import config, publish
from agent.publish import Publisher, PublishError, git_env, should_publish, state_digest
import validate_report as validate

START = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)


class Remote:
    def __init__(self, lab, tmp_path):
        self.lab = lab
        self.bare = tmp_path / "remote.git"
        self.checks = tmp_path / "checks"
        self.now = START
        git(lab.site, "branch", "-M", "main")
        git(lab.site, "config", "user.name", "agent")
        git(lab.site, "config", "user.email", "agent@example.invalid")
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(self.bare)], check=True)
        git(lab.site, "remote", "add", "origin", str(self.bare))
        git(lab.site, "push", "-q", "-u", "origin", "main")

    def clock(self):
        return self.now

    def run(self, data=None, *extra, connector=None):
        connector = connector or (lambda ctx, password: MockApi(base.CLEAN if data is None else data))
        return cli.main(["--router", "r2", "--once", "--no-remediate", *extra],
                        paths=self.lab.paths, clock=self.clock, connector=connector)

    def later(self, seconds=300):
        self.now += timedelta(seconds=seconds)

    def out(self, branch="main") -> Path:
        return self.lab.paths.data_dir / "publish" / branch / "r2"

    def commits(self, branch="main") -> int:
        out = subprocess.run(["git", "-C", str(self.bare), "rev-list", "--count", branch],
                             capture_output=True, text=True, check=True)
        return int(out.stdout)

    def checkout(self, branch="main") -> Path:
        if self.checks.exists():
            shutil.rmtree(self.checks)
        subprocess.run(["git", "clone", "-q", "-b", branch, str(self.bare), str(self.checks)], check=True)
        return self.checks

    def reports(self, branch="main") -> list[dict]:
        files = sorted((self.checkout(branch) / "reports" / "r2").rglob("*.json"))
        return [json.loads(p.read_text(encoding="utf-8")) for p in files]

    def assert_chain(self, count, branch="main"):
        root = self.checkout(branch)
        assert validate.validate_chain(root / "reports" / "r2") == []
        assert len(list((root / "reports" / "r2").rglob("*.json"))) == count

    def pending(self, branch="main") -> list[Path]:
        return sorted((self.out(branch) / "outbox").rglob("*.json"))

    def operator_commit(self, relative, text):
        """Zmiana scalona przez operatora, niezależnie od klonu agenta."""
        root = self.checkout()
        (root / relative).write_text(text, encoding="utf-8")
        git(root, "add", "-A")
        git(root, "commit", "-qm", "operator")
        git(root, "push", "-q", "origin", "main")


@pytest.fixture
def remote(lab, tmp_path):  # noqa: F811
    return Remote(lab, tmp_path)


def head(site):
    return subprocess.run(["git", "-C", str(site), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()


# --- R3, R9 ---
def test_first_cycle_publishes_report_and_state(remote):
    assert remote.run() == 0
    assert remote.commits() == 2
    root = remote.checkout()
    state = json.loads((root / "state" / "r2.json").read_text(encoding="utf-8"))
    assert validate.validate_state(state) == []
    reports = remote.reports()
    assert len(reports) == 1 and validate.validate_report(reports[0]) == []
    assert reports[0]["policy"]["evaluation_mode"] == "enforce"
    assert state["last_report"]["run_id"] == reports[0]["run"]["run_id"]
    assert remote.pending() == []


def test_unchanged_cycle_makes_no_commit(remote):
    assert remote.run() == 0
    remote.later()
    assert remote.run() == 0
    assert remote.commits() == 2


def test_heartbeat_commits_state_after_interval(remote):
    assert remote.run() == 0
    remote.later(1799)
    assert remote.run() == 0
    assert remote.commits() == 2
    remote.later(1)
    assert remote.run() == 0
    assert remote.commits() == 3
    remote.assert_chain(1)
    state = json.loads((remote.checkout() / "state" / "r2.json").read_text(encoding="utf-8"))
    assert state["last_run"]["run_seq"] == 3


def test_violation_publishes_at_once(remote):
    assert remote.run() == 0
    remote.later()
    assert remote.run(router(**SOCKS_ON)) == 0
    assert remote.commits() == 3
    remote.assert_chain(2)
    rep = remote.reports()[-1]
    assert validate.validate_report(rep) == []
    finding = next(f for f in rep["findings"] if f["rule"] == SOCKS_RULE)
    action = next(a for a in rep["actions"] if a["fingerprint"] == finding["fingerprint"])
    assert (action["type"], action["status"]) == ("auto-remediate", "skipped")
    assert "--no-remediate" in action["reason"]


def test_local_finding_action_is_proposed(remote):
    assert remote.run() == 0
    remote.later()
    assert remote.run(router(ppp__secret=[{".id": "*1", "name": "vpn", "password": SECRET}])) == 0
    rep = remote.reports()[-1]
    assert validate.validate_report(rep) == []
    assert [(a["type"], a["status"]) for a in rep["actions"]] == [("open-pr", "proposed")]


def test_secret_never_reaches_repository(remote):
    assert remote.run(router(ppp__secret=[{".id": "*1", "name": "vpn", "password": SECRET}])) == 0
    out = subprocess.run(["git", "-C", str(remote.bare), "grep", "-c", SECRET, "main"], capture_output=True, text=True)
    assert out.returncode == 1 and out.stdout == ""


# --- awarie ---
def test_push_failure_keeps_outbox_and_recovers(remote, capsys):
    git(remote.lab.site, "remote", "set-url", "--push", "origin", "/nie/ma/repo.git")
    before = head(remote.lab.site)
    assert remote.run() == 1
    assert "publikacja=błąd" in capsys.readouterr().out
    assert len(remote.pending()) == 1
    assert head(remote.lab.site) == before
    assert remote.commits() == 1

    remote.later()
    assert remote.run() == 1                                 # nowy błąd: drugi raport czeka
    assert len(remote.pending()) == 2
    remote.later()
    assert remote.run() == 1                                 # ten sam błąd: bez kolejnego raportu
    assert len(remote.pending()) == 2

    git(remote.lab.site, "remote", "set-url", "--push", "origin", str(remote.bare))
    remote.later()
    assert remote.run() == 0
    remote.assert_chain(2)
    assert remote.pending() == []
    assert {e["code"] for e in remote.reports()[-1]["run"]["errors"]} == {"publish.push-failed"}

    remote.later()
    assert remote.run() == 0                                 # koniec awarii zapisany w łańcuchu
    remote.assert_chain(3)
    assert remote.reports()[-1]["run"]["errors"] == []


def test_link_outage_gives_two_reports(remote):
    assert remote.run() == 0
    git(remote.lab.site, "remote", "set-url", "origin", "/nie/ma/repo.git")
    git(remote.lab.site, "remote", "set-url", "--push", "origin", "/nie/ma/repo.git")
    for _ in range(3):
        remote.later()
        assert remote.run() == 1                             # cykl trwa, wynik zapisany lokalnie
    assert len(remote.pending()) == 1
    git(remote.lab.site, "remote", "set-url", "origin", str(remote.bare))
    git(remote.lab.site, "remote", "set-url", "--push", "origin", str(remote.bare))
    remote.later()
    assert remote.run() == 0
    remote.assert_chain(3)
    reports = remote.reports()
    assert {e["code"] for e in reports[1]["run"]["errors"]} == {"publish.sync-failed"}
    assert reports[2]["run"]["errors"] == []


def test_router_publishes_only_own_data(remote):
    assert remote.run() == 0
    # r1 ma raport w outboxie, bo jego łącze nie działa; push r2 nie może go zabrać.
    ctx = SimpleNamespace(paths=remote.lab.paths, router_id="r1", agent_source="10.100.1.10")
    waiting = Publisher(ctx, "main", remote.lab.paths.data_dir / "publish" / "main" / "r1")
    (waiting.reports_dir / "2026" / "11").mkdir(parents=True)
    file = waiting.reports_dir / "2026" / "11" / "000001-X.json"
    file.write_text("{}", encoding="utf-8")
    remote.later()
    assert remote.run(router(**SOCKS_ON)) == 0
    root = remote.checkout()
    assert not (root / "reports" / "r1").exists() and not (root / "state" / "r1.json").exists()
    assert file.exists()


def test_rejected_push_is_retried_on_new_base(remote):
    hook = remote.bare / "hooks" / "pre-receive"
    flag = remote.bare / "rejected-once"
    hook.write_text(f'#!/bin/sh\n[ -e "{flag}" ] && exit 0\ntouch "{flag}"\nexit 1\n', encoding="utf-8")
    hook.chmod(0o755)
    assert remote.run() == 0
    assert flag.exists() and remote.commits() == 2


def test_publishes_on_top_of_operator_merge_during_cycle(remote):
    assert remote.run() == 0
    remote.later()

    def connector(ctx, password):
        remote.operator_commit("NOTATKA.md", "scalone w trakcie cyklu\n")
        return MockApi(router(**SOCKS_ON))

    assert remote.run(connector=connector) == 0
    remote.assert_chain(2)
    assert (remote.checks / "NOTATKA.md").exists()
    assert remote.commits() == 4


def test_policy_change_applies_in_same_cycle(remote):
    assert remote.run() == 0
    site = yaml.safe_load((remote.lab.site / "site.yml").read_text(encoding="utf-8"))
    site["policy"]["universal_version"] = "v9.9.9-lab"
    remote.operator_commit("site.yml", yaml.safe_dump(site))
    remote.later()
    assert remote.run() == 0
    assert head(remote.lab.site) == subprocess.run(
        ["git", "-C", str(remote.bare), "rev-parse", "main~1"], capture_output=True, text=True, check=True).stdout.strip()
    assert {e["code"] for e in remote.reports()[-1]["run"]["errors"]} == {"policy.version-mismatch"}


def test_interrupted_cycle_does_not_fork_chain(remote):
    assert remote.run() == 0
    orphan = remote.out() / "outbox" / "reports" / "r2" / "2026" / "11" / "000002-01ARZ3NDEKTSV4RRFFQ69G5FAV.json"
    orphan.parent.mkdir(parents=True, exist_ok=True)
    orphan.write_text("{}", encoding="utf-8")
    remote.later()
    assert remote.run(router(**SOCKS_ON)) == 0
    remote.assert_chain(2)
    assert (remote.out() / "orphaned" / orphan.name).exists()


def test_republishing_after_crash_is_idempotent(remote):
    assert remote.run() == 0
    runtime = remote.out() / "runtime.json"
    doc = json.loads(runtime.read_text(encoding="utf-8"))
    doc["published"] = None                                  # przerwanie tuż po pushu
    runtime.write_text(json.dumps(doc), encoding="utf-8")
    state = remote.out() / "state.json"
    before = state.read_bytes()
    remote.later()
    assert remote.run() == 0
    assert state.read_bytes() != before
    remote.assert_chain(1)


def test_lost_local_data_continues_chain(remote):
    assert remote.run() == 0
    remote.later()
    assert remote.run(router(**SOCKS_ON)) == 0
    shutil.rmtree(remote.out())
    remote.later()
    assert remote.run(router(**SOCKS_ON)) == 0
    state = json.loads((remote.checkout() / "state" / "r2.json").read_text(encoding="utf-8"))
    assert state["last_run"]["run_seq"] == 3
    assert len(state["open_findings"]) == 1
    remote.assert_chain(2)


# --- gałąź testowa ---
def test_test_branch_leaves_main_alone(remote):
    assert remote.run(None, "--publish-branch", "test/iter2") == 0
    assert remote.commits("main") == 1
    assert remote.commits("test/iter2") == 2
    remote.assert_chain(1, "test/iter2")
    assert remote.pending("test/iter2") == []
    branch = subprocess.run(["git", "-C", str(remote.lab.site), "branch", "--show-current"],
                            capture_output=True, text=True, check=True).stdout.strip()
    assert branch == "main"


def test_branch_chain_is_separate_from_main(remote):
    assert remote.run() == 0
    remote.later()
    assert remote.run(router(**SOCKS_ON)) == 0
    remote.later()
    # Gałąź wychodzi z main i zawiera jego raporty, więc jej łańcuch je kontynuuje.
    assert remote.run(router(**SOCKS_ON), "--publish-branch", "test/iter2") == 0
    remote.later()
    assert remote.run(None, "--publish-branch", "test/iter2") == 0
    remote.assert_chain(3, "test/iter2")
    remote.assert_chain(2, "main")


def test_clone_stays_clean(remote):
    assert remote.run() == 0
    site = str(remote.lab.site)
    status = subprocess.run(["git", "-C", site, "status", "--porcelain"], capture_output=True, text=True, check=True)
    worktrees = subprocess.run(["git", "-C", site, "worktree", "list"], capture_output=True, text=True, check=True)
    assert status.stdout == "" and len(worktrees.stdout.splitlines()) == 1
    assert not (remote.out() / "worktree").exists()


def test_dry_run_does_not_touch_remote(remote):
    before = head(remote.lab.site)
    remote.operator_commit("NOTATKA.md", "nowe\n")
    assert remote.lab.run() == 0
    assert head(remote.lab.site) == before
    assert remote.commits() == 2


# --- pomocnicze ---
def test_git_env_binds_source_and_key(lab):  # noqa: F811
    command = git_env(lab.paths, "10.100.2.10")["GIT_SSH_COMMAND"]
    assert "-b 10.100.2.10" in command
    assert f"-i {lab.paths.deploy_key}" in command
    assert "IdentitiesOnly=yes" in command and "StrictHostKeyChecking=yes" in command
    assert f"UserKnownHostsFile={lab.paths.known_hosts}" in command
    assert "BatchMode=yes" in command and "ConnectTimeout=" in command


def test_hanging_ssh_is_killed_at_timeout(remote, monkeypatch):
    monkeypatch.setattr(publish, "GIT_TIMEOUT", 1)
    ctx = SimpleNamespace(paths=remote.lab.paths, router_id="r2", agent_source="10.100.2.10")
    pub = Publisher(ctx, "main", remote.out())
    pub.env = {**pub.env, "GIT_SSH_COMMAND": "sleep 60 #"}
    git(remote.lab.site, "remote", "set-url", "origin", "ssh://git@example.invalid/x.git")
    started = time.monotonic()
    with pytest.raises(PublishError, match="przekroczono"):
        pub.sync()
    assert time.monotonic() - started < 10


def test_busy_lock_is_publish_error_not_hang(remote, monkeypatch):
    monkeypatch.setattr(config, "LOCK_WAIT_S", 0)
    ctx = SimpleNamespace(paths=remote.lab.paths, router_id="r2", agent_source="10.100.2.10")
    pub = Publisher(ctx, "main", remote.out())
    remote.lab.paths.site_lock.parent.mkdir(parents=True, exist_ok=True)
    with open(remote.lab.paths.site_lock, "a", encoding="utf-8") as other:
        fcntl.flock(other, fcntl.LOCK_EX)
        with pytest.raises(PublishError, match="zajęta"):
            pub.sync()


def state_doc(at="2026-11-06T12:00:00.000Z", posture="inconclusive"):
    return {"posture": posture, "last_run": {"run_seq": 1}, "heartbeat": {"at": at, "interval_s": 1800}}


def test_digest_ignores_only_run_and_heartbeat():
    assert state_digest(state_doc()) == state_digest(state_doc(at="2026-11-06T13:00:00.000Z"))
    assert state_digest(state_doc()) != state_digest(state_doc(posture="site-drift"))


@pytest.mark.parametrize("pending,published,at,expected", [
    (False, None, "2026-11-06T12:00:00.000Z", True),
    (True, {"digest": "same", "at": "2026-11-06T12:00:00.000Z"}, "2026-11-06T12:00:00.000Z", True),
    (False, {"digest": "same", "at": "2026-11-06T12:00:00.000Z"}, "2026-11-06T12:29:59.999Z", False),
    (False, {"digest": "same", "at": "2026-11-06T12:00:00.000Z"}, "2026-11-06T12:30:00.000Z", True),
    (False, {"digest": "inny", "at": "2026-11-06T12:00:00.000Z"}, "2026-11-06T12:05:00.000Z", True),
])
def test_should_publish(pending, published, at, expected):
    doc = state_doc(at=at)
    if published and published["digest"] == "same":
        published = {**published, "digest": state_digest(doc)}
    assert should_publish(doc, pending, published) is expected

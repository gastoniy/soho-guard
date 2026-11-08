"""Faza dynamiczna: odczyt Zeeka, próbki tablicy połączeń, detektory, pełny cykl."""
import gzip
import json
import os
from datetime import datetime, timedelta, timezone

import pytest
import yaml

import test_agent as base
import validate_report as validate
from test_agent import WAN, MockApi, lab, router, zeek_text  # noqa: F401
from test_mitigate import Sim, full  # noqa: F401
from test_publish import remote  # noqa: F401
from agent import __main__ as cli
from agent import dynamic_eval, l1_router, l2_zeek
from agent.config import Paths  # noqa: F401
from agent.findings import fingerprint

START = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)
T0 = START.timestamp()
C2 = "203.0.113.9"
DIVERGENCE = "integrity.divergence.connections"
ROGUE = "policy.dynamic.rogue-resolver"
DGA = "policy.dynamic.dga"
DGA_NAMES = ["xk3q9vbz7lmw2rtp.com", "p8fj2mzq4wnx7ctb.net", "h5rq0zvt3kxm9bwd.org"]


class Clock:
    def __init__(self):
        self.now = START

    def __call__(self):
        return self.now

    def later(self, seconds=300):
        self.now += timedelta(seconds=seconds)


@pytest.fixture
def clock():
    return Clock()


def cycle(lab, clock, data=None, *extra):  # noqa: F811
    data = router() if data is None else data
    return cli.main(["--router", "r2", "--once", "--dry-run", *extra], paths=lab.paths, clock=clock,
                    connector=lambda ctx, password: MockApi(data))


def flow(dst=C2, port=8443, proto="tcp", ts=T0 - 60, duration=7200.0, state="SF", orig=WAN, uid="C1"):
    return {"ts": f"{ts:.6f}", "uid": uid, "id.orig_h": orig, "id.orig_p": 40000, "id.resp_h": dst,
            "id.resp_p": port, "proto": proto, "duration": f"{duration:.6f}", "orig_bytes": 100,
            "resp_bytes": 200, "conn_state": state, "resp_pkts": 5}


def query(name, resolver="1.1.1.1", ts=T0 - 30, orig=WAN, uid="D1"):
    return {"ts": f"{ts:.6f}", "uid": uid, "id.orig_h": orig, "id.orig_p": 53000, "id.resp_h": resolver,
            "id.resp_p": 53, "proto": "udp", "query": name, "qtype_name": "A"}


def rule_of(rule_id):
    return next(r for r in yaml.safe_load(open(base.ROOT / "policy/dynamic/behavioral.yml"))["rules"]
                if r["id"] == rule_id)


def data_with(conn=(), dns=(), since=T0 - 3600, until=T0):
    data = l2_zeek.ZeekData(since=since, until=until)
    for row in conn:
        data.conn.append({"resp_pkts": 5, **row, "ts": float(row["ts"]), "duration": float(row["duration"])})
    for row in dns:
        data.dns.append({**row, "ts": float(row["ts"])})
    return data


def sample(at, cycle_id, targets=()):
    return {"at": at, "cycle": cycle_id, "targets": [list(t) for t in targets]}


# --- odczyt Zeeka ---
def test_wan_address_without_mask():
    assert l2_zeek.wan_ip("192.168.20.21/24") == "192.168.20.21"
    assert l2_zeek.wan_ip(None) is None


def test_parse_uses_header_and_skips_truncated_line():
    text = zeek_text("conn", [flow()]) + "1794083526.0\tucięty\n"
    rows = l2_zeek.parse(text.splitlines(keepends=True), l2_zeek.CONN_FIELDS)
    assert len(rows) == 1 and rows[0]["id.resp_h"] == C2 and rows[0]["conn_state"] == "SF"


def test_unset_field_is_none():
    rows = l2_zeek.parse(zeek_text("dns", [{"ts": "1.0", "query": "-"}]).splitlines(), l2_zeek.DNS_FIELDS)
    assert rows[0]["query"] is None


def test_fixture_files_parse():
    for kind, wanted in (("conn", l2_zeek.CONN_FIELDS), ("dns", l2_zeek.DNS_FIELDS)):
        text = (base.ZEEK_FIXTURES / f"{kind}.log").read_text(encoding="utf-8")
        assert len(l2_zeek.parse(text.splitlines(), wanted)) == 2


def test_read_filters_router_and_window(lab):  # noqa: F811
    lab.zeek("conn", [flow(uid="w"), flow(orig="192.168.20.21", uid="inny"),
                      flow(ts=T0 - 9000, duration=10, uid="stary"),
                      flow(ts=T0 - 9000, duration=6000, uid="dlugi")])
    data = l2_zeek.read(lab.paths.zeek_dir, WAN, T0)
    assert sorted(r["uid"] for r in data.conn) == ["dlugi", "w"]


def test_read_includes_recent_archive_only(lab):  # noqa: F811
    day = lab.paths.zeek_dir / START.strftime("%Y-%m-%d")
    day.mkdir()
    for name, uid, age in (("conn.11:00:00-12:00:00.log.gz", "nowe", 0), ("conn.08:00:00-09:00:00.log.gz", "stare", 10800)):
        path = day / name
        with gzip.open(path, "wt", encoding="utf-8") as handle:
            handle.write(zeek_text("conn", [flow(uid=uid, ts=T0 - 600, duration=10)]))
        os.utime(path, (T0 - age, T0 - age))
    data = l2_zeek.read(lab.paths.zeek_dir, WAN, T0)
    assert [r["uid"] for r in data.conn] == ["nowe"]


def test_missing_current_dir_is_error(tmp_path):
    with pytest.raises(l2_zeek.ZeekError):
        l2_zeek.read(tmp_path, WAN, T0)


# --- tablica połączeń ---
def test_targets_v7_and_v6_formats_without_lan():
    rows = [
        {"protocol": "tcp", "src-address": "10.200.1.199", "src-port": "42686", "dst-address": "140.82.121.4",
         "dst-port": "22", "reply-src-address": "140.82.121.4", "reply-src-port": "22"},
        {"protocol": "tcp", "src-address": "10.200.2.199:45964", "dst-address": "140.82.121.4:443",
         "reply-src-address": "140.82.121.4:443"},
        {"protocol": "icmp", "src-address": "10.200.2.5", "dst-address": "1.1.1.1"},
        {"protocol": "tcp", "dst-address": "2001:db8::1", "dst-port": "443"},
    ]
    targets = l1_router.connection_targets(rows)
    assert targets == [["1.1.1.1", "icmp", None], ["140.82.121.4", "tcp", 22], ["140.82.121.4", "tcp", 443]]
    assert "10.200" not in json.dumps(targets)


@pytest.mark.parametrize("row,active", [
    ({"enabled": "auto", "active-ipv4": True}, True),
    ({"enabled": "auto"}, True),                       # v6
    ({"enabled": "no"}, False),
    ({"enabled": "auto", "active-ipv4": False}, False),
])
def test_tracking_active(row, active):
    assert l1_router._tracking_active([row]) is active


# --- detektory ---
def test_divergence_needs_three_cycles():
    rule = rule_of(DIVERGENCE)
    data = data_with([flow(ts=T0 - 1000)])
    two = [sample(T0 - 600, "c1"), sample(T0 - 300, "c2")]
    assert dynamic_eval.divergence(rule, data, two) == []
    found = dynamic_eval.divergence(rule, data, two + [sample(T0, "c3")])
    assert [v.object_key for v in found] == [f"{C2}/tcp/8443"]
    v = found[0]
    assert v.trust["divergence"] and v.trust["contradicted_by"] == ["L1"]
    assert v.evidence["l1_claim"] == {"query": "/ip/firewall/connection", "destination_present": False}


def test_one_hit_in_window_means_no_divergence():
    samples = [sample(T0 - 600, "c1"), sample(T0 - 300, "c2", [(C2, "tcp", 8443)]), sample(T0, "c3")]
    assert dynamic_eval.divergence(rule_of(DIVERGENCE), data_with([flow(ts=T0 - 1000)]), samples) == []


def test_short_flows_between_samples_are_not_evidence():
    rows = [flow(ts=T0 - 600 + 10 + i * 300, duration=5, uid=f"k{i}") for i in range(3)]
    samples = [sample(T0 - 600, "c1"), sample(T0 - 300, "c2"), sample(T0, "c3")]
    assert dynamic_eval.divergence(rule_of(DIVERGENCE), data_with(rows), samples) == []


def test_unanswered_flows_are_not_evidence():
    samples = [sample(T0 - 600, "c1"), sample(T0 - 300, "c2"), sample(T0, "c3")]
    assert dynamic_eval.divergence(rule_of(DIVERGENCE), data_with([flow(state="S0", ts=T0 - 1000)]), samples) == []


def test_icmp_compared_without_port():
    samples = [sample(T0 - 600, "c1"), sample(T0 - 300, "c2"), sample(T0, "c3", [(C2, "icmp", None)])]
    rows = [flow(proto="icmp", port=8, ts=T0 - 1000, state="OTH")]
    assert dynamic_eval.divergence(rule_of(DIVERGENCE), data_with(rows), samples) == []
    assert [v.object_key for v in dynamic_eval.divergence(rule_of(DIVERGENCE), data_with(rows), samples[:2] + [
        sample(T0, "c3")])] == [f"{C2}/icmp"]


def test_unanswered_icmp_is_not_evidence():
    samples = [sample(T0 - 600, "c1"), sample(T0 - 300, "c2"), sample(T0, "c3")]
    row = {**flow(proto="icmp", port=8, ts=T0 - 1000, state="OTH"), "resp_pkts": 0}
    assert dynamic_eval.divergence(rule_of(DIVERGENCE), data_with([row]), samples) == []


def test_icmp_divergence_through_zeek_file(lab, clock):  # noqa: F811
    """Ping z routera przy notrack: Zeek widzi ICMP (OTH), tablica go nie ma."""
    lab.zeek("conn", [flow(proto="icmp", port=0, ts=T0 - 60, duration=7200, state="OTH")])
    for _ in range(3):
        assert cycle(lab, clock) == 0
        clock.later()
    assert [f["evidence"]["l2_observation"]["dport"] for f in base.only(lab.reports(), DIVERGENCE)] == [None]


@pytest.mark.parametrize("name,suspicious", [
    ("xk3q9vbz7lmw2rtp.com", True),
    ("www.wikipedia.org", False),
    ("news.ycombinator.com", False),
    ("100.120.250.142.in-addr.arpa", False),
    ("xk3q9vbz7lmw2rtp.in-addr.arpa", False),
    ("aaaaaaaaaaaaaaaa.com", False),
    ("xk3q9vbz7lmw2rtp.cdn.example", False),
])
def test_dga_name(name, suspicious):
    cond = rule_of(DGA)["assert"]
    assert dynamic_eval.suspicious_name(name, cond, ["cdn.example"]) is suspicious


def test_dga_needs_distinct_names():
    rule = rule_of(DGA)
    two = data_with(dns=[query(n, uid=n) for n in DGA_NAMES[:2]] * 3)
    assert dynamic_eval.dga(rule, two, []) == []
    found = dynamic_eval.dga(rule, data_with(dns=[query(n, uid=n) for n in DGA_NAMES]), [])
    assert [v.object_key for v in found] == ["1.1.1.1"]
    assert found[0].detail["names"] == sorted(DGA_NAMES)


def test_rogue_resolver_per_resolver():
    rows = [query("example.com", "8.8.8.8", uid="a"), query("example.org", "8.8.8.8", uid="b"),
            query("github.com", "1.1.1.1", uid="c")]
    found = dynamic_eval.rogue_resolver(rule_of(ROGUE), data_with(dns=rows), {"1.1.1.1", "9.9.9.9"})
    assert [(v.object_key, v.evidence["l2_observation"]["flow_count"]) for v in found] == [("8.8.8.8", 2)]


# --- pełny cykl ---
def test_rogue_resolver_alert_in_report(lab, clock):  # noqa: F811
    lab.zeek("dns", [query("example.com", "8.8.8.8")])
    assert cycle(lab, clock) == 0
    rep = lab.reports()[-1]
    assert validate.validate_report(rep, ["10.200.2.0/24"]) == []
    finding = base.only([rep], ROGUE)[0]
    assert finding["phase"] == "dynamic" and finding["ioc"] is True
    assert finding["evidence"]["type"] == "behavioral"
    assert finding["evidence"]["l2_observation"]["destination"] == "8.8.8.8"
    assert finding["fingerprint"] == fingerprint(ROGUE, "/zeek/dns", "8.8.8.8")
    assert base.action_of(rep, finding)["type"] == "alert"
    assert rep["verdict"]["posture"] == "compromise-suspected"
    assert rep["collection"]["l2"]["status"] == "degraded"


def test_dga_names_stay_local(lab, clock):  # noqa: F811
    lab.zeek("dns", [query(n, uid=n) for n in DGA_NAMES])
    assert cycle(lab, clock) == 0
    rep = lab.reports()[-1]
    assert base.only([rep], DGA)
    assert not any(n in json.dumps(rep) for n in DGA_NAMES)
    run_id = rep["run"]["run_id"]
    stored = json.loads((lab.out / "evidence" / run_id / "zeek.json").read_text(encoding="utf-8"))
    assert stored["findings"][0]["names"] == sorted(DGA_NAMES)


def test_divergence_after_three_cycles(lab, clock):  # noqa: F811
    lab.zeek("conn", [flow(ts=T0 - 60, duration=7200)])
    for _ in range(2):
        assert cycle(lab, clock) == 0
        clock.later()
    assert all(not base.only([r], DIVERGENCE) for r in lab.reports())
    assert cycle(lab, clock) == 0
    rep = lab.reports()[-1]
    finding = base.only([rep], DIVERGENCE)[0]
    assert finding["trust"] == {"observed_by": ["L2"], "corroborated_by": [], "contradicted_by": ["L1"],
                                "divergence": True}
    assert finding["evidence"]["l2_observation"]["dport"] == 8443
    assert validate.validate_report(rep) == []


def test_target_in_table_is_not_divergence(lab, clock):  # noqa: F811
    lab.zeek("conn", [flow(ts=T0 - 60, duration=7200)])
    table = [{"protocol": "tcp", "src-address": "10.200.2.199:40000", "dst-address": f"{C2}:8443",
              "reply-src-address": f"{C2}:8443"}]
    data = router(ip__firewall__connection=table)
    for _ in range(4):
        assert cycle(lab, clock, data) == 0
        clock.later()
    assert all(not base.only([r], DIVERGENCE) for r in lab.reports())
    ring = json.loads((lab.out / cli.SAMPLES_FILE).read_text(encoding="utf-8"))
    assert len(ring) == 12 and "10.200" not in json.dumps(ring)


def test_finding_resolves_after_window(lab, clock):  # noqa: F811
    lab.zeek("dns", [query("example.com", "8.8.8.8")])
    assert cycle(lab, clock) == 0
    clock.later(1800)
    assert cycle(lab, clock) == 0
    assert len(lab.reports()) == 1
    clock.later(1900)
    assert cycle(lab, clock) == 0
    resolved = lab.reports()[-1]["resolved"]
    assert [(r["rule"], r["resolved_by"]) for r in resolved] == [(ROGUE, "external-change")]


def test_unreadable_zeek_keeps_open_findings(lab, clock):  # noqa: F811
    lab.zeek("dns", [query("example.com", "8.8.8.8")])
    assert cycle(lab, clock) == 0
    (lab.zeek_current / "dns.log").unlink()
    (lab.zeek_current / "conn.log").unlink()
    lab.zeek_current.rmdir()
    clock.later(7200)
    assert cycle(lab, clock) == 0
    rep = lab.reports()[-1]
    assert rep["resolved"] == [] and rep["collection"]["l2"]["status"] == "unavailable"
    assert "l2.read-failed" in base.error_codes(rep)
    assert [f["rule"] for f in lab.state()["open_findings"]] == [ROGUE]


def test_tracking_disabled_leaves_divergence_unevaluated(lab, clock):  # noqa: F811
    lab.zeek("conn", [flow(ts=T0 - 60, duration=7200)])
    data = router(ip__firewall__connection__tracking=[{"enabled": "no"}])
    for _ in range(3):
        assert cycle(lab, clock, data) == 0
        clock.later()
    rep = lab.reports()[-1]
    assert rep["findings"] == []
    assert "śledzenie połączeń routera wyłączone" in rep["collection"]["l2"]["note"]
    assert base.error_codes(rep) == set()


def test_connection_read_failure_is_error(lab, clock):  # noqa: F811
    data = router(ip__firewall__connection=base.TrapError("brak uprawnień"))
    assert cycle(lab, clock, data) == 0
    assert "l1.connections-failed" in base.error_codes(lab.reports()[-1])


def test_missing_wan_address_makes_l2_unavailable(lab, clock):  # noqa: F811
    inventory = yaml.safe_load((lab.site / "routers/r2/inventory.yml").read_text(encoding="utf-8"))
    del inventory["addressing"]["wan_address"]
    lab.write_site("routers/r2/inventory.yml", yaml.safe_dump(inventory))
    assert cycle(lab, clock) == 0
    rep = lab.reports()[-1]
    assert rep["collection"]["l2"]["status"] == "unavailable"
    assert "l2.attribution-unavailable" in base.error_codes(rep)


def test_invalid_dynamic_baseline_skips_resolver_rule(lab, clock):  # noqa: F811
    lab.write_site("routers/r2/dynamic-baseline.yml", "- lista\n")
    lab.zeek("dns", [query("example.com", "8.8.8.8")])
    assert cycle(lab, clock) == 0
    rep = lab.reports()[-1]
    assert "dynamic-baseline.invalid" in base.error_codes(rep)
    assert not base.only([rep], ROGUE)
    assert rep["collection"]["l1"]["status"] == "ok"


def test_ioc_holds_remediation(full):  # noqa: F811
    full.lab.zeek("dns", [query("example.com", "8.8.8.8", ts=full.now.timestamp() - 30)])
    sim = Sim(router(**base.SOCKS_ON))
    assert full.full(sim, "--publish-branch", "test/x") == 0
    assert sim.writes == []
    rep = full.reports("test/x")[-1]
    action = next(a for a in rep["actions"] if a["type"] == "auto-remediate")
    assert action["status"] == "skipped" and "otwarty wskaźnik kompromitacji" in action["reason"]
    assert next(a for a in rep["actions"] if a["type"] == "alert")["status"] == "succeeded"

"""RITA (ClickHouse) i TI (OTX): klienci, detektor beaconów, allowlista, potwierdzenie L3."""
import base64
import json
import urllib.error
from datetime import datetime, timedelta, timezone

import pytest
import yaml

import test_agent as base
import oracle_eval as oe
import validate_report as validate
from test_agent import WAN, MockApi, lab, router  # noqa: F401
from agent import __main__ as cli
from agent import dynamic_eval, l2_rita, l3_ti

START = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)
T0 = START.timestamp()
C2 = "203.0.113.9"
BEACON = "policy.dynamic.beacon"
ROGUE = "policy.dynamic.rogue-resolver"
ENTRIES = yaml.safe_load(open(base.ROOT / "examples/dynamic-baseline.yml"))["beaconing"]["allowed_periodic"]


class Clock:
    def __init__(self):
        self.now = START

    def __call__(self):
        return self.now

    def later(self, seconds=300):
        self.now += timedelta(seconds=seconds)


def row(dst=C2, ports=("8443:tcp:",), score=0.95, src=WAN, fqdn="", kind="ip", count=60):
    return {"src": f"::ffff:{src}", "dst": f"::ffff:{dst}", "fqdn": fqdn, "server_ips": [],
            "port_proto_service": list(ports), "beacon_type": kind, "beacon_score": score,
            "count": count, "total_bytes": 4096, "last_seen": int(T0)}


class FakeRita:
    """Odpowiada jak ClickHouse: ostatni import i wiersze threat_mixtape."""

    def __init__(self, rows=(), import_id="AB12", ended=T0 - 600, fail=None):
        self.rows = list(rows)
        self.import_id = import_id
        self.ended = ended
        self.fail = fail
        self.beacon_queries = 0

    def query(self, sql):
        if self.fail:
            raise l2_rita.RitaError(self.fail)
        if "metadatabase.imports" in sql:
            return [{"id": self.import_id, "ended": self.ended, "since": self.ended - 86400, "until": self.ended}]
        assert "ORDER BY analyzed_at DESC, beacon_score DESC LIMIT 1 BY hash" in sql
        assert f"last_seen >= toDateTime({int(self.ended - 86400)})" in sql
        assert sql.index("LIMIT 1 BY hash") < sql.index("beacon_score > 0")
        self.beacon_queries += 1
        return [dict(r) for r in self.rows]


class FakeTi:
    def __init__(self, pulses=0, fail=None):
        self.pulses = pulses
        self.fail = fail
        self.calls = []

    def lookup(self, ip):
        self.calls.append(ip)
        if self.fail:
            raise l3_ti.TiError(self.fail)
        return {"validation": [], "pulse_info": {"count": self.pulses,
                                                 "pulses": [{"tags": ["C2", "Mirai botnet"]}] * self.pulses}}


def cycle(lab, clock, rita, ti=None, data=None):  # noqa: F811
    data = router() if data is None else data
    return cli.main(["--router", "r2", "--once", "--dry-run"], paths=lab.paths, clock=clock,
                    connector=lambda ctx, password: MockApi(data), rita=lambda ctx: rita,
                    ti=(lambda ctx: ti) if ti else None)


@pytest.fixture
def clock():
    return Clock()


def with_allowlist(lab):  # noqa: F811
    doc = dict(base.DYNAMIC_BASELINE, beaconing={"allowed_periodic": ENTRIES})
    lab.write_site("routers/r2/dynamic-baseline.yml", yaml.safe_dump(doc))


def dns_answer(name, ip, ts=T0 - 60):
    return {"ts": f"{ts:.6f}", "uid": "D1", "id.orig_h": "192.168.20.21", "id.orig_p": 5300, "id.resp_h": "1.1.1.1",
            "id.resp_p": 53, "proto": "udp", "query": name, "qtype_name": "A", "answers": f"{name},{ip}"}


# --- ClickHouse ---
class Response:
    def __init__(self, body):
        self.body = body

    def read(self):
        return self.body.encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_clickhouse_sends_auth_and_json_format():
    seen = {}

    def opener(request, timeout):
        seen.update(body=request.data.decode(), auth=request.headers["Authorization"], timeout=timeout)
        return Response('{"a": 1}\n{"a": 2}\n')

    assert l2_rita.ClickHouse("HASLO-CH", opener=opener).query("SELECT 1") == [{"a": 1}, {"a": 2}]
    assert seen["body"].endswith("FORMAT JSONEachRow") and seen["timeout"] == l2_rita.TIMEOUT_S
    assert base64.b64decode(seen["auth"].split()[1]).decode() == "soho_agent:HASLO-CH"


def test_clickhouse_error_hides_password():
    def opener(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 516, "auth", {}, None)

    with pytest.raises(l2_rita.RitaError) as exc:
        l2_rita.ClickHouse("HASLO-CH", opener=opener).query("SELECT 1")
    assert "HASLO" not in str(exc.value)


def test_ipv4_mapped_addresses():
    assert l2_rita.ipv4("::ffff:192.168.20.21") == "192.168.20.21"
    assert l2_rita.ipv4("2001:db8::1") is None


def test_beacons_only_for_router():
    rita = FakeRita([row(), row(src="192.168.20.21")])
    rows = l2_rita.beacons(rita, rita.ended - 86400, WAN)
    assert [(r["src"], r["dst"]) for r in rows] == [(WAN, C2)]


def test_no_finished_import():
    class Empty:
        def query(self, sql):
            return []
    assert l2_rita.collect(Empty(), WAN, None) is None


def test_beacons_queried_once_per_import(tmp_path):
    rita = FakeRita([row()])
    cache = tmp_path / "rita.json"
    data = l2_rita.collect(rita, WAN, cache)
    l2_rita.save(data, WAN, cache, lambda path, raw: path.write_bytes(raw))
    assert l2_rita.collect(rita, WAN, cache).rows == data.rows and rita.beacon_queries == 1
    rita.import_id = "CD34"
    assert l2_rita.collect(rita, WAN, cache).fresh_query and rita.beacon_queries == 2


# --- allowlista ---
@pytest.mark.parametrize("item,names,allowed", [
    (row(dst="193.70.94.182", ports=("123:udp:ntp",)), set(), True),               # "*" udp/123
    (row(dst="140.82.121.4", ports=("22:tcp:ssh",)), set(), True),                 # CIDR
    (row(dst="20.1.2.3", ports=("22:tcp:ssh",)), {"github.com"}, True),            # nazwa z dns.log
    (row(dst="20.1.2.3", ports=("22:tcp:ssh",)), {"lb-1.github.com"}, True),       # poddomena
    (row(dst="20.1.2.3", ports=("22:tcp:ssh",)), {"github.com.evil.example"}, False),
    (row(dst="20.1.2.3", ports=("22:tcp:ssh",)), {"evilgithub.com"}, False),
    (row(dst="20.1.2.3", ports=("22:tcp:ssh",)), set(), False),
    (row(dst="140.82.121.4", ports=("22:tcp:ssh", "443:tcp:ssl")), set(), False),  # każdy port musi pasować
    (row(dst="140.82.121.4", ports=()), set(), False),
])
def test_allowed_periodic(item, names, allowed):
    data = dict(item, dst=l2_rita.ipv4(item["dst"]))
    assert dynamic_eval.allowed_periodic(data, ENTRIES, names) is allowed


# --- pełny cykl: beacon ---
def test_beacon_finding_with_full_coverage(lab, clock):  # noqa: F811
    with_allowlist(lab)
    rita = FakeRita([row(), row(dst="193.70.94.182", ports=("123:udp:ntp",), score=0.98)])
    assert cycle(lab, clock, rita) == 0
    rep = lab.reports()[-1]
    assert validate.validate_report(rep) == []
    finding = base.only([rep], BEACON)[0]
    obs = finding["evidence"]["l2_observation"]
    assert (obs["destination"], obs["dport"], obs["proto"], obs["score"]) == (C2, 8443, "tcp", 0.95)
    assert rep["collection"]["l2"] == {"required": True, "status": "ok", "sources": ["zeek", "rita"],
                                       "window": rep["collection"]["l2"]["window"]}
    assert rep["verdict"] == {**rep["verdict"], "posture": "compromise-suspected", "coverage": "full"}
    manifest = yaml.safe_load((base.ROOT / "scenarios/dynamic/dynamic-c2-beacon.yml").read_text(encoding="utf-8"))
    assert oe.oracle_eval(manifest, rep, lab.state()) == []


def test_clean_router_with_rita_has_no_violations(lab, clock):  # noqa: F811
    assert cycle(lab, clock, FakeRita()) == 0
    rep = lab.reports()[-1]
    assert rep["verdict"]["posture"] == "no-violations" and rep["verdict"]["coverage"] == "full"


def test_heartbeat_allowed_by_name_from_dns_log(lab, clock):  # noqa: F811
    with_allowlist(lab)
    rita = FakeRita([row(dst="20.1.2.3", ports=("22:tcp:ssh",), score=0.9)])
    assert cycle(lab, clock, rita) == 0
    assert [f["evidence"]["l2_observation"]["destination"] for f in base.only(lab.reports(), BEACON)] == ["20.1.2.3"]
    clock.later()
    lab.zeek("dns", [dns_answer("github.com", "20.1.2.3")])
    rita = FakeRita([row(dst="20.1.2.3", ports=("22:tcp:ssh",), score=0.9)])
    assert cycle(lab, clock, rita) == 0
    assert not base.only(lab.reports(), BEACON)


def test_finding_kept_between_imports_and_resolved_by_new_one(lab, clock):  # noqa: F811
    rita = FakeRita([row()])
    assert cycle(lab, clock, rita) == 0
    clock.later()
    assert cycle(lab, clock, rita) == 0
    assert rita.beacon_queries == 1 and len(lab.reports()) == 1
    rita.import_id, rita.rows, rita.ended = "CD34", [], T0 + 3000
    clock.later(3000)
    assert cycle(lab, clock, rita) == 0
    assert [(r["rule"], r["resolved_by"]) for r in lab.reports()[-1]["resolved"]] == [(BEACON, "external-change")]


def test_stale_import_degrades_l2(lab, clock):  # noqa: F811
    assert cycle(lab, clock, FakeRita(ended=T0 - 3 * 3600)) == 0
    l2 = lab.reports()[-1]["collection"]["l2"]
    assert l2["status"] == "degraded" and "starszy niż 2 h" in l2["note"]


def test_rita_failure_keeps_open_beacon(lab, clock):  # noqa: F811
    assert cycle(lab, clock, FakeRita([row()])) == 0
    clock.later()
    assert cycle(lab, clock, FakeRita(fail="ClickHouse HTTP 503")) == 0
    rep = lab.reports()[-1]
    assert "l2.rita-failed" in base.error_codes(rep) and rep["resolved"] == []
    assert [f["rule"] for f in lab.state()["open_findings"]] == [BEACON]


# --- TI ---
@pytest.mark.parametrize("doc,expected", [
    ({"validation": [{"source": "whitelist"}], "pulse_info": {"count": 9}}, "benign"),
    ({"validation": [], "pulse_info": {"count": 3}}, "malicious"),
    ({"validation": [], "pulse_info": {"count": 1}}, "suspicious"),
    ({"validation": [], "pulse_info": {"count": 0}}, "unknown"),
])
def test_otx_verdict(doc, expected):
    assert l3_ti.verdict(doc)["verdict"] == expected


def test_otx_categories_are_identifiers():
    doc = {"pulse_info": {"count": 1, "pulses": [{"tags": ["C2 Server", "Mirai!", "c2-server", "  "]}]}}
    assert l3_ti.verdict(doc)["categories"] == ["c2-server", "mirai"]


def test_read_key_formats(tmp_path):
    for text in ("OTX_API_KEY=abc\n", "export OTX_API_KEY='abc'\n", "# x\nOTX_API_KEY=\"abc\"\n"):
        (tmp_path / "ti.env").write_text(text, encoding="utf-8")
        assert l3_ti.read_key(tmp_path / "ti.env") == "abc"
    (tmp_path / "ti.env").write_text("INNY=1\n", encoding="utf-8")
    with pytest.raises(l3_ti.TiError):
        l3_ti.read_key(tmp_path / "ti.env")


class Connection:
    seen = {}

    def __init__(self, host, timeout, source_address):
        Connection.seen.update(host=host, source=source_address)

    def request(self, method, path, headers):
        Connection.seen.update(path=path, key=headers["X-OTX-API-KEY"])

    def getresponse(self):
        class R:
            status = Connection.status

            def read(self):
                return b'{"pulse_info": {"count": 0}}'
        return R()

    def close(self):
        pass


def test_otx_client_binds_source_and_hides_key():
    Connection.status = 200
    client = l3_ti.OtxClient("KLUCZ-OTX", "10.100.2.10", connection=Connection)
    assert client.lookup("8.8.8.8") == {"pulse_info": {"count": 0}}
    assert Connection.seen == {"host": "otx.alienvault.com", "source": ("10.100.2.10", 0),
                               "path": "/api/v1/indicators/IPv4/8.8.8.8/general", "key": "KLUCZ-OTX"}
    Connection.status = 403
    with pytest.raises(l3_ti.TiError) as exc:
        client.lookup("8.8.8.8")
    assert "KLUCZ" not in str(exc.value)


def test_ti_cache_and_private_targets(tmp_path):
    ti = FakeTi(pulses=3)
    write = lambda path, raw: path.write_bytes(raw)  # noqa: E731
    first = l3_ti.corroborate({"8.8.8.8", "192.168.10.5"}, lambda: ti, tmp_path / "c.json", T0, write)
    assert first.verdicts["8.8.8.8"]["verdict"] == "malicious" and "192.168.10.5" not in first.verdicts
    l3_ti.corroborate({"8.8.8.8"}, lambda: ti, tmp_path / "c.json", T0 + 3600, write)
    assert ti.calls == ["8.8.8.8"]
    l3_ti.corroborate({"8.8.8.8"}, lambda: ti, tmp_path / "c.json", T0 + 90000, write)
    assert ti.calls == ["8.8.8.8", "8.8.8.8"]


def rogue_query():
    return {"ts": f"{T0 - 30:.6f}", "uid": "R1", "id.orig_h": WAN, "id.orig_p": 5300, "id.resp_h": "8.8.8.8",
            "id.resp_p": 53, "proto": "udp", "query": "example.com", "qtype_name": "A"}


def test_ti_corroborates_dynamic_finding(lab, clock):  # noqa: F811
    lab.zeek("dns", [rogue_query()])
    ti = FakeTi(pulses=5)
    assert cycle(lab, clock, FakeRita(), ti) == 0
    rep = lab.reports()[-1]
    assert validate.validate_report(rep) == []
    finding = base.only([rep], ROGUE)[0]
    assert finding["trust"]["corroborated_by"] == ["L3"]
    assert finding["evidence"]["l3_corroboration"] == {"provider": "otx", "verdict": "malicious",
                                                       "categories": ["c2", "mirai-botnet"]}
    assert rep["collection"]["l3"] == {"required": False, "status": "ok", "sources": ["otx"]}


def test_ti_failure_never_creates_finding(lab, clock):  # noqa: F811
    lab.zeek("dns", [rogue_query()])
    assert cycle(lab, clock, FakeRita(), FakeTi(fail="OTX HTTP 503")) == 0
    rep = lab.reports()[-1]
    finding = base.only([rep], ROGUE)[0]
    assert "l3_corroboration" not in finding["evidence"] and finding["trust"]["corroborated_by"] == []
    assert rep["collection"]["l3"]["status"] == "degraded" and "l3.lookup-failed" in base.error_codes(rep)
    assert [f["rule"] for f in rep["findings"]] == [ROGUE]
    assert rep["verdict"]["coverage"] == "full"


def test_dga_resolver_is_not_checked_in_ti(lab, clock):  # noqa: F811
    names = ["xk3q9vbz7lmw2rtp.com", "p8fj2mzq4wnx7ctb.net", "h5rq0zvt3kxm9bwd.org"]
    lab.zeek("dns", [{**rogue_query(), "id.resp_h": "1.1.1.1", "query": n, "uid": n} for n in names])
    ti = FakeTi(pulses=5)
    assert cycle(lab, clock, FakeRita(), ti) == 0
    assert base.only(lab.reports(), "policy.dynamic.dga") and ti.calls == []


def test_empty_last_import_keeps_beacon(lab, clock):  # noqa: F811
    """Węzeł 2026-11-08: import bez wierszy. Wynik to najnowsza ocena pary w oknie, więc
    beacon nie znika, gdy ostatni import go nie przeliczył."""
    rita = FakeRita([row()])
    assert cycle(lab, clock, rita) == 0
    rita.import_id, rita.ended = "CD34", T0 + 3000
    clock.later(3000)
    assert cycle(lab, clock, rita) == 0
    assert rita.beacon_queries == 2 and len(lab.reports()) == 1
    assert [f["rule"] for f in lab.state()["open_findings"]] == [BEACON]


def test_rita_cache_written_only_after_new_import(lab, clock):  # noqa: F811
    rita = FakeRita([row()])
    assert cycle(lab, clock, rita) == 0
    cache = json.loads((lab.out / l2_rita.CACHE_FILE).read_text(encoding="utf-8"))
    assert cache["import_id"] == "AB12" and cache["wan"] == WAN and len(cache["rows"]) == 1


def test_ntp_pool_without_allowlist_is_beacon(lab, clock):  # noqa: F811
    """Bez wpisu * udp/123 pula NTP (wynik RITA ~0,98) daje finding: allowlista jest konieczna."""
    assert cycle(lab, clock, FakeRita([row(dst="193.70.94.182", ports=("123:udp:ntp",), score=0.98)])) == 0
    assert base.only(lab.reports(), BEACON)


def test_unknown_verdict_is_evidence_only(lab, clock):  # noqa: F811
    lab.zeek("dns", [rogue_query()])
    assert cycle(lab, clock, FakeRita(), FakeTi(pulses=0)) == 0
    finding = base.only(lab.reports(), ROGUE)[0]
    assert finding["evidence"]["l3_corroboration"]["verdict"] == "unknown"
    assert finding["trust"]["corroborated_by"] == []

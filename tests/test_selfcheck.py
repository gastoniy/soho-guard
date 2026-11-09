"""Samokontrola czujników L2 (iteracja 6): obniża pokrycie, nigdy nie tworzy findingu."""
import gzip
import os

import pytest

import test_agent as base
from test_agent import WAN, lab, router, zeek_text  # noqa: F401
from test_l3 import T0, Clock, FakeRita, cycle, rogue_query, row  # noqa: F401
from agent import selfcheck

ROGUE = "policy.dynamic.rogue-resolver"
ADDRESSES = [{"address": f"{WAN}/24", "interface": "ether1-wan"}, {"address": "10.100.2.1/24", "interface": "vlan-mgmt"}]


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def strict(monkeypatch):
    monkeypatch.setattr(selfcheck, "REQUIRE_ROUTER_TRAFFIC", True)
    monkeypatch.setattr(selfcheck, "REQUIRE_CAPTURE_LOSS", True)


def loss_row(ts=T0 - 300, acks=2000, lost=0.1):
    return {"ts": f"{ts:.6f}", "ts_delta": "900.0", "peer": "zeek", "gaps": "2", "acks": str(acks),
            "percent_lost": str(lost)}


def write_loss(lab, *rows):  # noqa: F811
    lab.zeek("capture_loss", list(rows))


def background(lab):  # noqa: F811
    """Ruch routera w oknie, jak NTP i DNS na prawdziwym łączu."""
    lab.zeek("dns", [{**rogue_query(), "id.resp_h": "1.1.1.1", "query": "pool.ntp.org", "uid": "B1"}])


# --- atrybucja (e) ---
@pytest.mark.parametrize("state,reason", [
    (None, None),
    ({}, None),                                                             # menu nieodczytane
    ({"ip_addresses": ADDRESSES}, None),
    ({"ip_addresses": ADDRESSES[1:]}, "nie ma adresu"),
    ({"ip_addresses": [dict(ADDRESSES[0], disabled=True)]}, "nie ma adresu"),
    ({"ip_addresses": ADDRESSES, "dhcp_clients": [{"interface": "ether1-wan", "disabled": False}]}, "klient DHCP"),
    ({"ip_addresses": ADDRESSES, "dhcp_clients": [{"interface": "ether1-wan", "disabled": True}]}, None),
    ({"ip_addresses": ADDRESSES, "dhcp_clients": [{"interface": "vlan-users", "disabled": False}]}, None),
])
def test_attribution(state, reason):
    found = selfcheck.attribution(state, WAN)
    assert (found is None) if reason is None else (reason in found)


# --- utrata pakietów (b) ---
def test_capture_loss_ok(lab):  # noqa: F811
    write_loss(lab, loss_row())
    result = selfcheck.SelfCheck()
    selfcheck.capture_loss(lab.paths.zeek_dir, T0, result)
    assert result.errors == [] and result.info == []


@pytest.mark.parametrize("rows,code,info", [
    ([loss_row(lost=2.5)], "selfcheck.capture-loss", False),
    ([loss_row(acks=40, lost=10.0)], None, True),                            # za mało ruchu TCP
    ([loss_row(ts=T0 - 3600)], "selfcheck.capture-loss", False),             # wpis starszy niż 30 min
    ([], "selfcheck.capture-loss", False),                                   # plik bez wpisów
])
def test_capture_loss_cases(lab, rows, code, info):  # noqa: F811
    write_loss(lab, *rows)
    result = selfcheck.SelfCheck()
    selfcheck.capture_loss(lab.paths.zeek_dir, T0, result)
    assert [c for c, _ in result.errors] == ([code] if code else [])
    assert bool(result.info) is info


def test_capture_loss_from_archive_after_rotation(lab):  # noqa: F811
    day = lab.paths.zeek_dir / "2026-11-08"
    day.mkdir()
    path = day / "capture_loss.11:00:00-12:00:00.log.gz"
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        handle.write(zeek_text("capture_loss", [loss_row(lost=3.0)]))
    os.utime(path, (T0 - 60, T0 - 60))
    result = selfcheck.SelfCheck()
    selfcheck.capture_loss(lab.paths.zeek_dir, T0, result)
    assert "3.00%" in result.errors[0][1]


# --- pełny cykl ---
def test_clean_strict_cycle_is_ok(lab, clock, strict):  # noqa: F811
    background(lab)
    write_loss(lab, loss_row())
    assert cycle(lab, clock, FakeRita()) == 0
    rep = lab.reports()[-1]
    assert rep["collection"]["l2"]["status"] == "ok" and rep["verdict"]["coverage"] == "full"
    assert base.error_codes(rep) == set()


def test_low_tcp_volume_is_info_only(lab, clock, strict):  # noqa: F811
    background(lab)
    write_loss(lab, loss_row(acks=40, lost=10.0))
    assert cycle(lab, clock, FakeRita()) == 0
    l2 = lab.reports()[-1]["collection"]["l2"]
    assert l2["status"] == "ok" and "za mało ruchu TCP" in l2["note"]


def test_capture_loss_degrades_without_finding(lab, clock, strict):  # noqa: F811
    background(lab)
    write_loss(lab, loss_row(lost=4.0))
    assert cycle(lab, clock, FakeRita()) == 0
    rep = lab.reports()[-1]
    assert rep["collection"]["l2"]["status"] == "degraded" and rep["verdict"]["coverage"] == "partial"
    assert "selfcheck.capture-loss" in base.error_codes(rep) and rep["findings"] == []
    assert rep["verdict"]["posture"] == "inconclusive"


def test_stale_conn_log_keeps_open_findings(lab, clock):  # noqa: F811
    lab.zeek("dns", [rogue_query()])
    assert cycle(lab, clock, FakeRita()) == 0
    clock.later(7200)
    old = clock().timestamp() - 2000
    os.utime(lab.zeek_current / "conn.log", (old, old))
    assert cycle(lab, clock, FakeRita()) == 0
    rep = lab.reports()[-1]
    assert "selfcheck.zeek-stale" in base.error_codes(rep) and rep["resolved"] == []
    assert rep["collection"]["l2"]["status"] == "degraded"
    assert [f["rule"] for f in lab.state()["open_findings"]] == [ROGUE]


def test_no_router_traffic_blocks_zeek_rules(lab, clock, strict):  # noqa: F811
    write_loss(lab, loss_row())
    assert cycle(lab, clock, FakeRita()) == 0
    rep = lab.reports()[-1]
    assert "selfcheck.no-router-traffic" in base.error_codes(rep)
    assert "nie oceniono" in rep["collection"]["l2"]["note"] and rep["verdict"]["coverage"] == "partial"


def test_wan_mismatch_disables_l2_and_rita(lab, clock):  # noqa: F811
    rita = FakeRita([row()])
    lab.zeek("dns", [rogue_query()])
    assert cycle(lab, clock, rita, data=router(ip__address=ADDRESSES[1:])) == 0
    rep = lab.reports()[-1]
    assert rep["collection"]["l2"]["status"] == "unavailable" and "atrybucja niepewna" in rep["collection"]["l2"]["note"]
    assert "selfcheck.wan-mismatch" in base.error_codes(rep)
    # Zmiana adresu to też drift (faza statyczna); L2 nie ocenia niczego.
    assert [f["phase"] for f in rep["findings"]] == ["static"] and rita.beacon_queries == 0


def test_dhcp_on_wan_disables_l2(lab, clock):  # noqa: F811
    data = router()
    data[("ip", "dhcp-client")] = [{"interface": "ether1-wan", "disabled": False}]
    assert cycle(lab, clock, FakeRita(), data=data) == 0
    assert "selfcheck.wan-mismatch" in base.error_codes(lab.reports()[-1])

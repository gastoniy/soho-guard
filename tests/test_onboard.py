import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import mikrotik_onboard as ob


class MockApi:
    """Imituje librouteros: .path(*parts) -> lista dict-ów."""
    def __init__(self, data): self.data = data          # {('ip','socks'): [...]}
    def path(self, *parts):
        if parts not in self.data:
            raise KeyError("/".join(parts) + ": no such command")  # jak brak menu (v6 wireguard)
        return [dict(x) for x in self.data[parts]]
    def close(self): pass


CLEAN = {
    ("system", "identity"): [{"name": "R2"}],
    ("system", "resource"): [{"version": "6.49.19 (long-term)", "uptime": "1d", "cpu-load": 3}],
    ("ip", "socks"): [{".id": "*1", "enabled": "false"}],
    ("ip", "service"): [
        {".id": "*1", "name": "winbox", "disabled": "false", "address": "10.100.2.0/24"},
        {".id": "*2", "name": "telnet", "disabled": "true"},
    ],
    ("user",): [{".id": "*1", "name": "admin", "disabled": "true"},
                {".id": "*2", "name": "monitor", "disabled": "false"}],
    ("ip", "route"): [{"dst-address": "0.0.0.0/0", "gateway": "ether1-wan"}],
    ("ip", "address"): [{"address": "192.168.20.22/24", "network": "192.168.20.0", "interface": "ether1-wan"}],
    ("interface",): [{"name": "ether1-wan", "mac-address": "AA:BB:CC:00:00:01"}],
    ("system", "scheduler"): [],
}

COMPROMISED = dict(CLEAN)
COMPROMISED[("ip", "socks")] = [{".id": "*1", "enabled": "true", "port": 1080}]   # Mēris/Coinhive IOC
COMPROMISED[("ip", "service")] = [
    {".id": "*1", "name": "winbox", "disabled": "false", "address": ""},          # publiczny Winbox
]
COMPROMISED[("user",)] = [{".id": "*1", "name": "admin", "disabled": "false"}]    # domyślny admin aktywny

POLICY = [
    {"id": "policy.services.socks.disabled", "severity": "critical", "phase": "static",
     "check": {"path": "/ip/socks", "assert": {"enabled": "no"}}},
    {"id": "policy.mgmt.winbox.not-public", "severity": "critical", "phase": "static",
     "check": {"path": "/ip/service", "where": {"name": "winbox"}, "assert": {"address": {"private": True}}}},
    {"id": "policy.accounts.default-admin.disabled", "severity": "critical", "phase": "static",
     "check": {"path": "/user", "scope": "none-match", "assert": {"name": "admin", "disabled": "no"}}},
]


# --- przetwarzanie czyste ---
def test_coerce_and_volatile():
    e = ob.strip_volatile({".id": "*1", "enabled": "true", "uptime": "9d", "port": "1080"})
    assert e == {"enabled": True, "port": 1080}          # .id/uptime odcięte, typy znormalizowane

def test_fetch_skips_missing_menu():
    api = MockApi(CLEAN)   # brak ('interface','wireguard') -> pominięte, nie wyjątek
    raw = ob.fetch_resources(api)
    assert "socks" in raw and "wireguard_interfaces" not in raw

def test_build_state_deterministic():
    s1 = ob.build_state(ob.fetch_resources(MockApi(CLEAN)))
    s2 = ob.build_state(ob.fetch_resources(MockApi(CLEAN)))
    assert s1 == s2

def test_detect_profile():
    st = ob.build_state(ob.fetch_resources(MockApi(CLEAN)))
    assert ob.detect_profile(st) == "ros6"

def test_detect_wan():
    st = ob.build_state(ob.fetch_resources(MockApi(CLEAN)))
    wan = ob.detect_wan(st)
    assert wan["wan_address"] == "192.168.20.22/24"
    assert wan["wan_mac"] == "AA:BB:CC:00:00:01"

def test_scaffold_has_changeme_and_autodetect():
    st = ob.build_state(ob.fetch_resources(MockApi(CLEAN)))
    inv = ob.scaffold_inventory("site-042", st)
    assert inv["router_id"] == "CHANGE_ME"
    assert inv["addressing"]["mgmt_net"] == "CHANGE_ME"          # pole dla człowieka
    assert inv["profile"] == "ros6"                       # autodetekcja
    assert inv["addressing"]["wan_address"] == "192.168.20.22/24"
    assert inv["onboarding"]["firmware_reported"].startswith("6.49.19")

# --- weryfikacja onboardingu (ADR-003 krok 4) ---
def test_clean_device_no_violations():
    st = ob.build_state(ob.fetch_resources(MockApi(CLEAN)))
    assert ob.verify_against_policy(st, POLICY) == []

def test_compromised_device_flags_all_three():
    st = ob.build_state(ob.fetch_resources(MockApi(COMPROMISED)))
    v = ob.verify_against_policy(st, POLICY)
    ids = {f["rule"] for f in v}
    assert "policy.services.socks.disabled" in ids        # SOCKS włączony
    assert "policy.mgmt.winbox.not-public" in ids          # Winbox publiczny
    assert "policy.accounts.default-admin.disabled" in ids # admin aktywny

def test_private_predicate():
    assert ob._match_predicate("10.100.2.0/24", {"private": True})
    assert not ob._match_predicate("", {"private": True})
    assert not ob._match_predicate("0.0.0.0/0", {"private": True})


# --- pokrycie: każda reguła statyczna z policy/ musi mieć zbieraną ścieżkę ---
def test_all_static_policy_paths_collected():
    rules = ob.load_policy(Path(__file__).resolve().parents[1] / "policy")
    missing = [r["id"] for r in rules
               if r.get("phase") == "static" and "check" in r
               and r["check"]["path"] not in ob.PATH_TO_KEY]
    assert missing == [], f"reguły bez zbieranej ścieżki: {missing}"

def test_unevaluated_reported_when_menu_missing():
    state = ob.build_state(ob.fetch_resources(MockApi(CLEAN)))
    rule = {"id": "policy.mgmt.ssh.strong-crypto", "phase": "static",
            "check": {"path": "/ip/ssh", "assert": {"strong-crypto": "yes"}}}
    out = ob.unevaluated_rules(state, [rule])
    assert out and out[0]["rule"] == "policy.mgmt.ssh.strong-crypto"


def test_ca_file_requires_tls(capsys):
    with pytest.raises(SystemExit):
        ob.main(["--host", "x", "--user", "u", "--password", "p", "--site-id", "s", "--ca-file", "ca.crt"])
    assert "wymagają --tls" in capsys.readouterr().err


# --- RouterOS 7.20 (onboarding R1 TMP, 2026-10-30) ---
def test_detect_wan_v7_gateway_ip():
    st = {"routes": [{"dst-address": "0.0.0.0/0", "gateway": "192.168.20.1",
                      "immediate-gw": "192.168.20.1%ether1-wan", "active": True}],
          "ip_addresses": [{"address": "10.100.1.1/24", "interface": "vlan-mgmt"},
                           {"address": "192.168.20.21/24", "interface": "ether1-wan"}],
          "interfaces": [{"name": "ether1-wan", "mac-address": "0C:0F:E0:06:00:00"}]}
    w = ob.detect_wan(st)
    assert w == {"wan_interface_candidate": "ether1-wan",
                 "wan_address": "192.168.20.21/24", "wan_mac": "0C:0F:E0:06:00:00"}

def test_detect_wan_gateway_ip_without_immediate_gw():
    st = {"routes": [{"dst-address": "0.0.0.0/0", "gateway": "192.168.20.1"}],
          "ip_addresses": [{"address": "192.168.20.22/24", "interface": "ether1-wan"}],
          "interfaces": [{"name": "ether1-wan", "mac-address": "AA"}]}
    assert ob.detect_wan(st)["wan_interface_candidate"] == "ether1-wan"

def test_service_session_rows_dropped():
    raw = [{"name": "api", "port": "8728", "disabled": "false", "address": ""},
           {"name": "api", "connection": "true", "remote": "10.100.1.10:52866"}]
    assert ob.normalize(raw) == [{"name": "api", "port": 8728, "disabled": False, "address": ""}]

def test_runtime_counters_not_in_state():
    e = ob.strip_volatile({"name": "ether1", "fp-rx-byte": "5", "rx-drop": "1", "mtu": "1500"})
    assert e == {"name": "ether1", "mtu": 1500}


# --- neighbor discovery: not_one_of (2026-10-30) ---
ND_RULE = None
def _nd_rule():
    rules = ob.load_policy(Path(__file__).resolve().parents[1] / "policy")
    return [r for r in rules if r["id"] == "policy.mgmt.neighbor-discovery.restricted"]

@pytest.mark.parametrize("val,violated", [
    ("static", True), ("all", True), ("!dynamic", True), ("dynamic", True),
    ("", True), ("MGMT", False), ("LAN", False),
])
def test_nd_rule_not_one_of(val, violated):
    st = {"neighbor_discovery": [{"discover-interface-list": val}]}
    assert bool(ob.verify_against_policy(st, _nd_rule())) is violated


def test_onboarding_note_variants():
    assert ob.onboarding_note(0, 0).startswith("Brak naruszeń")
    assert "Wykryto 3 naruszeń" in ob.onboarding_note(3, 0)
    assert ob.onboarding_note(0, 2).startswith("Nie oceniono 2")
    assert "faza dynamiczna" in ob.onboarding_note(0, 0)


# --- repo instalacji z wieloma routerami (2026-11-01) ---
def test_scaffold_with_router_id():
    st = ob.build_state(ob.fetch_resources(MockApi(CLEAN)))
    inv = ob.scaffold_inventory("lab", st, router_id="r2")
    assert inv["site_id"] == "lab" and inv["router_id"] == "r2"
    assert inv["dynamic_baseline"] == "routers/r2/dynamic-baseline.yml"


def test_export_params_key_vs_password():
    k = ob.export_connect_params("10.100.1.1", "monitor", "pw", ssh_key="/etc/soho-guard/r1/monitor_rsa")
    assert k["use_keys"] and k["key_file"].endswith("monitor_rsa") and "password" not in k
    p = ob.export_connect_params("10.100.1.1", "breakglass", "pw")
    assert p["password"] == "pw" and "key_file" not in p


def test_inventory_policy_points_to_site_yml():
    st = ob.build_state(ob.fetch_resources(MockApi(CLEAN)))
    inv = ob.scaffold_inventory("lab", st, router_id="r1")
    assert inv["policy"] == {"universal_version_source": "site.yml"}

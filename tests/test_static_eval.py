import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.static_eval import check_rule, evaluate, object_keys  # noqa: E402


def rule(rid, path, asserts, where=None, severity="high", ioc=False, scope=None, phase="static"):
    check = {"path": path, "assert": asserts}
    if where:
        check["where"] = where
    if scope:
        check["scope"] = scope
    return {"id": rid, "severity": severity, "ioc": ioc, "phase": phase, "check": check}


SOCKS = rule("policy.services.socks.disabled", "/ip/socks", {"enabled": "no"})
WINBOX = rule("policy.mgmt.winbox.not-public", "/ip/service", {"address": {"private": True}}, where={"name": "winbox"})
ADMIN = rule("policy.accounts.default-admin.disabled", "/user", {"name": "admin", "disabled": "no"}, scope="none-match")


def rules_of(result):
    return {v.rule for v in result.violations}


# --- klucze obiektów ---
def test_key_singleton_is_last_path_segment():
    assert object_keys("socks", [{"enabled": False}]) == ["socks"]
    assert object_keys("neighbor_discovery", [{"x": 1}]) == ["discovery-settings"]


def test_key_named_row():
    assert object_keys("users", [{"name": "monitor"}, {"name": "ansible"}]) == ["monitor", "ansible"]


def test_key_repeated_name_uses_proto():
    rows = [{"name": "resolver", "proto": "tcp"}, {"name": "resolver", "proto": "udp"}]
    assert object_keys("services", rows) == ["resolver/tcp", "resolver/udp"]


def test_key_unnamed_row_is_content_hash_independent_of_ignored():
    a = {"chain": "input", "action": "drop", "comment": "stary"}
    b = {"chain": "input", "action": "drop", "comment": "nowy"}
    assert object_keys("firewall_filter", [a]) != object_keys("firewall_filter", [b])
    assert object_keys("firewall_filter", [a], {"comment"}) == object_keys("firewall_filter", [b], {"comment"})


def test_key_identical_rows_stay_distinct():
    row = {"chain": "input", "action": "drop"}
    keys = object_keys("firewall_filter", [row, dict(row)])
    assert len(set(keys)) == 2


# --- reguła check ---
def test_rule_violation_carries_only_asserted_attrs():
    check = check_rule(SOCKS, {"socks": [{"enabled": True, "port": 1080}]})
    assert check.evaluated
    v = check.violations[0]
    assert (v.object_key, v.expected, v.observed) == ("socks", {"enabled": "no"}, {"enabled": True})


def test_rule_where_without_row_is_unevaluated():
    check = check_rule(WINBOX, {"services": [{"name": "ssh"}]})
    assert not check.evaluated and "selektor" in check.reason


def test_rule_empty_singleton_is_unevaluated():
    assert not check_rule(SOCKS, {"socks": []}).evaluated


def test_rule_menu_not_read_is_unevaluated():
    assert not check_rule(SOCKS, {}).evaluated


def test_rule_unknown_path_is_unevaluated():
    assert not check_rule(rule("policy.x.y", "/ip/nie-ma", {"a": "b"}), {}).evaluated


def test_none_match_absent_user_is_clean():
    assert check_rule(ADMIN, {"users": [{"name": "monitor", "disabled": False}]}).violations == []
    assert check_rule(ADMIN, {"users": []}).evaluated


def test_none_match_active_admin_violates_with_null_expected():
    check = check_rule(ADMIN, {"users": [{"name": "admin", "disabled": False}]})
    assert check.violations[0].expected is None
    assert check.violations[0].object_key == "admin"


# --- drift i precedencja ---
def test_drift_clean_when_same():
    state = {"scheduler": [{"name": "a", "interval": "1d"}]}
    assert evaluate(state, [], {}, copy.deepcopy(state)).violations == []


def test_drift_added_removed_changed():
    base = {"scheduler": [{"name": "a", "interval": "1d"}, {"name": "b", "interval": "1h"}]}
    state = {"scheduler": [{"name": "a", "interval": "2d"}, {"name": "c", "interval": "1h"}]}
    found = {v.object_key: v for v in evaluate(state, [], {}, base).violations}
    assert found["a"].expected == {"interval": "1d"} and found["a"].observed == {"interval": "2d"}
    assert found["b"].observed is None
    assert found["c"].expected is None
    assert {v.rule for v in found.values()} == {"local.drift.scheduler"}
    assert found["a"].severity == "medium" and found["a"].rule_source == "local"


def test_drift_override_sets_id_and_severity():
    local = {"drift": {"overrides": [{"resource": "ppp_secrets", "id": "local.ppp.secrets", "severity": "high"}]}}
    result = evaluate({"ppp_secrets": [{"name": "vpn"}]}, [], local, {"ppp_secrets": []})
    assert result.violations[0].rule == "local.ppp.secrets" and result.violations[0].severity == "high"


def test_drift_ignore_applies_to_attr_and_key():
    local = {"drift": {"ignore": [{"resource": "firewall_filter", "attrs": ["comment"], "reason": "powod"}]}}
    base = {"firewall_filter": [{"chain": "input", "action": "drop", "comment": "BL"}]}
    state = {"firewall_filter": [{"chain": "input", "action": "drop", "comment": "inny"}]}
    assert evaluate(state, [], local, base).violations == []
    assert evaluate(state, [], {}, base).violations            # bez wpisu: drift


def test_drift_ignore_does_not_hide_new_object():
    local = {"drift": {"ignore": [{"resource": "firewall_filter", "attrs": ["comment"], "reason": "powod"}]}}
    state = {"firewall_filter": [{"chain": "input", "action": "accept"}]}
    assert evaluate(state, [], local, {"firewall_filter": []}).violations


def test_drift_excludes_telemetry():
    result = evaluate({"system_resource": [{"version": "2"}]}, [], {}, {"system_resource": [{"version": "1"}]})
    assert result.violations == []


def test_drift_type_differences_are_not_drift():
    # API: bool i int; YAML wzorca może dać napis
    result = evaluate({"socks": [{"enabled": False, "port": 1080}]}, [], {}, {"socks": [{"enabled": "no", "port": "1080"}]})
    assert result.violations == []


def test_drift_menu_missing_on_both_sides_is_evaluated():
    result = evaluate({}, [], {}, {})
    assert "local.drift.wireguard-peers" in result.evaluated_rules and result.unevaluated == []


def test_drift_menu_not_read_is_unevaluated():
    result = evaluate({}, [], {}, {"scheduler": []})
    assert {u["rule"] for u in result.unevaluated} == {"local.drift.scheduler"}


def test_drift_resource_outside_baseline_is_unevaluated():
    result = evaluate({"ppp_secrets": [{"name": "vpn"}]}, [], {}, {})
    assert result.violations == []
    assert {u["rule"] for u in result.unevaluated} == {"local.drift.ppp-secrets"}
    assert "local.drift.ppp-secrets" not in result.evaluated_rules


def test_universal_absorbs_drift_on_same_object():
    base = {"socks": [{"enabled": False}]}
    state = {"socks": [{"enabled": True}]}
    result = evaluate(state, [SOCKS], {}, base)
    assert [v.rule for v in result.violations] == [SOCKS["id"]]
    assert result.violations[0].also_matched == ["local.drift.socks"]
    assert ("local.drift.socks", "/ip/socks", "socks") in result.absorbed


def test_universal_absorbs_local_rule_on_same_object():
    local_rule = {"id": "local.mgmt.winbox", "severity": "high", "reason": "powod",
                  "check": {"path": "/ip/service", "where": {"name": "winbox"}, "assert": {"address": "10.0.0.0/24"}}}
    state = {"services": [{"name": "winbox", "address": ""}]}
    result = evaluate(state, [WINBOX], {"rules": [local_rule]}, {})
    assert [v.rule for v in result.violations] == [WINBOX["id"]]
    assert "local.mgmt.winbox" in result.violations[0].also_matched


def test_local_rule_absorbs_drift_without_also_matched():
    local_rule = {"id": "local.mgmt.winbox", "severity": "high", "reason": "powod",
                  "check": {"path": "/ip/service", "where": {"name": "winbox"}, "assert": {"address": "10.0.0.0/24"}}}
    base = {"services": [{"name": "winbox", "address": "10.0.0.0/24"}]}
    state = {"services": [{"name": "winbox", "address": "10.9.0.0/24"}]}
    result = evaluate(state, [], {"rules": [local_rule]}, base)
    assert [v.rule for v in result.violations] == ["local.mgmt.winbox"]
    assert result.violations[0].also_matched == []


def test_dynamic_rules_are_skipped():
    dynamic = {"id": "policy.dynamic.x", "severity": "high", "ioc": True, "phase": "dynamic", "detector": "ti"}
    result = evaluate({}, [dynamic], {}, {})
    assert result.violations == [] and "policy.dynamic.x" not in result.known_rules

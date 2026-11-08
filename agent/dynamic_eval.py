"""Faza dynamiczna: detektory na danych Zeeka i próbkach tablicy połączeń routera.

Wynik ma postać naruszeń jak w fazie statycznej. Okno WINDOW_S sprawia, że finding
znika dopiero po godzinie bez zdarzeń: beacon o rzadkim interwale nie daje serii
raportów nowy/rozwiązany.
"""
from __future__ import annotations

import ipaddress
import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

from agent.l2_zeek import WINDOW_S, ZeekData
from agent.report import timestamp
from agent.static_eval import Violation

SAMPLE_MARGIN_S = 2
# Stany Zeeka dla przepływu TCP/UDP zestawionego w obie strony: tylko taki router musi
# śledzić. ICMP ma zawsze stan OTH, więc o zestawieniu świadczy odpowiedź.
ESTABLISHED = {"SF", "S1", "S2", "S3", "RSTO", "RSTR"}
CONN_PATH = "/zeek/conn"
DNS_PATH = "/zeek/dns"
RITA_PATH = "/rita/beacon"
# Cele, dla których TI ma sens: zewnętrzny koniec kanału, nie resolver użyty przez DGA.
TI_DETECTORS = {"zeek.conn", "rita.beacon", "dns.resolver"}
CONNECTION_QUERY = "/ip/firewall/connection"
SUPPORTED = {"zeek.conn", "dns.resolver", "dns.dga", "rita.beacon"}
MAX_DETAIL = 50


@dataclass
class DynamicResult:
    violations: list[Violation] = field(default_factory=list)
    evaluated_rules: set[str] = field(default_factory=set)
    unevaluated: list[dict] = field(default_factory=list)


def iso(epoch: float) -> str:
    return timestamp(datetime.fromtimestamp(epoch, timezone.utc))


def _answered(row: dict) -> bool:
    if row["proto"] == "icmp":
        return row.get("resp_pkts", 0) > 0
    return row["proto"] in ("tcp", "udp") and row["conn_state"] in ESTABLISHED


def merge_samples(ring: list[dict], fresh: list[dict] | None, run_id: str, now: float) -> list[dict]:
    """Próbki z okna: wpis Zeeka powstaje po końcu przepływu, więc porównanie sięga
    próbek z wcześniejszych cykli."""
    kept = [s for s in ring if s["at"] >= now - WINDOW_S]
    kept += [{**s, "cycle": run_id} for s in fresh or []]
    return kept


def _key(proto: str, dst: str, port: int | None) -> tuple:
    return (dst, proto, None if proto == "icmp" else port)


def _object_key(key: tuple) -> str:
    dst, proto, port = key
    return f"{dst}/{proto}" if port is None else f"{dst}/{proto}/{port}"


def _violation(rule: dict, path: str, key: str, evidence: dict, trust: dict, detail: dict) -> Violation:
    return Violation(rule=rule["id"], rule_source="universal", severity=rule["severity"],
                     ioc=bool(rule.get("ioc")), path=path, object_key=key, expected=None, observed=None,
                     phase="dynamic", evidence=evidence, trust=trust, detail=detail)


def _observation(data: ZeekData, detector: str, dst: str, proto: str, port: int | None,
                 count: int, octets: int) -> dict:
    return {"destination": dst, "dport": port, "proto": proto, "flow_count": count, "bytes_total": octets,
            "window": {"from": iso(data.since), "to": iso(data.until)}, "detector": detector, "score": None}


def divergence(rule: dict, data: ZeekData, samples: list[dict]) -> list[Violation]:
    """Brak celu w tablicy liczy się tylko wtedy, gdy przepływ trwał w chwili próbki.
    Wystarczy jedno trafienie celu w oknie, żeby rozbieżności nie było."""
    seen = {tuple(t) for s in samples for t in s["targets"]}
    misses: dict[tuple, set[str]] = {}
    flows: dict[tuple, list[dict]] = {}
    for row in data.conn:
        if not _answered(row):
            continue
        key = _key(row["proto"], row["id.resp_h"], row["id.resp_p"])
        if key in seen:
            continue
        flows.setdefault(key, []).append(row)
        start, end = row["ts"] + SAMPLE_MARGIN_S, row["ts"] + row["duration"] - SAMPLE_MARGIN_S
        for sample in samples:
            if start <= sample["at"] <= end:
                misses.setdefault(key, set()).add(sample["cycle"])

    found = []
    need = int(rule["assert"].get("min_repeats", 3))
    for key, cycles in sorted(misses.items(), key=lambda kv: _object_key(kv[0])):
        if len(cycles) < need:
            continue
        rows = flows[key]
        evidence = {
            "l1_claim": {"query": CONNECTION_QUERY, "destination_present": False},
            "l2_observation": _observation(data, rule["detector"], key[0], key[1], key[2], len(rows),
                                           sum(r["orig_bytes"] + r["resp_bytes"] for r in rows)),
        }
        trust = {"observed_by": ["L2"], "corroborated_by": [], "contradicted_by": ["L1"], "divergence": True}
        detail = {"cycles_without_target": sorted(cycles),
                  "flows": [{"uid": r["uid"], "ts": r["ts"], "duration": r["duration"]} for r in rows[:MAX_DETAIL]]}
        found.append(_violation(rule, CONN_PATH, _object_key(key), evidence, trust, detail))
    return found


def _dns_by_resolver(data: ZeekData) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for row in data.dns:
        if row["id.resp_p"] == 53 and row["id.resp_h"]:
            grouped.setdefault(row["id.resp_h"], []).append(row)
    return grouped


def _dns_violation(rule: dict, data: ZeekData, resolver: str, rows: list[dict], detail: dict) -> Violation:
    proto = Counter(r["proto"] for r in rows).most_common(1)[0][0]
    evidence = {"l2_observation": _observation(data, rule["detector"], resolver,
                                               proto if proto in ("tcp", "udp") else "udp", 53, len(rows), 0)}
    trust = {"observed_by": ["L2"], "corroborated_by": [], "contradicted_by": [], "divergence": False}
    return _violation(rule, DNS_PATH, resolver, evidence, trust, detail)


def rogue_resolver(rule: dict, data: ZeekData, allowed: set[str]) -> list[Violation]:
    found = []
    for resolver, rows in sorted(_dns_by_resolver(data).items()):
        if resolver not in allowed:
            found.append(_dns_violation(rule, data, resolver, rows, {"queries": len(rows)}))
    return found


def entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def suspicious_name(name: str | None, cond: dict, suffixes: list[str]) -> bool:
    if not name:
        return False
    name = name.rstrip(".").lower()
    if name.endswith(".arpa") or any(name == s or name.endswith("." + s) for s in suffixes):
        return False
    labels = name.split(".")[:-1]
    longest = max(labels, key=len, default="")
    return len(longest) >= int(cond.get("min_label_length", 12)) and entropy(longest) > float(cond["entropy_max"])


def dga(rule: dict, data: ZeekData, suffixes: list[str]) -> list[Violation]:
    cond = rule["assert"]
    found = []
    for resolver, rows in sorted(_dns_by_resolver(data).items()):
        hits = [r for r in rows if suspicious_name(r["query"], cond, suffixes)]
        names = sorted({r["query"].rstrip(".").lower() for r in hits})
        if len(names) >= int(cond.get("min_distinct", 3)):
            # Nazwy tylko w dowodzie lokalnym: zdradzałyby ruch hostów LAN (R6).
            found.append(_dns_violation(rule, data, resolver, hits, {"names": names[:MAX_DETAIL]}))
    return found


def ports(row: dict) -> list[tuple[str, int | None]]:
    """port_proto_service RITA: "123:udp:ntp", "22:tcp:" → (proto, port)."""
    found = []
    for item in row.get("port_proto_service") or []:
        port, _, rest = str(item).partition(":")
        proto = rest.split(":", 1)[0]
        try:
            pair = (proto, int(port))
        except ValueError:
            pair = (proto, None)
        if proto and pair not in found:
            found.append(pair)
    return found


def _dst_matches(entry_dst: str, ip: str | None, names: set[str]) -> bool:
    """dst: "*", adres lub CIDR, albo nazwa (także poddomena) z FQDN RITA lub odpowiedzi DNS."""
    entry_dst = str(entry_dst).strip().lower().rstrip(".")
    if entry_dst == "*":
        return True
    try:
        network = ipaddress.ip_network(entry_dst, strict=False)
    except ValueError:
        return any(n == entry_dst or n.endswith("." + entry_dst) for n in names)
    try:
        return ip is not None and ipaddress.ip_address(ip) in network
    except ValueError:
        return False


def allowed_periodic(row: dict, entries: list[dict], names: set[str]) -> bool:
    """Każda para proto/port beaconu musi mieć wpis z pasującym celem."""
    pairs = ports(row)
    if not pairs:
        return False
    return all(any(str(e.get("proto")) == proto and e.get("port") == port and _dst_matches(e.get("dst"), row.get("dst"), names)
                   for e in entries) for proto, port in pairs)


def beacon(rule: dict, rita, entries: list[dict], zeek_names: dict[str, set[str]]) -> list[Violation]:
    found = []
    limit = float(rule["assert"]["score_max"])
    window = {"from": iso(rita.imported.since), "to": iso(rita.imported.until)}
    for row in rita.rows:
        score = float(row.get("beacon_score") or 0)
        if score <= limit:
            continue
        fqdn = (row.get("fqdn") or "").rstrip(".").lower()
        destination = row.get("dst") if row.get("dst") and row.get("dst") != "0.0.0.0" else \
            next(iter(row.get("server_ips") or []), None)
        names = set(zeek_names.get(destination or "", set())) | ({fqdn} if fqdn else set())
        if allowed_periodic(row, entries, names) or destination is None:
            continue
        pairs = ports(row)
        proto, port = pairs[0] if pairs else ("tcp", None)
        key = fqdn if fqdn and row.get("beacon_type") != "ip" else destination
        evidence = {"l2_observation": {
            "destination": destination, "dport": port, "proto": proto if proto in ("tcp", "udp", "icmp") else "tcp",
            "flow_count": max(int(row.get("count") or 1), 1), "bytes_total": int(row.get("total_bytes") or 0),
            "window": window, "detector": rule["detector"], "score": round(min(max(score, 0.0), 1.0), 3)}}
        trust = {"observed_by": ["L2"], "corroborated_by": [], "contradicted_by": [], "divergence": False}
        detail = {"import_id": row.get("import_id") or rita.imported.import_id, "beacon_type": row.get("beacon_type"), "fqdn": fqdn or None,
                  "port_proto_service": row.get("port_proto_service"), "score": score,
                  "names": sorted(names)[:MAX_DETAIL]}
        found.append(_violation(rule, RITA_PATH, key, evidence, trust, detail))
    return sorted(found, key=lambda v: v.object_key)


def corroborate(violations: list[Violation], verdicts: dict[str, dict], rule_ids: set[str]) -> None:
    """L3 potwierdza finding: werdykt w dowodzie, malicious/suspicious w corroborated_by."""
    for v in violations:
        if v.evidence is None or v.rule not in rule_ids:
            continue
        found = verdicts.get(v.evidence["l2_observation"]["destination"])
        if not found:
            continue
        v.evidence["l3_corroboration"] = dict(found)
        if found["verdict"] in ("malicious", "suspicious") and "L3" not in v.trust["corroborated_by"]:
            v.trust["corroborated_by"].append("L3")


def ti_targets(violations: list[Violation], rules: list[dict]) -> tuple[set[str], set[str]]:
    """(adresy do sprawdzenia, reguły, których cele sprawdza TI)."""
    ids = {r["id"] for r in rules if r.get("detector") in TI_DETECTORS}
    targets = {v.evidence["l2_observation"]["destination"] for v in violations
               if v.evidence is not None and v.rule in ids}
    return targets, ids


def _suffixes(dynamic_baseline: dict) -> list[str]:
    values = ((dynamic_baseline.get("dns") or {}).get("allowed_suffixes")) or []
    return [str(v).strip(".").lower() for v in values if str(v).strip(".")]


def evaluate(rules: list[dict], data: ZeekData | None, samples: list[dict] | None,
             dynamic_baseline: dict, l2_reason: str | None, rita=None, rita_reason: str | None = None) -> DynamicResult:
    """data=None: logów brak, reguły Zeeka nie są ocenione. samples=None: brak próbek
    w tym cyklu, więc nieoceniona jest tylko rozbieżność. rita=None: beacon nieoceniony."""
    result = DynamicResult()
    dns_cfg = dynamic_baseline.get("dns") if isinstance(dynamic_baseline.get("dns"), dict) else {}

    def skip(rule: dict, reason: str):
        result.unevaluated.append({"rule": rule["id"], "reason": reason})

    for rule in rules:
        detector = rule.get("detector")
        if detector not in SUPPORTED:
            continue                      # ti: TI tylko potwierdza findingi (D4)
        if detector == "rita.beacon":
            if rita is None:
                skip(rule, rita_reason or "brak wyników RITA")
                continue
            entries = ((dynamic_baseline.get("beaconing") or {}).get("allowed_periodic")) or []
            result.evaluated_rules.add(rule["id"])
            result.violations += beacon(rule, rita, entries, data.names if data else {})
            continue
        if data is None:
            skip(rule, l2_reason or "brak danych L2")
            continue
        if detector == "zeek.conn":
            if not samples:
                skip(rule, "brak próbek tablicy połączeń w tym cyklu")
                continue
            found = divergence(rule, data, samples)
        elif detector == "dns.resolver":
            allowed = dns_cfg.get("allowed_resolvers")
            if not isinstance(allowed, list) or not dns_cfg.get("alert_on_other_resolver", True):
                skip(rule, "dynamic-baseline: brak dns.allowed_resolvers lub detektor wyłączony")
                continue
            found = rogue_resolver(rule, data, {str(a) for a in allowed})
        else:
            found = dga(rule, data, _suffixes(dynamic_baseline))
        result.evaluated_rules.add(rule["id"])
        result.violations += found
    return result

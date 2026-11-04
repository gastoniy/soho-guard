#!/usr/bin/env python3
"""
mikrotik_onboard.py — Faza 0' (onboarding), B4 + B5.

Zastępuje wcześniejszy mikrotik_baseline.py. Zmiany względem niego:

  1. Transport REST → BINARY API (librouteros). REST jest tylko w v7; binary
     API działa na v6 i v7, więc jeden kod obsługuje oba (spójnie z profilem
     ros6/ros7 agenta, ADR-004). Onboarding łączy się z urządzeniem jeszcze
     NIE pod baseline, więc domyślnie binary API 8728 (domyślnie włączone);
     --tls używa 8729.
  2. Rozdział artefaktów (B4) — patrz niżej. Poprzedni skrypt mieszał metadane
     instalacji z migawką konfiguracji w jednym inventory.yml.
  3. /export z hide-sensitive — poprzedni commitował sekrety urządzenia (R6).
  4. Weryfikacja względem policy/ (ADR-003, krok 4 fazy 0') — opcjonalny krok
     oznaczający naruszenia obecne już w chwili adopcji.

TRZY ARTEFAKTY (rozwiązanie B4 — rozdzielenie ról dotąd zlanych w "inventory.yml"):

  routers/{router}/inventory.yml metadane instalacji + pin wersji policy +
                                 warstwa lokalna. HUMAN-authored SSOT. Skrypt
                                 generuje SZKIELET z autodetekcją; człowiek
                                 uzupełnia i commituje (ADR-002).
  routers/{router}/baseline-state.yml znormalizowana migawka konfiguracji (binary
                                 API) do maszynowego diffu driftu (faza statyczna).
  routers/{router}/export.rsc    surowy /export hide-sensitive (SSH) do
                                 restore/rollback; NIE do diffu, bez sekretów.

Pełny /export z sekretami (do realnego restore) zostaje LOKALNIE, nigdy w repo (R6).

Zależności: pip install librouteros pyyaml netmiko
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

# --- zasoby wchodzące w migawkę (tylko config, nie telemetria/runtime) -------
# Zestaw pogrupowany wg powierzchni ataku (ATT&CK) i IOC kampanii MikroTik.
# Ścieżki jako krotki menu binary API (librouteros path), bez wiodącego '/'.
RESOURCES = {
    # baza sieciowa/usługowa
    "identity":              ("system", "identity"),
    "interfaces":            ("interface",),
    "vlans":                 ("interface", "vlan"),
    "bridges":               ("interface", "bridge"),
    "ip_addresses":          ("ip", "address"),
    "dhcp_clients":          ("ip", "dhcp-client"),   # dynamiczny adres WAN = utrata atrybucji L2
    "routes":                ("ip", "route"),
    "dns":                   ("ip", "dns"),
    "ntp_client":            ("system", "ntp", "client"),
    # dostęp i poświadczenia (T1078)
    "users":                 ("user",),
    "user_groups":           ("user", "group"),
    "ssh_keys":              ("user", "ssh-keys"),
    "services":              ("ip", "service"),
    "system_resource":       ("system", "resource"),
    # trwałość / backdoor (T1053)
    "scheduler":             ("system", "scheduler"),
    "scripts":               ("system", "script"),
    "certificates":          ("certificate",),
    # przekierowanie ruchu / proxy (T1090)
    "firewall_filter":       ("ip", "firewall", "filter"),
    "firewall_nat":          ("ip", "firewall", "nat"),
    "firewall_address_lists":("ip", "firewall", "address-list"),
    "socks":                 ("ip", "socks"),
    # tunelowanie / nieautoryzowany zdalny dostęp (v7: wireguard; brak w v6 — pomijany)
    "wireguard_interfaces":  ("interface", "wireguard"),
    "wireguard_peers":       ("interface", "wireguard", "peers"),
    "l2tp_client":           ("interface", "l2tp-client"),
    "l2tp_server":           ("interface", "l2tp-server"),
    "ovpn_client":           ("interface", "ovpn-client"),
    "ovpn_server":           ("interface", "ovpn-server"),
    # anty-forensyka
    "logging":               ("system", "logging"),
    # powierzchnia zarządzania / usługi pojedyncze (menu-singletony) — wymagane
    # przez reguły policy/static; bez nich reguły byłyby po cichu pomijane
    "neighbor_discovery":    ("ip", "neighbor", "discovery-settings"),
    "ssh":                   ("ip", "ssh"),
    "smb":                   ("ip", "smb"),
    "bandwidth_server":      ("tool", "bandwidth-server"),
    "proxy":                 ("ip", "proxy"),
    "upnp":                  ("ip", "upnp"),
    "cloud":                 ("ip", "cloud"),
}

# odwrotna mapa: "/ip/socks" -> "socks" (dla weryfikacji względem policy)
PATH_TO_KEY = {"/" + "/".join(p): k for k, p in RESOURCES.items()}

VOLATILE_KEYS = {
    ".id", "dynamic", "invalid", "running", "inactive",
    "bytes", "packets", "tx-byte", "rx-byte", "tx-packet", "rx-packet",
    "last-link-down-time", "last-link-up-time", "link-downs",
    "actual-mtu", "current-mac-address", "uptime", "free-memory",
    "cpu-load", "free-hdd-space",
    # liczniki i stan runtime (RouterOS 7.x) — inaczej każdy cykl dawałby drift
    "fp-rx-byte", "fp-rx-packet", "fp-tx-byte", "fp-tx-packet",
    "rx-drop", "rx-error", "tx-drop", "tx-error", "tx-queue-drop",
    "cache-used", "write-sect-since-reboot", "write-sect-total",
    "last-logged-in", "freq-drift", "status", "loop-protect-status",
}

# Wpisy runtime pojawiające się w menu konfiguracyjnych (v7.20: /ip/service
# pokazuje aktywne sesje, np. sesję samego onboardingu) — nie są konfiguracją.
def _is_runtime_entry(e: dict) -> bool:
    return str(e.get("connection", "")).lower() in ("true", "yes")

PRIVATE_NETS = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2",
                "172.30.", "172.31.", "192.168.")


# --- transport (leniwe importy: pozwala testować część czystą bez bibliotek) -
def connect_api(host, user, password, tls=False, port=None, verify=False, ca_file=None):
    from librouteros import connect
    if tls:
        import ssl
        # ca_file: CA labu/instalacji (certyfikat api-ssl z SAN=IP:adres zarządzania)
        ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE   # lab: self-signed. Prod: pinuj cert.
        # librouteros wywołuje ssl_wrapper(sock) bez server_hostname — przy
        # weryfikacji (check_hostname) nazwa/IP musi być podana jawnie.
        import functools
        wrapper = functools.partial(ctx.wrap_socket, server_hostname=host)
        return connect(username=user, password=password, host=host,
                       port=port or 8729, ssl_wrapper=wrapper)
    return connect(username=user, password=password, host=host, port=port or 8728)


def fetch_resources(api, resources=RESOURCES) -> dict:
    """api: obiekt z metodą .path(*parts) -> iterowalne dict-y (librouteros).
    Zwraca surowy stan per klucz. Menu nieistniejące na danej wersji (np.
    wireguard na v6) jest pomijane — różnice v6/v7 obsłużone naturalnie."""
    out = {}
    for key, parts in resources.items():
        try:
            out[key] = [dict(x) for x in api.path(*parts)]
        except Exception as exc:                       # noqa: BLE001 (różne wyjątki API)
            print(f"[WARN] {'/'.join(parts)}: {exc}", file=sys.stderr)
    return out


def export_connect_params(host, user, password, ssh_key=None) -> dict:
    """Parametry SSH dla /export. Użytkownik z zaimportowanym kluczem loguje się
    przez SSH tylko kluczem (RouterOS: always-allow-password-login=no)."""
    dev = {"device_type": "mikrotik_routeros", "host": host, "username": user}
    if ssh_key:
        dev.update(use_keys=True, key_file=ssh_key, allow_agent=False)
    else:
        dev["password"] = password
    return dev


def dump_export_rsc(host, user, password, ssh_key=None) -> str:
    """Surowy /export hide-sensitive (SSH). Bez sekretów — bezpieczny do repo."""
    from netmiko import ConnectHandler
    dev = export_connect_params(host, user, password, ssh_key)
    with ConnectHandler(**dev) as conn:
        return conn.send_command("/export terse hide-sensitive")


# --- przetwarzanie (czyste, testowalne) --------------------------------------
def coerce(v):
    if isinstance(v, str):
        if v in ("true", "false"):
            return v == "true"
        if v.isdigit():
            return int(v)
    return v


def strip_volatile(entry: dict) -> dict:
    return {k: coerce(v) for k, v in entry.items() if k not in VOLATILE_KEYS}


def normalize(resource):
    if isinstance(resource, dict):
        return {k: coerce(resource[k]) for k in sorted(resource) if k not in VOLATILE_KEYS}
    cleaned = [strip_volatile(e) for e in resource if not _is_runtime_entry(e)]
    return sorted(cleaned, key=lambda e: e.get("name") or json.dumps(e, sort_keys=True))


def build_state(raw: dict) -> dict:
    return {k: normalize(v) for k, v in raw.items()}


def detect_profile(state: dict) -> str:
    res = state.get("system_resource") or []
    ver = (res[0].get("version") if res else "") or ""
    m = re.match(r"\s*(\d+)\.", ver)
    major = int(m.group(1)) if m else 0
    return "ros6" if major == 6 else "ros7" if major == 7 else "unknown"


def detect_wan(state: dict) -> dict:
    """Kandydat na WAN: interfejs trasy domyślnej + jego adres i MAC.
    W v7 `gateway` to adres IP, a interfejs jest w `immediate-gw`
    ("192.168.20.1%ether1-wan"); w v6 bywa nazwa interfejsu. Wynik jest
    KANDYDATEM do potwierdzenia przez człowieka (ADR-003: urządzenie może kłamać)."""
    import ipaddress
    iface, gw = None, None
    for r in state.get("routes", []):
        if r.get("dst-address") == "0.0.0.0/0" and r.get("active", True) is not False:
            gw = str(r.get("gateway") or "")
            imm = str(r.get("immediate-gw") or "")
            if "%" in imm:
                iface = imm.split("%", 1)[1]
            break
    addrs = state.get("ip_addresses", [])
    if iface is None and gw:
        names = {i.get("name") for i in state.get("interfaces", [])}
        if gw in names:
            iface = gw
        else:                                    # gateway jako IP: interfejs z adresem w tej sieci
            try:
                g = ipaddress.ip_address(gw.split("%")[0])
                for a in addrs:
                    if g in ipaddress.ip_interface(a["address"]).network:
                        iface = a.get("interface"); break
            except ValueError:
                pass
    addr = next((a.get("address") for a in addrs if iface and a.get("interface") == iface
                 and a.get("disabled") is not True), None)
    mac = next((i.get("mac-address") for i in state.get("interfaces", [])
                if iface and i.get("name") == iface), None)
    return {"wan_interface_candidate": iface, "wan_address": addr, "wan_mac": mac}


def scaffold_inventory(site_id: str, state: dict, router_id: str | None = None) -> dict:
    """Szkielet inventory.yml (B4). Autodetekcja + pola CHANGE_ME do uzupełnienia
    przez człowieka. CHANGE_ME celowo blokuje commit bez przeglądu."""
    ident = state.get("identity") or []
    res = state.get("system_resource") or []
    wan = detect_wan(state)
    return {
        "schema_version": "1.0",
        "site_id": site_id,
        "router_id": router_id or "CHANGE_ME",    # --router-id albo człowiek: r1 / r2 / ...
        "profile": detect_profile(state),         # autodetekcja
        # Wersja polityki: jedynym źródłem jest site.yml (policy.universal_version)
        # repozytorium instalacji — decyzja 2026-11-02. Tu wyłącznie informacja.
        "policy": {
            "universal_version_source": "site.yml",
        },
        "addressing": {
            "mgmt_net": "CHANGE_ME",
            # kandydaci z autodetekcji — POTWIERDZIĆ (ADR-004 atrybucja L2):
            "wan_address": wan["wan_address"] or "CHANGE_ME",
            "wan_mac": wan["wan_mac"] or "CHANGE_ME",
        },
        # repo instalacji: routers/<router_id>/ (jedno repo na site, wiele routerów)
        "dynamic_baseline": f"routers/{router_id or 'CHANGE_ME'}/dynamic-baseline.yml",
        "local_policy": [],                        # warstwa lokalna (ADR-002); człowiek dodaje
        "onboarding": {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "firmware_reported": (res[0].get("version") if res else None),
            "identity_reported": (ident[0].get("name") if ident else None),
            "wan_interface_candidate": wan["wan_interface_candidate"],
            "verified_against_policy": False,      # ustaw po przeglądzie
            "review_status": "pending",
        },
    }


# --- weryfikacja względem policy/ (ADR-003 krok 4) ---------------------------
def _canon(x):
    """Ujednolica reprezentację bool: API zwraca true/false, polityka pisze
    yes/no. Bez tego 'enabled=no' nie zrówna się z wartością False z API."""
    if isinstance(x, bool):
        return x
    if isinstance(x, str) and x.lower() in ("yes", "true"):
        return True
    if isinstance(x, str) and x.lower() in ("no", "false"):
        return False
    return x


def _match_predicate(value, cond) -> bool:
    if isinstance(cond, dict):
        if cond.get("private") is True:
            return isinstance(value, str) and value.startswith(PRIVATE_NETS)
        if cond.get("not_empty") is True:
            return value not in (None, "", [], {})
        if "one_of" in cond:
            return _canon(value) in [_canon(c) for c in cond["one_of"]]
        if "not_one_of" in cond:
            # brak wartości to też naruszenie — nie da się wykazać ograniczenia
            if value in (None, "", [], {}):
                return False
            return _canon(value) not in [_canon(c) for c in cond["not_one_of"]]
        return False
    cv, cc = _canon(value), _canon(cond)
    return cv == cc or str(value) == str(cond)


def verify_against_policy(state: dict, policy_rules: list) -> list:
    """Minimalna weryfikacja fazy 0': które reguły STATYCZNE policy/ są już
    naruszone w chwili adopcji. Pełny silnik ewaluacji to agent (C1); tu obsługa
    asercji na pojedynczych menu (enabled/disabled/private/one_of/not_one_of/not_empty).
    Zwraca listę naruszeń do przeglądu człowieka."""
    findings = []
    for rule in policy_rules:
        if rule.get("phase") != "static" or "check" not in rule:
            continue
        chk = rule["check"]
        key = PATH_TO_KEY.get(chk["path"])
        if key is None or key not in state:
            continue
        data = state[key]
        entries = data if isinstance(data, list) else [data]
        where = chk.get("where")
        if where:
            entries = [e for e in entries if all(_match_predicate(e.get(k), v) for k, v in where.items())]
        if not entries:
            continue
        for prop, cond in chk["assert"].items():
            # none-match: naruszenie, gdy ISTNIEJE wpis pasujący do wszystkich warunków
            if chk.get("scope") == "none-match":
                for e in entries:
                    if all(_match_predicate(e.get(p2), c2) for p2, c2 in chk["assert"].items()):
                        findings.append({"rule": rule["id"], "severity": rule["severity"],
                                         "detail": f"istnieje wpis pasujący: {chk['assert']}"})
                        break
                break
            # domyślnie: naruszenie, gdy KTÓRYKOLWIEK wpis nie spełnia asercji
            bad = [e for e in entries if not _match_predicate(e.get(prop), cond)]
            if bad:
                findings.append({"rule": rule["id"], "severity": rule["severity"],
                                 "detail": f"{chk['path']} {prop}={bad[0].get(prop)!r}, oczekiwano {cond!r}"})
    return findings


def onboarding_note(violations: int, not_evaluated: int) -> str:
    """Komunikat dla administratora zależny od wyniku (ADR-003: brak naruszeń
    statycznych nie dowodzi braku kompromitacji)."""
    if not_evaluated:
        head = (f"Nie oceniono {not_evaluated} reguł (brak danych) — wynik niepełny, "
                "nie zatwierdzać przed wyjaśnieniem.")
    elif violations:
        head = (f"Wykryto {violations} naruszeń polityki uniwersalnej w chwili adopcji. "
                "Urządzenie mogło zostać przejęte przed onboardingiem — przejrzyj "
                "naruszenia i usuń ich przyczynę przed zatwierdzeniem inwentarza.")
    else:
        head = "Brak naruszeń sprawdzanych reguł statycznych polityki uniwersalnej."
    return head + (" Zakres: wyłącznie stan konfiguracji widoczny przez API — nie "
                   "wyklucza kompromitacji ukrytej przed self-reportem (weryfikuje ją "
                   "faza dynamiczna).")


def unevaluated_rules(state: dict, policy_rules: list) -> list:
    """Reguły statyczne, których NIE dało się ocenić (brak ścieżki w RESOURCES
    albo menu nieodczytane z urządzenia). Raportowane jawnie — brak naruszenia
    nie może wynikać z braku danych (pokrycie, ADR-005)."""
    out = []
    for rule in policy_rules:
        if rule.get("phase") != "static" or "check" not in rule:
            continue
        path = rule["check"]["path"]
        key = PATH_TO_KEY.get(path)
        if key is None:
            out.append({"rule": rule["id"], "reason": f"ścieżka {path} nie jest zbierana (RESOURCES)"})
        elif key not in state:
            out.append({"rule": rule["id"], "reason": f"menu {path} nieodczytane z urządzenia"})
    return out


def load_policy(policy_dir: Path) -> list:
    rules = []
    for f in list(policy_dir.rglob("*.yml")) + list(policy_dir.rglob("*.yaml")):
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        rules += doc.get("rules", [])
    return rules


# --- CLI ---------------------------------------------------------------------
def write_yaml(path: Path, data):
    path.write_text(yaml.safe_dump(data, sort_keys=True, default_flow_style=False,
                                   allow_unicode=True), encoding="utf-8")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Faza 0' onboarding (binary API, B4+B5)")
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--site-id", required=True, help="identyfikator instalacji (np. lab)")
    ap.add_argument("--router-id", help="identyfikator routera w instalacji (np. r1); "
                    "katalog wyjściowy = <out-dir>/<router-id>")
    ap.add_argument("--out-dir", default="./sites")
    ap.add_argument("--tls", action="store_true", help="binary API przez TLS (8729) zamiast 8728")
    ap.add_argument("--verify-tls", action="store_true", help="weryfikuj certyfikat TLS (domyślnie nie — self-signed)")
    ap.add_argument("--ca-file", help="plik CA do weryfikacji certyfikatu api-ssl (wymusza --verify-tls)")
    ap.add_argument("--skip-rsc", action="store_true", help="pomiń SSH /export")
    ap.add_argument("--ssh-key", help="klucz prywatny SSH dla /export (konto z kluczem, np. monitor)")
    ap.add_argument("--policy-dir", help="katalog policy/ — weryfikacja onboardingu (ADR-003 krok 4)")
    args = ap.parse_args(argv)
    if args.ca_file:
        args.verify_tls = True
    if args.verify_tls and not args.tls:
        ap.error("--verify-tls/--ca-file wymagają --tls")

    site_dir = Path(args.out_dir) / (args.router_id or args.site_id)
    site_dir.mkdir(parents=True, exist_ok=True)

    api = connect_api(args.host, args.user, args.password, tls=args.tls,
                      verify=args.verify_tls, ca_file=args.ca_file)
    try:
        raw = fetch_resources(api)
    finally:
        try: api.close()
        except Exception: pass

    state = build_state(raw)
    write_yaml(site_dir / "baseline-state.yml", state)
    print(f"[OK] {site_dir / 'baseline-state.yml'}")

    inv = scaffold_inventory(args.site_id, state, router_id=args.router_id)

    if args.policy_dir:
        rules = load_policy(Path(args.policy_dir))
        viol = verify_against_policy(state, rules)
        skipped = unevaluated_rules(state, rules)
        write_yaml(site_dir / "onboarding-findings.yml",
                   {"count": len(viol), "findings": viol,
                    "not_evaluated": skipped,
                    "note": onboarding_note(len(viol), len(skipped))})
        inv["onboarding"]["policy_violations_at_adoption"] = len(viol)
        inv["onboarding"]["policy_rules_not_evaluated"] = len(skipped)
        print(f"[OK] {site_dir / 'onboarding-findings.yml'} ({len(viol)} naruszeń, "
              f"{len(skipped)} reguł nieocenionych)")
        if skipped:
            print("[WARN] część reguł nie została oceniona — patrz not_evaluated", file=sys.stderr)

    write_yaml(site_dir / "inventory.yml", inv)
    print(f"[OK] {site_dir / 'inventory.yml'} (szkielet — uzupełnij CHANGE_ME i zrecenzuj)")

    if not args.skip_rsc:
        rsc = dump_export_rsc(args.host, args.user, args.password, ssh_key=args.ssh_key)
        # export.rsc (nie baseline.rsc): nazwa odróżnia eksport bez sekretów od
        # wyrenderowanego skryptu baseline z hasłami (pomyłka 2026-10-31).
        (site_dir / "export.rsc").write_text(rsc, encoding="utf-8")
        print(f"[OK] {site_dir / 'export.rsc'} (/export hide-sensitive)")

    print("\nNastępny krok: uzupełnij inventory.yml (CHANGE_ME), przejrzyj "
          "onboarding-findings.yml, potwierdź wan_address/wan_mac, commituj (PR).")


if __name__ == "__main__":
    sys.exit(main())

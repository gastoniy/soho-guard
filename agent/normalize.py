"""Normalizacja stanu routera wspólna dla agenta i onboardingu.

Tylko biblioteka standardowa. Moduł nie otwiera połączeń: odczyt dostaje gotowy
obiekt API. tools/validate_report.py celowo z niego nie korzysta (ADR-005).
"""
from __future__ import annotations

import ipaddress
import json
import sys

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
    "ppp_secrets":           ("ppp", "secret"),
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

# Telemetria w migawce, poza porównaniem driftu.
DRIFT_EXCLUDED = {"system_resource"}
DRIFT_PREFIX = "local.drift."

# Menu z jednym wierszem ustawień: obiekt nie ma własnej nazwy.
SINGLETONS = {"identity", "dns", "socks", "neighbor_discovery", "ssh", "smb", "bandwidth_server",
              "proxy", "upnp", "cloud", "ntp_client", "system_resource"}

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
    "expires-after",   # odliczanie ważności certyfikatu — zmienia się w każdym cyklu
    # stan synchronizacji NTP; konfiguracja to servers/server-dns-names/primary-ntp/secondary-ntp
    "active-server", "last-adjustment", "last-update-before", "last-update-from",
    "poll-interval", "synced-server", "synced-stratum", "system-offset",
    # stan wykonania zadania: zmienia się przy każdym uruchomieniu
    "next-run", "run-count",
}

# Wartości tajne nie trafiają do migawki: baseline-state.yml leży w repozytorium
# instalacji (R6). Skutek: zmiana samego hasła nie jest wykrywana jako drift.
# Flagi logiczne (certyfikat: private-key=true) są konfiguracją i zostają.
# Celowo bez ogólnego "-key": public-key peera WireGuard jest potrzebny do driftu.
SENSITIVE_KEYS = {"password", "passwd", "secret", "passphrase", "private-key",
                  "pre-shared-key", "preshared-key", "wpa-pre-shared-key",
                  "wpa2-pre-shared-key", "authentication-key"}
SENSITIVE_SUFFIXES = ("-password", "-secret", "-passphrase")

# Wpisy runtime pojawiające się w menu konfiguracyjnych (v7.20: /ip/service
# pokazuje aktywne sesje, np. sesję samego onboardingu) — nie są konfiguracją.
def _is_runtime_entry(e: dict) -> bool:
    return str(e.get("connection", "")).lower() in ("true", "yes")


def drift_rule_id(resource: str) -> str:
    """Domyślny identyfikator reguły driftu zasobu."""
    return DRIFT_PREFIX + resource.replace("_", "-")


# --- odczyt ---------------------------------------------------------------
def fetch_resources(api, resources=RESOURCES, failed: dict | None = None) -> dict:
    """api: obiekt z metodą .path(*parts) -> iterowalne dict-y (librouteros).
    Zwraca surowy stan per klucz. Menu nieistniejące na danej wersji (np.
    wireguard na v6) jest pomijane — różnice v6/v7 obsłużone naturalnie.
    failed: zbiera błędy inne niż brak menu; to one obniżają pokrycie."""
    out = {}
    for key, parts in resources.items():
        try:
            out[key] = [dict(x) for x in api.path(*parts)]
        except Exception as exc:                       # noqa: BLE001 (różne wyjątki API)
            print(f"[WARN] {'/'.join(parts)}: {exc}", file=sys.stderr)
            if failed is not None and "no such command" not in str(exc).lower():
                failed[key] = str(exc)[:200]
    return out


# --- przetwarzanie (czyste, testowalne) --------------------------------------
def coerce(v):
    if isinstance(v, str):
        if v in ("true", "false"):
            return v == "true"
        if v.isdigit():
            return int(v)
    return v


def _is_sensitive(key: str, value) -> bool:
    if isinstance(coerce(value), bool):
        return False
    return key in SENSITIVE_KEYS or key.endswith(SENSITIVE_SUFFIXES)


def strip_volatile(entry: dict) -> dict:
    return {k: coerce(v) for k, v in entry.items()
            if k not in VOLATILE_KEYS and not _is_sensitive(k, v)}


def _is_service_listener(entry: dict) -> bool:
    """v7: /ip/service pokazuje też bieżące gniazda (dhcp, ntp, resolver, włączony socks):
    mają proto, ale nie mają address. Odzwierciedlają stan działania, a nie konfigurację,
    więc nie wchodzą do migawki. Skutek: tak jak na v6 nowe gniazdo nie jest driftem."""
    return "proto" in entry and "address" not in entry


def is_service_config(entry: dict) -> bool:
    return not _is_runtime_entry(entry) and not _is_service_listener(entry)


def normalize(resource):
    if isinstance(resource, dict):
        return dict(sorted(strip_volatile(resource).items()))
    cleaned = [strip_volatile(e) for e in resource if not _is_runtime_entry(e)]
    return sorted(cleaned, key=lambda e: e.get("name") or json.dumps(e, sort_keys=True))


def build_state(raw: dict) -> dict:
    return {k: normalize([e for e in v if is_service_config(e)] if k == "services" else v)
            for k, v in raw.items()}


# --- predykaty polityki -----------------------------------------------------
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


def _is_private_scope(value) -> bool:
    """Lista adresów usługi RouterOS (po przecinku): prywatna tylko, gdy KAŻDY wpis
    jest prywatny. Pusta wartość = dostęp z dowolnego adresu."""
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        return all(ipaddress.ip_network(p.strip(), strict=False).is_private
                   for p in value.split(","))
    except ValueError:
        return False


def _match_predicate(value, cond) -> bool:
    if isinstance(cond, dict):
        if cond.get("private") is True:
            return _is_private_scope(value)
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

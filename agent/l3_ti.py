"""L3: reputacja celów z findingów dynamicznych (OTX).

TI potwierdza istniejący finding, nie tworzy nowego: wynik trafia do
evidence.l3_corroboration. Zapytanie wychodzi z adresu źródłowego instalacji
(zakaz egresu przez łącze utrzymaniowe), wynik jest trzymany w cache 24 h.
Awaria TI obniża status warstwy L3, nigdy nie tworzy findingu.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

PROVIDER = "otx"
HOST = "otx.alienvault.com"
PATH = "/api/v1/indicators/IPv4/{ip}/general"
TIMEOUT_S = 10
CACHE_TTL_S = 86400
CACHE_FILE = "ti-cache.json"
MALICIOUS_PULSES = 3
MAX_CATEGORIES = 10
KEY_NAME = "OTX_API_KEY"


class TiError(Exception):
    """Zapytanie TI nieudane: werdykt nieznany."""


def read_key(env_file: Path) -> str:
    """ti.env w formacie EnvironmentFile. Ręczny cykl (sudo -u) nie wczytuje go ze
    środowiska jednostki, więc agent czyta plik sam."""
    try:
        lines = env_file.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise TiError("nie można odczytać pliku ti.env") from exc
    for line in lines:
        line = line.strip()
        if line.startswith("export "):
            line = line[len("export "):]
        name, sep, value = line.partition("=")
        if sep and name.strip() == KEY_NAME and value.strip().strip("'\""):
            return value.strip().strip("'\"")
    raise TiError(f"brak {KEY_NAME} w ti.env")


class OtxClient:
    def __init__(self, key: str, source: str, connection=http.client.HTTPSConnection):
        self.key = key
        self.source = source
        self.connection = connection

    def lookup(self, ip: str) -> dict:
        conn = self.connection(HOST, timeout=TIMEOUT_S, source_address=(self.source, 0))
        try:
            conn.request("GET", PATH.format(ip=ip), headers={"X-OTX-API-KEY": self.key,
                                                            "User-Agent": "soho-guard-agent"})
            response = conn.getresponse()
            body = response.read()
            if response.status != 200:
                raise TiError(f"OTX HTTP {response.status}")
            return json.loads(body.decode("utf-8"))
        except (OSError, http.client.HTTPException, ValueError) as exc:
            raise TiError(f"OTX: {type(exc).__name__}: {exc}"[:200]) from exc
        finally:
            conn.close()


def connect(ctx) -> OtxClient:
    return OtxClient(read_key(ctx.paths.etc_dir / "ti.env"), ctx.agent_source)


def _category(tag: str) -> str | None:
    text = re.sub(r"[^a-z0-9-]+", "-", str(tag).lower()).strip("-")[:63]
    return text if text and text[0].isalnum() else None


def verdict(doc: dict) -> dict:
    """validation (np. biała lista) → benign; liczba pulse: ≥3 malicious, 1–2 suspicious,
    0 unknown. Progi wstępne, do kalibracji."""
    pulses = (doc.get("pulse_info") or {}).get("pulses") or []
    count = int((doc.get("pulse_info") or {}).get("count") or len(pulses))
    if doc.get("validation"):
        result = "benign"
    elif count >= MALICIOUS_PULSES:
        result = "malicious"
    elif count >= 1:
        result = "suspicious"
    else:
        result = "unknown"
    categories: list[str] = []
    for pulse in pulses:
        for tag in pulse.get("tags") or []:
            item = _category(tag)
            if item and item not in categories and len(categories) < MAX_CATEGORIES:
                categories.append(item)
    return {"provider": PROVIDER, "verdict": result, "categories": categories if result != "benign" else []}


def checkable(ip: str) -> bool:
    """Adresy prywatne i specjalne nie mają reputacji (np. c2-lab w sieci labu)."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


@dataclass
class TiResult:
    verdicts: dict[str, dict] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    status: str = "ok"
    note: str | None = None


def _read_cache(path: Path) -> dict:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        return doc if isinstance(doc, dict) else {}
    except (OSError, ValueError):
        return {}


def corroborate(targets: set[str], connect_client, cache_path: Path, now: float, write) -> TiResult:
    result = TiResult()
    wanted = sorted(ip for ip in targets if checkable(ip))
    cache = {ip: item for ip, item in _read_cache(cache_path).items()
             if isinstance(item, dict) and now - float(item.get("at", 0)) < CACHE_TTL_S}
    missing = [ip for ip in wanted if ip not in cache]
    client = None
    if missing:
        try:
            client = connect_client()
        except TiError as exc:
            result.status, result.note = "unavailable", str(exc)
    for ip in missing:
        if client is None:
            break
        try:
            cache[ip] = {"at": now, **verdict(client.lookup(ip))}
        except TiError as exc:
            result.errors.append(f"{ip}: {exc}")
    for ip in wanted:
        if ip in cache:
            result.verdicts[ip] = {k: cache[ip][k] for k in ("provider", "verdict", "categories")}
    if result.status == "unavailable" and result.verdicts:
        result.status = "degraded"            # część werdyktów z cache
    if result.errors:
        result.status = "degraded"
        result.note = "; ".join(result.errors)[:500]
    write(cache_path, json.dumps(cache).encode("utf-8"))
    return result

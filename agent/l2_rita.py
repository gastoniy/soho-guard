"""L2 statystyczna: wyniki RITA z ClickHouse (DYN-011b).

Import zapisuje w threat_mixtape tylko pary przeliczone w tym imporcie (ostatni może
nie mieć żadnego wiersza). Bieżący wynik to najnowsza ocena każdej pary (hash), której
last_seen mieści się w oknie danych ostatniego importu; tak samo liczy `rita view`
(porównanie na węźle 2026-11-08). Agent pyta o beacony tylko po nowym imporcie, a wynik
trzyma lokalnie: między importami finding nie znika.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

URL = "http://127.0.0.1:8123/"
DATABASE = "lab"
USER = "soho_agent"
TIMEOUT_S = 15
MAX_IMPORT_AGE_S = 7200
CACHE_FILE = "rita.json"


class RitaError(Exception):
    """ClickHouse niedostępny lub odpowiedź nieczytelna: wyniki RITA nieznane."""


class ClickHouse:
    """Zapytania HTTP z wynikiem JSONEachRow; konto tylko do odczytu."""

    def __init__(self, password: str, url: str = URL, opener=urllib.request.urlopen):
        token = base64.b64encode(f"{USER}:{password}".encode("utf-8")).decode("ascii")
        self.headers = {"Authorization": f"Basic {token}"}
        self.url = url
        self.opener = opener

    def query(self, sql: str) -> list[dict]:
        request = urllib.request.Request(self.url, data=f"{sql} FORMAT JSONEachRow".encode("utf-8"),
                                         headers=self.headers, method="POST")
        try:
            with self.opener(request, timeout=TIMEOUT_S) as response:
                body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise RitaError(f"ClickHouse HTTP {exc.code}") from exc
        except (OSError, ValueError) as exc:
            raise RitaError(f"ClickHouse: {type(exc).__name__}: {exc}") from exc
        try:
            return [json.loads(line) for line in body.splitlines() if line.strip()]
        except ValueError as exc:
            raise RitaError("ClickHouse: odpowiedź nie jest JSONEachRow") from exc


def connect(ctx) -> ClickHouse:
    try:
        password = (ctx.paths.etc_dir / "clickhouse_ro").read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RitaError("nie można odczytać pliku hasła ClickHouse") from exc
    return ClickHouse(password)


@dataclass
class RitaImport:
    import_id: str
    ended_at: float
    since: float
    until: float


@dataclass
class RitaData:
    imported: RitaImport
    rows: list[dict] = field(default_factory=list)
    fresh_query: bool = False


def latest_import(client) -> RitaImport | None:
    """Import ma dwa wiersze: przy starcie (ended_at = 0) i po zakończeniu."""
    rows = client.query(
        "SELECT hex(import_id) AS id, toUnixTimestamp(max(ended_at)) AS ended, "
        "toUnixTimestamp(max(min_timestamp)) AS since, toUnixTimestamp(max(max_timestamp)) AS until "
        f"FROM metadatabase.imports WHERE database = '{DATABASE}' GROUP BY id HAVING ended > 0 "
        "ORDER BY ended DESC LIMIT 1")
    if not rows:
        return None
    row = rows[0]
    return RitaImport(str(row["id"]), float(row["ended"]), float(row["since"]), float(row["until"]))


def ipv4(value: str | None) -> str | None:
    """RITA zapisuje adresy jako IPv6 (::ffff:a.b.c.d)."""
    try:
        ip = ipaddress.ip_address(value or "")
    except ValueError:
        return None
    if ip.version == 6:
        ip = ip.ipv4_mapped
    return str(ip) if ip else None


def beacons(client, since: float, wan: str) -> list[dict]:
    """Najnowsza ocena każdej pary z danymi w oknie; próg wyniku dopiero po jej wyborze,
    żeby starsza, wyższa ocena nie zastąpiła nowszej. Jedna analiza zapisuje dla pary
    kilka wierszy o tym samym analyzed_at (np. wiersz modyfikatorów z wynikiem 0 i wiersz
    sni z wynikiem beaconu; węzeł, 2026-11-09), więc w obrębie analizy wygrywa najwyższy
    wynik, tak jak w `rita view`."""
    rows = client.query(
        "SELECT * FROM (SELECT IPv6NumToString(src) AS src, IPv6NumToString(dst) AS dst, fqdn, "
        "arrayMap(x -> IPv6NumToString(x), server_ips) AS server_ips, port_proto_service, beacon_type, "
        "beacon_score, count, total_bytes, toUnixTimestamp(last_seen) AS last_seen, hex(import_id) AS import_id "
        f"FROM {DATABASE}.threat_mixtape WHERE last_seen >= toDateTime({int(since)}) "
        "ORDER BY analyzed_at DESC, beacon_score DESC LIMIT 1 BY hash) WHERE beacon_score > 0")
    found = []
    for row in rows:
        if ipv4(row.get("src")) != wan:
            continue
        found.append({**row, "src": wan, "dst": ipv4(row.get("dst")),
                      "server_ips": [ip for ip in (ipv4(s) for s in row.get("server_ips") or []) if ip]})
    return found


def _read_cache(path: Path) -> dict | None:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        return doc if isinstance(doc.get("rows"), list) and doc.get("import_id") else None
    except (OSError, ValueError, AttributeError):
        return None


def collect(client, wan: str, cache_path: Path) -> RitaData | None:
    """None: RITA nie ma jeszcze zakończonego importu."""
    current = latest_import(client)
    if current is None:
        return None
    cached = _read_cache(cache_path)
    if cached and cached["import_id"] == current.import_id and cached.get("wan") == wan:
        return RitaData(current, cached["rows"])
    return RitaData(current, beacons(client, current.since, wan), fresh_query=True)


def save(data: RitaData, wan: str, cache_path: Path, write) -> None:
    doc = {"import_id": data.imported.import_id, "ended_at": data.imported.ended_at, "wan": wan, "rows": data.rows}
    write(cache_path, json.dumps(doc).encode("utf-8"))

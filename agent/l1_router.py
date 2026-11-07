"""L1: odczyt konfiguracji routera przez api-ssl, wyłącznie z weryfikacją CA."""
from __future__ import annotations

import functools
import ssl
import time
from dataclasses import dataclass, field

from agent.config import Context
from agent.normalize import RESOURCES, build_state, fetch_resources

API_SSL_PORT = 8729
CONNECT_TIMEOUT_S = 15
AUTH_REJECTED_TEXTS = ("invalid user name or password", "cannot log in")


@dataclass
class L1Result:
    state: dict | None = None
    raw: dict | None = None
    auth_rejected: bool = False
    duration_ms: int = 0
    errors: list[tuple[str, str]] = field(default_factory=list)   # (kod, opis)
    failed_menus: dict[str, str] = field(default_factory=dict)


def read_password(ctx: Context, account: str = "monitor") -> str:
    path = ctx.paths.etc_dir / ctx.router_id / f"{account}.pass"
    return path.read_text(encoding="utf-8").rstrip("\r\n")


def _connect(ctx: Context, username: str, password: str):
    from librouteros import connect

    context = ssl.create_default_context(cafile=str(ctx.paths.etc_dir / "ca.crt"))
    # librouteros wywołuje wrapper bez server_hostname, a weryfikacja nazwy go wymaga.
    wrapper = functools.partial(context.wrap_socket, server_hostname=ctx.mgmt_address)
    # latin-1 dekoduje każdy bajt: znak spoza ASCII w komentarzu nie zablokuje odczytu menu.
    return connect(host=ctx.mgmt_address, username=username, password=password,
                   port=API_SSL_PORT, timeout=CONNECT_TIMEOUT_S, saddr=ctx.agent_source,
                   ssl_wrapper=wrapper, encoding="latin-1")


def connect_monitor(ctx: Context, password: str):
    return _connect(ctx, "monitor", password)


def connect_remediate(ctx: Context, password: str):
    return _connect(ctx, "remediate", password)


def _classify_connect_error(exc: Exception) -> tuple[str, bool]:
    """Zwraca (kod błędu, czy router odrzucił logowanie). Tylko odrzucenie jest sygnałem
    R4; awaria łączności obniża pokrycie i nie jest wskaźnikiem kompromitacji."""
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "l1.tls-verify-failed", False
    if isinstance(exc, ssl.SSLError):
        return "l1.tls-error", False
    if isinstance(exc, OSError):
        return "l1.unreachable", False
    if any(text in str(exc).lower() for text in AUTH_REJECTED_TEXTS):
        return "l1.auth-rejected", True
    return "l1.connect-failed", False


def collect(ctx: Context, connector=connect_monitor) -> L1Result:
    start = time.monotonic()
    result = L1Result()

    def done() -> L1Result:
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result

    try:
        password = read_password(ctx)
    except OSError:
        result.errors.append(("l1.credentials-unavailable", "nie można odczytać pliku hasła konta monitor"))
        return done()

    try:
        api = connector(ctx, password)
    except Exception as exc:  # noqa: BLE001 (różne wyjątki biblioteki i gniazda)
        code, rejected = _classify_connect_error(exc)
        result.auth_rejected = rejected
        result.errors.append((code, f"połączenie z {ctx.mgmt_address}: {type(exc).__name__}: {exc}"[:500]))
        return done()

    try:
        raw = fetch_resources(api, failed=result.failed_menus)
    finally:
        try:
            api.close()
        except Exception:  # noqa: BLE001 (sesja i tak jest kończona)
            pass

    for key, message in sorted(result.failed_menus.items()):
        path = "/" + "/".join(RESOURCES[key])
        result.errors.append(("l1.read-failed", f"{path}: {message}"[:500]))
    if raw:
        result.raw = raw
        result.state = build_state(raw)
    return done()

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent import l1_router  # noqa: E402


@pytest.fixture(autouse=True)
def fast_samples(monkeypatch):
    """Próbki tablicy połączeń bez odstępu: testy nie czekają."""
    monkeypatch.setattr(l1_router, "SAMPLE_INTERVAL_S", 0)


class NoImportRita:
    """Domyślna atrapa RITA: brak zakończonego importu, więc L2 degraded jak przed iteracją 5."""

    def query(self, sql):
        return []


class UnknownTi:
    def lookup(self, ip):
        return {"pulse_info": {"count": 0, "pulses": []}, "validation": []}


@pytest.fixture(autouse=True)
def offline_l2_l3(monkeypatch):
    """Testy nie łączą się z ClickHouse ani OTX, chyba że podadzą własną atrapę."""
    from agent import l2_rita, l3_ti
    monkeypatch.setattr(l2_rita, "connect", lambda ctx: NoImportRita())
    monkeypatch.setattr(l3_ti, "connect", lambda ctx: UnknownTi())

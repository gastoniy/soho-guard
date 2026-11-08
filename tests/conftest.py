import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent import l1_router  # noqa: E402


@pytest.fixture(autouse=True)
def fast_samples(monkeypatch):
    """Próbki tablicy połączeń bez odstępu: testy nie czekają."""
    monkeypatch.setattr(l1_router, "SAMPLE_INTERVAL_S", 0)

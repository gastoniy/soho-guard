"""Logi harnessu: znaczniki w UTC, log przebiegu `<run_id>.log` obok wyniku JSON."""
from __future__ import annotations

import logging
import time
from pathlib import Path

log = logging.getLogger("harness")

LOG_FORMAT = "%(asctime)s.%(msecs)03dZ %(levelname)s %(message)s"
LOG_DATEFMT = "%Y-%m-%dT%H:%M:%S"


def log_formatter() -> logging.Formatter:
    """Znaczniki w UTC, jak czasy w treści logu i w wyniku JSON."""
    f = logging.Formatter(LOG_FORMAT, LOG_DATEFMT)
    f.converter = time.gmtime
    return f


class run_log:
    """Plik `<run_id>.log` w katalogu wyników na czas bloku `with` (konsola bez zmian).

    Bloki można zagnieżdżać: log kampanii zbiera wszystko, log przebiegu — tylko swój przebieg."""

    def __init__(self, results_dir: Path, run_id: str):
        results_dir.mkdir(parents=True, exist_ok=True)
        self.handler = logging.FileHandler(results_dir / f"{run_id}.log", encoding="utf-8")
        self.handler.setFormatter(log_formatter())

    def __enter__(self):
        log.addHandler(self.handler)
        return self

    def __exit__(self, *exc):
        log.removeHandler(self.handler)
        self.handler.close()
        return False

"""Dostęp do routera wyłącznie kontem `ansible`: playbooki scenariuszy i odczyt obiektu (H5).

Ansible działa na `localhost` (moduły `community.routeros` łączą się z api-ssl routera
z weryfikacją CA). Hasło konta `ansible` pochodzi z pliku Vault routera (`-e @<vault_file>`,
`--vault-password-file`); w wierszu poleceń i w wyniku nie ma żadnej wartości tajnej.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

from . import REPO_ROOT, HarnessError
from .config import Config, RouterCfg

Runner = Callable[..., subprocess.CompletedProcess]

READ_PLAYBOOK = "playbooks/common/read.yml"
OUTPUT_TAIL = 2000


class Ansible:
    def __init__(self, cfg: Config, runner: Runner = subprocess.run):
        self.cfg = cfg
        self._run = runner

    def command(self, playbook: str, router: RouterCfg, tags: str | None,
                extra: dict | None = None) -> list[str]:
        evars = {
            "router_id": router.router_id,
            "router_host": router.mgmt_address,
            "router_api_port": router.api_port,
            "router_ca_path": str(self.cfg.ca_path),
            **(extra or {}),
        }
        cmd = [self.cfg.ansible_playbook,
               "-i", str(self.cfg.inventory),
               "--vault-password-file", str(self.cfg.vault_password_file),
               "-e", f"@{router.vault_file}",
               "-e", json.dumps(evars, sort_keys=True)]
        if tags:
            cmd += ["--tags", tags]
        cmd.append(playbook)
        return cmd

    def playbook(self, playbook: str, router: RouterCfg, tags: str | None = None,
                 extra: dict | None = None) -> None:
        if not (REPO_ROOT / playbook).is_file():
            raise HarnessError(f"brak playbooka {playbook}")
        cmd = self.command(playbook, router, tags, extra)
        try:
            p = self._run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True,
                          timeout=self.cfg.ansible_timeout_s,
                          env=_ansible_env())
        except subprocess.TimeoutExpired:
            raise HarnessError(f"{playbook} [{tags}]: przekroczony czas "
                               f"{self.cfg.ansible_timeout_s} s") from None
        except OSError as e:
            raise HarnessError(f"nie można uruchomić {cmd[0]}: {e}") from None
        if p.returncode != 0:
            tail = (p.stdout + p.stderr)[-OUTPUT_TAIL:]
            raise HarnessError(f"{playbook} [{tags}]: kod {p.returncode}\n{tail}")

    def read(self, router: RouterCfg, path: str) -> list[dict]:
        """Odczyt menu RouterOS (np. `ip socks`) przez `community.routeros.api_info` → lista wierszy."""
        with tempfile.TemporaryDirectory(prefix="harness-read-") as d:
            out = Path(d) / "read.json"
            self.playbook(READ_PLAYBOOK, router, None, {"read_path": path, "read_out": str(out)})
            try:
                rows = json.loads(out.read_text(encoding="utf-8"))
            except (OSError, ValueError) as e:
                raise HarnessError(f"odczyt '{path}': brak lub błędny JSON ({e})") from None
        if not isinstance(rows, list):
            raise HarnessError(f"odczyt '{path}': oczekiwano listy wierszy")
        return rows


def _ansible_env() -> dict:
    env = dict(os.environ)
    env.update({"ANSIBLE_NOCOLOR": "1", "ANSIBLE_RETRY_FILES_ENABLED": "0"})
    return env

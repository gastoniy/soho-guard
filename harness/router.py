"""Dostęp do routera wyłącznie kontem `ansible`: playbooki scenariuszy, odczyt obiektów (H5)
i eksport konfiguracji przez SSH (bramka).

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
ROUTER_ACCOUNT = "ansible"
EXPORT_CMD = "/export terse hide-sensitive"


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
        """Odczyt jednego menu RouterOS (np. `ip socks`) → lista wierszy."""
        return self.read_many(router, [path])[path]

    def read_many(self, router: RouterCfg, paths: list[str],
                  raw: bool = False) -> dict[str, list[dict]]:
        """Odczyt kilku menu jednym przebiegiem playbooka → {menu: wiersze}.

        raw=False: `api_info` (wartości typowane, menu musi mieć model dla wersji RouterOS);
        raw=True: zwykły print przez `community.routeros.api` (dowolna wersja, wartości jako tekst).
        Plik pośredni (0600) leży w katalogu tymczasowym usuwanym zaraz po odczycie."""
        with tempfile.TemporaryDirectory(prefix="harness-read-") as d:
            out = Path(d) / "read.json"
            self.playbook(READ_PLAYBOOK, router, None,
                          {"read_paths": list(paths), "read_out": str(out),
                           "read_raw": raw})
            try:
                doc = json.loads(out.read_text(encoding="utf-8"))
            except (OSError, ValueError) as e:
                raise HarnessError(f"odczyt {paths}: brak lub błędny JSON ({e})") from None
        if not isinstance(doc, dict) or any(not isinstance(doc.get(p), list) for p in paths):
            raise HarnessError(f"odczyt {paths}: oczekiwano mapy menu → lista wierszy")
        return {p: doc[p] for p in paths}


class Ssh:
    """`/export terse hide-sensitive` kontem `ansible` (klient z `-F <ssh_config>` harnessu)."""

    def __init__(self, cfg: Config, runner: Runner = subprocess.run):
        self.cfg = cfg
        self._run = runner

    def command(self, router: RouterCfg) -> list[str]:
        return [self.cfg.ssh_bin, "-F", str(self.cfg.ssh_config), "-l", ROUTER_ACCOUNT,
                "-o", "BatchMode=yes", router.mgmt_address, EXPORT_CMD]

    def export(self, router: RouterCfg) -> str:
        if self.cfg.ssh_config is None:
            raise HarnessError("harness.yml: brak ssh.config")
        cmd = self.command(router)
        try:
            p = self._run(cmd, capture_output=True, text=True, timeout=self.cfg.ssh_timeout_s)
        except subprocess.TimeoutExpired:
            raise HarnessError(f"ssh {router.router_id}: przekroczony czas "
                               f"{self.cfg.ssh_timeout_s} s") from None
        except OSError as e:
            raise HarnessError(f"nie można uruchomić {cmd[0]}: {e}") from None
        if p.returncode != 0:
            raise HarnessError(f"ssh {router.router_id} /export: kod {p.returncode}: "
                               f"{p.stderr.strip()[-OUTPUT_TAIL:]}")
        return p.stdout


def _ansible_env() -> dict:
    env = dict(os.environ)
    env.update({"ANSIBLE_NOCOLOR": "1", "ANSIBLE_RETRY_FILES_ENABLED": "0"})
    return env

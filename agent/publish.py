"""Publikacja do repo instalacji (ADR-005 R9).

Niewysłane dane czekają w outboxie, nie w gicie. Commit powstaje dopiero przy publikacji,
w tymczasowym worktree: dane routera wychodzą więc wyłącznie przez jego łącze, a czas
commita, który sprawdza watcher, to czas publikacji. Commity czekające we wspólnym klonie
wyszłyby przy pushu drugiego routera i ukryły brak egresu przez pierwszy.
"""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from agent.config import ConfigError, Context, LockTimeout, Paths, site_lock

MAIN = "main"
GIT_TIMEOUT = 30
MAX_ATTEMPTS = 2
MAX_MESSAGE = 200
VOLATILE_STATE = ("last_run", "heartbeat")


class PublishError(Exception):
    """Operacja git się nie udała; dane zostają lokalnie do kolejnej próby."""


def git_env(paths: Paths, source: str) -> dict:
    ssh = shlex.join(["ssh", "-b", source, "-i", str(paths.deploy_key),
                      "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
                      "-o", f"UserKnownHostsFile={paths.known_hosts}", "-o", "BatchMode=yes",
                      "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2"])
    return {**os.environ, "GIT_SSH_COMMAND": ssh, "GIT_TERMINAL_PROMPT": "0"}


def state_digest(state_doc: dict) -> str:
    """Skrót stanu bez pól zmieniających się w każdym cyklu."""
    stable = {k: v for k, v in state_doc.items() if k not in VOLATILE_STATE}
    return hashlib.sha256(json.dumps(stable, sort_keys=True).encode("utf-8")).hexdigest()


def _moment(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")


def should_publish(state_doc: dict, has_pending: bool, published: dict | None) -> bool:
    """R9: zdarzenie, zmiana stanu albo przypadający heartbeat."""
    if has_pending or not published or published["digest"] != state_digest(state_doc):
        return True
    heartbeat = state_doc["heartbeat"]
    elapsed = _moment(heartbeat["at"]) - _moment(published["at"])
    return elapsed.total_seconds() >= heartbeat["interval_s"]


class Publisher:
    """Cel publikacji jednego routera. Każda operacja git jest pod blokadą klonu."""

    def __init__(self, ctx: Context, branch: str, out_dir: Path):
        self.paths = ctx.paths
        self.router_id = ctx.router_id
        self.env = git_env(ctx.paths, ctx.agent_source)
        self.branch = branch
        self.out_dir = out_dir
        self.outbox = out_dir / "outbox"
        self.worktree = out_dir / "worktree"

    @property
    def reports_dir(self) -> Path:
        return self.outbox / "reports" / self.router_id

    @contextmanager
    def _lock(self):
        """Przekroczony czas blokady to tu błąd publikacji, a nie konfiguracji."""
        try:
            with site_lock(self.paths):
                yield
        except LockTimeout as exc:
            raise PublishError(str(exc)) from exc

    def _git(self, *args: str, cwd: Path | None = None) -> str:
        command = ["git", *args]
        process = subprocess.Popen(command, cwd=cwd or self.paths.site_dir, env=self.env, text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            out, err = process.communicate(timeout=GIT_TIMEOUT)
        except subprocess.TimeoutExpired as exc:
            # Cała grupa: ssh trzymałby potoki i communicate nie wróciłoby.
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise PublishError(f"git {args[0]}: przekroczono {GIT_TIMEOUT} s") from exc
        if process.returncode != 0:
            # Przyczyna bywa w pierwszych wierszach, na końcu git dopisuje ogólną podpowiedź.
            detail = " ".join(err.split()) or process.returncode
            raise PublishError(f"git {args[0]}: {detail}"[:MAX_MESSAGE])
        return out

    def _head(self) -> str:
        return self._git("rev-parse", "HEAD").strip()

    def _base_ref(self) -> str:
        """Nowa gałąź testowa zaczyna się od main."""
        ref = f"origin/{self.branch}"
        try:
            self._git("rev-parse", "--verify", "--quiet", f"refs/remotes/{ref}")
        except PublishError:
            return f"origin/{MAIN}"
        return ref

    def sync(self) -> bool:
        """Aktualizuje checkout z konfiguracją. Zwraca, czy HEAD się zmienił."""
        with self._lock():
            before = self._head()
            self._git("fetch", "--prune", "origin")
            self._git("merge", "--ff-only", "--quiet", f"origin/{MAIN}")
            return self._head() != before

    def published_state(self) -> dict | None:
        """Ostatni opublikowany stan: pozwala kontynuować łańcuch po utracie danych lokalnych."""
        with self._lock():
            try:
                raw = self._git("show", f"{self._base_ref()}:state/{self.router_id}.json")
            except PublishError:
                return None
        try:
            return json.loads(raw)
        except ValueError as exc:
            raise ConfigError(f"opublikowany stan {self.router_id} jest nieczytelny: {exc}") from exc

    def pending(self) -> list[Path]:
        return sorted(self.reports_dir.rglob("*.json")) if self.reports_dir.exists() else []

    def quarantine_orphans(self, head_seq: int) -> None:
        """Raport nowszy niż czoło łańcucha to ślad przerwanego cyklu: stan go nie zna,
        więc publikacja rozwidliłaby łańcuch. Findingi zostaną wykryte ponownie."""
        for path in self.pending():
            if int(path.name.split("-", 1)[0]) > head_seq:
                target = self.out_dir / "orphaned" / path.name
                target.parent.mkdir(parents=True, exist_ok=True)
                os.replace(path, target)
                print(f"[WARN] {self.router_id}: raport {path.name} poza łańcuchem, przeniesiony do {target.parent}",
                      file=sys.stderr)

    def publish(self, state_file: Path, message: str) -> None:
        """Publikuje outbox i stan. Po błędzie outbox zostaje bez zmian."""
        files = self.pending()
        with self._lock():
            for attempt in range(1, MAX_ATTEMPTS + 1):
                self._git("fetch", "--prune", "origin")
                try:
                    self._commit_and_push(files, state_file, message)
                    break
                except (PublishError, OSError) as exc:
                    if attempt == MAX_ATTEMPTS:
                        raise PublishError(str(exc)[:MAX_MESSAGE]) from exc
        for path in files:
            path.unlink()

    def _commit_and_push(self, files: list[Path], state_file: Path, message: str) -> None:
        self._discard_worktree()
        self._git("worktree", "add", "--quiet", "--detach", str(self.worktree), self._base_ref())
        try:
            copies = [(path, path.relative_to(self.outbox)) for path in files]
            copies.append((state_file, Path("state") / f"{self.router_id}.json"))
            for source, relative in copies:
                target = self.worktree / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
            self._git("add", "--", *(str(relative) for _, relative in copies), cwd=self.worktree)
            # Przerwanie po pushu, a przed czyszczeniem outboxu, daje przy ponowieniu te same pliki.
            if self._git("status", "--porcelain", cwd=self.worktree).strip():
                self._git("commit", "--quiet", "-m", message, cwd=self.worktree)
                self._git("push", "--quiet", "origin", f"HEAD:refs/heads/{self.branch}", cwd=self.worktree)
        finally:
            self._discard_worktree()

    def _discard_worktree(self) -> None:
        if self.worktree.exists():
            shutil.rmtree(self.worktree)
        self._git("worktree", "prune")

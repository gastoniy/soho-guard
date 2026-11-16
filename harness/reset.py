"""Pełny reset routera do baseline (H4).

  1. pliki do wgrania: zbiór stałych nazw z `baseline.rsc.j2` (site-lab, bieżący commit) musi się
     zgadzać z `routers.<id>.upload` w harness.yml; pliki lokalne muszą istnieć (treści nie czytamy);
  2. moment resetu: :X0 + `timing.reset_offset_s` (po odczycie L1 agenta);
  3. `playbooks/common/reset.yml --tags prepare` tuż przed tym momentem: render baseline.rsc
     (Vault), scp pod stałe nazwy, shred wyrenderowanego pliku na hoście;
  4. kontrola na routerze: komplet plików (inaczej skrypt po resecie z `keep-users=no` przerwałby się
     w połowie) — bez kompletu reset się nie odbywa, pliki są usuwane (`--tags cleanup`);
  5. `/system reset-configuration … run-after-reset=baseline.rsc` przez SSH, usunięcie wpisu
     routera z known_hosts harnessu;
  6. powrót MGMT: odczyt api-ssl (konto `ansible`, CA) się udaje i plików resetu już nie ma
     — skrypt baseline usuwa je na samym końcu, więc to dowód, że doszedł do końca;
  7. nowy klucz hosta (`accept-new`) — RouterOS 6 generuje klucz hosta dopiero przy pierwszej próbie
     połączenia po starcie („Corrupt host's key, regenerating it!”), a każda kolejna próba zaczyna
     generowanie od nowa (lab 2026-11-15: próby co 10 s przez 4,5 min bez skutku, pojedyncza próba
     po 2,5 min przerwy — od razu). Dlatego ponawianie rzadkie (`timing.ssh_retry_s`) do
     `timing.ssh_ready_timeout_s` od powrotu api-ssl; odcisk do wyniku, bramka H5 (obowiązkowa).
"""
from __future__ import annotations

import logging
import re
import subprocess
import tempfile
from datetime import timedelta
from pathlib import Path

from . import HarnessError, UsageError
from . import gate as gate_mod
from .results import RESULT_VERSION, harness_commit
from .timing import grid_offset, iso, plan_apply

log = logging.getLogger("harness")

RESET_PLAYBOOK = "playbooks/common/reset.yml"
TEMPLATE = "baseline.rsc.j2"
HOST_VARS = "host_vars.yml"
BASELINE = "baseline.rsc"
RESET_CMD = ("/system reset-configuration no-defaults=yes keep-users=no skip-backup=yes "
             f"run-after-reset={BASELINE}")
PREPARE_LEAD_S = 90      # render + scp startują tyle przed momentem resetu
RESET_SSH_TIMEOUT_S = 30
_IMPORT_RE = re.compile(r"\b(?:file-name|public-key-file)=\"?([A-Za-z0-9_.-]+)")


def required_files(template: str) -> set[str]:
    """Stałe nazwy plików, które szablon importuje po resecie (plus sam baseline.rsc).

    Linie komentarzy pomijamy — w nagłówku szablonu jest lista poglądowa."""
    names = {BASELINE}
    for ln in template.splitlines():
        if not ln.lstrip().startswith("#"):
            names.update(_IMPORT_RE.findall(ln))
    return names


def check_uploads(rcfg, required: set[str]) -> None:
    want = required - {BASELINE}
    have = set(rcfg.upload)
    if want != have:
        raise UsageError(f"harness.yml: routers.{rcfg.router_id}.upload: oczekiwane nazwy "
                         f"{sorted(want)}, jest {sorted(have)} (wg {TEMPLATE} w site-lab)")
    for name, path in sorted(rcfg.upload.items()):
        if not path.is_file() or path.stat().st_size == 0:
            raise UsageError(f"harness.yml: routers.{rcfg.router_id}.upload.{name}: "
                             f"brak pliku lub pusty: {path}")


def _ensure_removed(rendered: Path) -> None:
    """Zabezpieczenie na wypadek, gdyby `always` playbooka się nie wykonał (np. przerwanie)."""
    if not rendered.exists():
        return
    subprocess.run(["shred", "-u", str(rendered)], capture_output=True, timeout=60)
    if rendered.exists():
        raise HarnessError(f"wyrenderowany baseline nie został usunięty — usuń ręcznie: {rendered}")


def _router_files(ctx, rcfg) -> dict[str, dict]:
    rows = ctx.ansible.read_many(rcfg, ["file"], raw=True)["file"]
    return {str(r.get("name")): r for r in rows if isinstance(r, dict)}


def _size_ok(row: dict) -> bool:
    size = str(row.get("size", "")).split(" ")[0]
    return not size.isdigit() or int(size) > 0


def _new_result(run_id: str, router_id: str, now) -> dict:
    return {
        "result_version": RESULT_VERSION,
        "kind": "reset",
        "run_id": run_id,
        "harness_commit": harness_commit(),
        "router_id": router_id,
        "started_at": iso(now),
        "finished_at": None,
        "site_lab": {"sha": None},
        "files": [],
        "timing": {"planned_at": None, "offset_s": None, "reset_sent_at": None,
                   "reset_grid_offset_s": None, "mgmt_back_at": None, "mgmt_return_s": None,
                   "ssh_ready_at": None, "ssh_ready_s": None},
        "host_key": {"fingerprints": []},
        "gate": None,
        "cleanup": None,
        "ok": False,
        "error": None,
    }


def _cleanup(ctx, rcfg, names: set[str], res: dict) -> None:
    try:
        ctx.ansible.playbook(RESET_PLAYBOOK, rcfg, "cleanup", {"reset_names": sorted(names)})
        left = names & set(_router_files(ctx, rcfg))
        res["cleanup"] = "ok" if not left else f"pozostały pliki: {sorted(left)}"
    except HarnessError as e:
        res["cleanup"] = f"błąd: {e}"
    log.info("%s: sprzątanie plików resetu: %s", rcfg.router_id, res["cleanup"])


def _wait_mgmt(ctx, rcfg, names: set[str], sent_at):
    """Do `mgmt_return_timeout_s`: odczyt api-ssl działa i plików resetu nie ma (skrypt skończony)."""
    deadline = sent_at + timedelta(seconds=rcfg.mgmt_return_timeout_s)
    last = "brak odczytu"
    while True:
        try:
            left = names & set(_router_files(ctx, rcfg))
            if not left:
                return ctx.clock.now(), None
            last = f"pliki resetu nadal na routerze: {sorted(left)}"
        except HarnessError as e:
            last = f"router nieosiągalny ({str(e).splitlines()[0][:200]})"
        remaining = (deadline - ctx.clock.now()).total_seconds()
        if remaining <= 0:
            return None, last
        ctx.clock.sleep(min(ctx.cfg.timing.mgmt_poll_s, remaining))


def _wait_ssh(ctx, rcfg, deadline):
    """Pierwsze połączenie SSH z `accept-new`, ponawiane co `ssh_retry_s` do `deadline` (klucz hosta
    w trakcie generowania → rozłączenie przy wymianie kluczy, kod 255)."""
    while True:
        try:
            ctx.ssh.accept_new(rcfg)
            return ctx.clock.now(), None
        except HarnessError as e:
            last = str(e).splitlines()[0][:200]
        remaining = (deadline - ctx.clock.now()).total_seconds()
        if remaining <= 0:
            return None, last
        log.info("%s: SSH jeszcze niegotowy (%s), ponawiam za %d s", rcfg.router_id, last,
                 min(ctx.cfg.timing.ssh_retry_s, remaining))
        ctx.clock.sleep(min(ctx.cfg.timing.ssh_retry_s, remaining))


def run_reset(ctx, router_id: str, run_id: str) -> dict:
    cfg = ctx.cfg
    rcfg = cfg.router(router_id)
    if cfg.build_dir is None:
        raise UsageError("harness.yml: brak build_dir (wymagany przy pełnym resecie)")
    if cfg.ssh_known_hosts is None:
        raise UsageError("harness.yml: brak ssh.known_hosts (wymagany przy pełnym resecie)")
    res = _new_result(run_id, router_id, ctx.clock.now())

    sha = ctx.site.fetch()
    site_doc = ctx.site.site(sha)
    template = ctx.site.router_file(sha, site_doc, router_id, TEMPLATE)
    host_vars = ctx.site.router_file(sha, site_doc, router_id, HOST_VARS)
    names = required_files(template)
    check_uploads(rcfg, names)
    res["site_lab"]["sha"] = sha
    res["files"] = sorted(names)

    uploaded = sent = False
    try:
        t, off = plan_apply(ctx.clock.now() + timedelta(seconds=PREPARE_LEAD_S), cfg.timing,
                            ctx.rng, fixed_offset_s=cfg.timing.reset_offset_s)
        res["timing"].update(planned_at=iso(t), offset_s=off)
        log.info("%s: pełny reset o %s (site-lab %s)", router_id, iso(t), sha[:8])
        ctx.clock.sleep_until(t - timedelta(seconds=PREPARE_LEAD_S))

        # --- render + wgranie (rendered usuwany w `always` playbooka)
        cfg.build_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        rendered = cfg.build_dir / f"{router_id}-{run_id}.rendered.rsc"
        with tempfile.TemporaryDirectory(prefix="harness-reset-") as d:
            (Path(d) / TEMPLATE).write_text(template, encoding="utf-8")
            (Path(d) / HOST_VARS).write_text(host_vars, encoding="utf-8")
            uploaded = True      # od tej chwili na routerze mogą być pliki resetu
            try:
                ctx.ansible.playbook(RESET_PLAYBOOK, rcfg, "prepare", {
                    "reset_template": str(Path(d) / TEMPLATE),
                    "reset_host_vars": str(Path(d) / HOST_VARS),
                    "reset_rendered": str(rendered),
                    "reset_uploads": [{"src": str(p), "dst": n}
                                      for n, p in sorted(rcfg.upload.items())],
                    "baseline_rev": sha,
                    "ssh_config": str(cfg.ssh_config),
                    "scp_bin": cfg.scp_bin,
                    "router_account": "ansible",
                })
            finally:
                _ensure_removed(rendered)

        # --- komplet plików na routerze
        files = _router_files(ctx, rcfg)
        missing = sorted(n for n in names if n not in files or not _size_ok(files[n]))
        if missing:
            raise HarnessError(f"po wgraniu brak plików na routerze (lub puste): {missing}")
        log.info("%s: wgrane %d pliki, komplet na routerze", router_id, len(names))

        if ctx.clock.now() > t:      # przygotowanie trwało za długo → następny cykl
            t, off = plan_apply(ctx.clock.now(), cfg.timing, ctx.rng,
                                fixed_offset_s=cfg.timing.reset_offset_s)
            res["timing"].update(planned_at=iso(t), offset_s=off)
        ctx.clock.sleep_until(t)

        # --- reset (połączenie zrywa się razem z restartem — kod SSH bez znaczenia)
        sent_at = ctx.clock.now()
        try:
            ctx.ssh.run(rcfg, RESET_CMD, timeout=RESET_SSH_TIMEOUT_S, input="y\n", check=False)
        except HarnessError as e:
            if "przekroczony czas" not in str(e):
                raise
        sent = True
        res["timing"].update(reset_sent_at=iso(sent_at),
                             reset_grid_offset_s=round(grid_offset(sent_at, cfg.timing.cycle_s), 3))
        log.info("%s: reset wysłany, czekam na MGMT do %d s", router_id, rcfg.mgmt_return_timeout_s)
        ctx.ssh.forget_host(rcfg)

        back_at, why = _wait_mgmt(ctx, rcfg, names, sent_at)
        if back_at is None:
            raise HarnessError(f"MGMT nie wrócił w {rcfg.mgmt_return_timeout_s} s: {why}")
        res["timing"].update(mgmt_back_at=iso(back_at),
                             mgmt_return_s=round((back_at - sent_at).total_seconds(), 3))
        log.info("%s: MGMT po %.0f s", router_id, (back_at - sent_at).total_seconds())

        ssh_deadline = back_at + timedelta(seconds=cfg.timing.ssh_ready_timeout_s)
        ssh_at, why = _wait_ssh(ctx, rcfg, ssh_deadline)
        if ssh_at is None:
            raise HarnessError(f"SSH niegotowy do {iso(ssh_deadline)}: {why}")
        res["timing"].update(ssh_ready_at=iso(ssh_at),
                             ssh_ready_s=round((ssh_at - sent_at).total_seconds(), 3))
        res["host_key"]["fingerprints"] = ctx.ssh.fingerprints(rcfg)

        g = gate_mod.check(ctx.ssh, ctx.ansible, ctx.site, sha, site_doc, rcfg)
        res["gate"] = g.as_dict()
        res["ok"] = g.ok
        if not g.ok:
            res["error"] = g.summary()
    except HarnessError as e:
        res["error"] = str(e)
    except KeyboardInterrupt:
        res["error"] = "przerwane przez operatora (Ctrl-C)"
        res["interrupted"] = True
    finally:
        # reset się nie odbył albo skrypt baseline nie doszedł do końca: pliki z hasłami
        # mogą zostać na routerze — próba usunięcia (przy niedostępnym routerze tylko zapis błędu)
        if uploaded and (not sent or res["timing"]["mgmt_back_at"] is None):
            _cleanup(ctx, rcfg, names, res)
        res["finished_at"] = iso(ctx.clock.now())
    log.info("%s: reset %s%s", router_id, "ok" if res["ok"] else "NIEUDANY",
             "" if res["ok"] else f": {res['error']}")
    return res

"""CLI harnessu.

  python -m harness [--config harness.yml] run <manifest> [--target R] [--repeat N] [--offset S]
                                                [--seed N] [--close-artifacts]
  python -m harness [--config harness.yml] gate <router> [--dump-objects]

Kody wyjścia: 0 wszystkie `pass` (gate: zgodna); 1 co najmniej jeden `fail`/`timeout`;
2 błędne argumenty, konfiguracja lub manifest; 3 `invalid`, `error` albo nieudany teardown
(kolejne powtórzenia przerwane; gate: niezgodna lub błąd).
"""
from __future__ import annotations

import argparse
import logging
import os
import random
import sys
import time
from pathlib import Path

from . import HarnessError, UsageError
from . import config as config_mod
from . import gate as gate_mod
from .artifacts import GitHub
from .results import new_run_id, write
from .router import Ansible, Ssh
from .scenario import Context, run_scenario
from .sitelab import SiteLab
from .timing import Clock

log = logging.getLogger("harness")

EXIT_OK, EXIT_FAIL, EXIT_USAGE, EXIT_ABORT = 0, 1, 2, 3
LOG_FORMAT = "%(asctime)s.%(msecs)03dZ %(levelname)s %(message)s"
LOG_DATEFMT = "%Y-%m-%dT%H:%M:%S"


def log_formatter() -> logging.Formatter:
    """Znaczniki w UTC, jak czasy w treści logu i w wyniku JSON."""
    f = logging.Formatter(LOG_FORMAT, LOG_DATEFMT)
    f.converter = time.gmtime
    return f


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m harness", description="Harness scenariuszy soho-guard")
    p.add_argument("--config", help=f"harness.yml (domyślnie ${config_mod.ENV_VAR} "
                                    f"lub harness/harness.yml w repo)")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="przebieg scenariusza")
    r.add_argument("manifest", type=Path)
    r.add_argument("--target", help="router z site.yml zamiast target.router_id manifestu (D-B)")
    r.add_argument("--repeat", type=int, default=1, help="liczba powtórzeń (domyślnie 1)")
    r.add_argument("--offset", type=float, help="stałe przesunięcie apply względem siatki cyklu [s]")
    r.add_argument("--seed", type=int, help="ziarno losowania przesunięcia (powtarzalność)")
    r.add_argument("--close-artifacts", action="store_true",
                   help="zamknij PR/issue agenta z tego przebiegu (H9; domyślnie tylko odczyt)")
    g = sub.add_parser("gate", help="bramka H5: czy router jest w baseline")
    g.add_argument("router")
    g.add_argument("--dump-objects", action="store_true",
                   help="wzorzec gate-objects.yml z bieżącego stanu routera (bez porównania)")
    g.add_argument("--output", type=Path,
                   help="z --dump-objects: zapisz do pliku (tylko po udanym odczycie) zamiast na stdout")
    return p


def build_context(cfg: config_mod.Config, seed: int | None) -> Context:
    if seed is None:
        seed = random.SystemRandom().randrange(2**32)
    return Context(
        cfg=cfg,
        ansible=Ansible(cfg),
        site=SiteLab(cfg.site_lab_clone, cfg.site_lab_remote, cfg.site_lab_branch),
        clock=Clock(),
        rng=random.Random(seed),
        seed=seed,
        ssh=Ssh(cfg),
        github=GitHub(cfg.gh_bin, cfg.site_lab_clone),
    )


def cmd_run(args, ctx: Context) -> int:
    if args.repeat < 1:
        raise UsageError("--repeat musi być ≥ 1")
    code = EXIT_OK
    for i in range(1, args.repeat + 1):
        run_id = new_run_id(ctx.clock.now())
        ctx.cfg.results_dir.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(ctx.cfg.results_dir / f"{run_id}.log", encoding="utf-8")
        handler.setFormatter(log_formatter())
        log.addHandler(handler)
        try:
            log.info("przebieg %s: %s [%d/%d], seed=%s", run_id, args.manifest, i, args.repeat,
                     ctx.seed)
            res = run_scenario(ctx, args.manifest, target=args.target, offset_s=args.offset,
                               close_artifacts=args.close_artifacts, run_id=run_id)
            res["repeat"] = {"index": i, "of": args.repeat}
            path = write(res, ctx.cfg.results_dir)
        finally:
            log.removeHandler(handler)
            handler.close()
        m = res.get("metrics") or {}
        td_ok = res["teardown"]["ok"] is not False
        print(f"[{i}/{args.repeat}] {res['manifest']['id']} {res['target']['router_id']}: "
              f"{res['verdict']}"
              + (f" mttd={m['mttd_s']}s" if m.get("mttd_s") is not None else "")
              + ("" if td_ok else " TEARDOWN-NIEZGODNY")
              + f" → {path}")
        for reason in res["reasons"]:
            print(f"    {reason}")
        if not td_ok:
            print(f"    teardown: {res['teardown']['error']}")
        if res["verdict"] in ("invalid", "error") or not td_ok or res.get("interrupted"):
            return EXIT_ABORT
        if res["verdict"] in ("fail", "timeout"):
            code = EXIT_FAIL
    return code


def cmd_gate(args, ctx: Context) -> int:
    rcfg = ctx.cfg.router(args.router)
    try:
        if args.dump_objects:
            objs = gate_mod.read_objects(ctx.ansible, rcfg)
            text = gate_mod.dump_objects(args.router, objs, ctx.clock.now())
            if args.output is None:
                sys.stdout.write(text)
            else:
                tmp = args.output.with_name(args.output.name + ".tmp")
                tmp.write_text(text, encoding="utf-8")
                os.replace(tmp, args.output)
                print(f"{args.router}: wzorzec obiektów zapisany w {args.output}")
            return EXIT_OK
        if args.output is not None:
            raise UsageError("--output tylko z --dump-objects")
        sha = ctx.site.fetch()
        g = gate_mod.check(ctx.ssh, ctx.ansible, ctx.site, sha, ctx.site.site(sha), rcfg)
    except HarnessError as e:
        print(f"błąd: {e}", file=sys.stderr)
        return EXIT_ABORT
    if g.ok:
        print(f"{args.router}: bramka zgodna (site-lab {sha[:8]})")
        return EXIT_OK
    print(f"{args.router}: {g.summary()} (site-lab {sha[:8]})")
    for ln in g.export_diff + g.objects_diff:
        print(f"    {ln}")
    return EXIT_ABORT


def main(argv: list[str] | None = None, context_factory=build_context) -> int:
    if not logging.getLogger().handlers:
        console = logging.StreamHandler(sys.stderr)
        console.setFormatter(log_formatter())
        logging.basicConfig(level=logging.INFO, handlers=[console])
    log.setLevel(logging.INFO)      # niezależnie od konfiguracji root (log do pliku przebiegu)
    args = _parser().parse_args(argv)
    try:
        cfg = config_mod.load(config_mod.resolve_path(args.config))
        ctx = context_factory(cfg, getattr(args, "seed", None))
        if args.cmd == "run":
            return cmd_run(args, ctx)
        if args.cmd == "gate":
            return cmd_gate(args, ctx)
    except UsageError as e:
        print(f"błąd: {e}", file=sys.stderr)
        return EXIT_USAGE
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())

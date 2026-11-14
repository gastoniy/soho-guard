"""CLI harnessu.

  python -m harness [--config harness.yml] run <manifest> [--target R] [--repeat N] [--offset S] [--seed N]

Kody wyjścia: 0 wszystkie `pass`; 1 co najmniej jeden `fail`/`timeout`; 2 błędne argumenty,
konfiguracja lub manifest; 3 `invalid` lub `error` (kolejne powtórzenia przerwane).
"""
from __future__ import annotations

import argparse
import logging
import random
import sys
from pathlib import Path

from . import UsageError
from . import config as config_mod
from .results import write
from .router import Ansible
from .scenario import Context, run_scenario
from .sitelab import SiteLab
from .timing import Clock

log = logging.getLogger("harness")

EXIT_OK, EXIT_FAIL, EXIT_USAGE, EXIT_ABORT = 0, 1, 2, 3


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m harness", description="Harness scenariuszy soho-guard")
    p.add_argument("--config", help=f"harness.yml (domyślnie ${config_mod.ENV_VAR} "
                                    f"lub {config_mod.DEFAULT_PATH})")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="przebieg scenariusza")
    r.add_argument("manifest", type=Path)
    r.add_argument("--target", help="router z site.yml zamiast target.router_id manifestu (D-B)")
    r.add_argument("--repeat", type=int, default=1, help="liczba powtórzeń (domyślnie 1)")
    r.add_argument("--offset", type=float, help="stałe przesunięcie apply względem siatki cyklu [s]")
    r.add_argument("--seed", type=int, help="ziarno losowania przesunięcia (powtarzalność)")
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
    )


def cmd_run(args, ctx: Context) -> int:
    if args.repeat < 1:
        raise UsageError("--repeat musi być ≥ 1")
    code = EXIT_OK
    for i in range(1, args.repeat + 1):
        res = run_scenario(ctx, args.manifest, target=args.target, offset_s=args.offset)
        res["repeat"] = {"index": i, "of": args.repeat}
        path = write(res, ctx.cfg.results_dir)
        m = res.get("metrics") or {}
        print(f"[{i}/{args.repeat}] {res['manifest']['id']} {res['target']['router_id']}: "
              f"{res['verdict']}"
              + (f" mttd={m['mttd_s']}s" if m.get("mttd_s") is not None else "")
              + f" → {path}")
        for reason in res["reasons"]:
            print(f"    {reason}")
        if res["verdict"] in ("invalid", "error"):
            return EXIT_ABORT
        if res["verdict"] in ("fail", "timeout"):
            code = EXIT_FAIL
    return code


def main(argv: list[str] | None = None, context_factory=build_context) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", stream=sys.stderr)
    args = _parser().parse_args(argv)
    try:
        cfg = config_mod.load(config_mod.resolve_path(args.config))
        ctx = context_factory(cfg, args.seed)
        if args.cmd == "run":
            return cmd_run(args, ctx)
    except UsageError as e:
        print(f"błąd: {e}", file=sys.stderr)
        return EXIT_USAGE
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())

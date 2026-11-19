"""CLI harnessu.

  python -m harness [--config harness.yml] run <manifest> [--target R] [--repeat N] [--offset S]
                                                [--seed N] [--close-artifacts]
  python -m harness [--config harness.yml] pair <dyn-manifest> <ctl-manifest> [--offset S]
                                                [--seed N] [--close-artifacts] [--operator-checks F]
  python -m harness [--config harness.yml] gate <router> [--dump-objects]
  python -m harness [--config harness.yml] reset <router> --yes
  python -m harness [--config harness.yml] campaign <plan.yml> [--seed N] [--check]
                                                [--operator-checks F]
  python -m harness summary <wynik.json|katalog|kampania.json>... [--csv F] [--agg-csv F]

Kody wyjścia: 0 wszystkie `pass` (gate: zgodna); 1 co najmniej jeden `fail`/`timeout`;
2 błędne argumenty, konfiguracja lub manifest; 3 `invalid`, `error` albo nieudany teardown
(kolejne powtórzenia przerwane; gate: niezgodna lub błąd; reset: nieudany lub bramka niezgodna;
campaign: kampania przerwana).
"""
from __future__ import annotations

import argparse
import logging
import os
import random
import sys
from pathlib import Path

from . import HarnessError, UsageError
from . import config as config_mod
from . import gate as gate_mod
from .logs import log_formatter, run_log
from .artifacts import GitHub
from . import campaign as campaign_mod
from . import summary as summary_mod
from .reset import run_reset
from .results import new_run_id, write, write_pair, write_reset
from .router import Ansible, Ssh
from .scenario import Context, run_scenario
from .pair import load_operator_checks, run_pair
from .sitelab import SiteLab
from .timing import Clock

log = logging.getLogger("harness")

EXIT_OK, EXIT_FAIL, EXIT_USAGE, EXIT_ABORT = 0, 1, 2, 3
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
    pr = sub.add_parser("pair", help="skoordynowany przebieg pary DYN-011b + CTL-001 (iteracja 5)")
    pr.add_argument("dynamic", type=Path, help="manifest dynamiczny z detekcją (DYN-011b)")
    pr.add_argument("control", type=Path, help="manifest control bez detekcji (CTL-001)")
    pr.add_argument("--offset", type=float, help="stałe przesunięcie apply względem siatki cyklu [s]")
    pr.add_argument("--seed", type=int, help="ziarno losowania przesunięcia (powtarzalność)")
    pr.add_argument("--close-artifacts", action="store_true",
                    help="zamknij PR/issue agenta z tego przebiegu (H9; domyślnie tylko odczyt)")
    pr.add_argument("--operator-checks", type=Path,
                    help="YAML z check-rita-dyn011b.sh (warunki startu; cel ruchu)")
    g = sub.add_parser("gate", help="bramka H5: czy router jest w baseline")
    g.add_argument("router")
    g.add_argument("--dump-objects", action="store_true",
                   help="wzorzec gate-objects.yml z bieżącego stanu routera (bez porównania)")
    g.add_argument("--output", type=Path,
                   help="z --dump-objects: zapisz do pliku (tylko po udanym odczycie) zamiast na stdout")
    x = sub.add_parser("reset", help="pełny reset routera do baseline (H4) + bramka")
    x.add_argument("router")
    x.add_argument("--yes", action="store_true",
                   help="potwierdzenie: reset kasuje całą konfigurację routera")
    c = sub.add_parser("campaign", help="kampania wg planu (harness/campaigns/*.yml)")
    c.add_argument("plan", type=Path)
    c.add_argument("--seed", type=int, help="ziarno losowania przesunięć (powtarzalność)")
    c.add_argument("--check", action="store_true",
                   help="tylko walidacja planu i lista kroków, bez działań na routerach")
    c.add_argument("--operator-checks", type=Path,
                   help="YAML z check-rita-dyn011b.sh dla kroku pary (plan z jednym krokiem pary)")
    s = sub.add_parser("summary", help="zestawienie wyników (Markdown, opcjonalnie CSV)")
    s.add_argument("paths", type=Path, nargs="+")
    s.add_argument("--csv", type=Path, help="CSV: wiersz na przebieg")
    s.add_argument("--agg-csv", type=Path, help="CSV: agregaty per manifest × router")
    return p


def terminal_prompt(text: str) -> None:
    """Potwierdzenie operatora (generate.from=client): komunikat na stderr, czekanie na Enter."""
    log.info("czekam na operatora: %s", text)
    print(f"\n>>> {text}", file=sys.stderr, flush=True)
    try:
        input()
    except EOFError:
        raise HarnessError("brak terminala do potwierdzenia operatora (stdin zamknięty)") from None
    log.info("operator potwierdził")


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
        prompt=terminal_prompt,
    )


def cmd_run(args, ctx: Context) -> int:
    if args.repeat < 1:
        raise UsageError("--repeat musi być ≥ 1")
    code = EXIT_OK
    for i in range(1, args.repeat + 1):
        run_id = new_run_id(ctx.clock.now())
        with run_log(ctx.cfg.results_dir, run_id):
            log.info("przebieg %s: %s [%d/%d], seed=%s", run_id, args.manifest, i, args.repeat,
                     ctx.seed)
            res = run_scenario(ctx, args.manifest, target=args.target, offset_s=args.offset,
                               close_artifacts=args.close_artifacts, run_id=run_id,
                               gen_index=i - 1)
            res["repeat"] = {"index": i, "of": args.repeat}
            path = write(res, ctx.cfg.results_dir)
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


def cmd_pair(args, ctx: Context) -> int:
    checks = load_operator_checks(args.operator_checks) if args.operator_checks else None
    run_id = new_run_id(ctx.clock.now())
    with run_log(ctx.cfg.results_dir, run_id):
        log.info("pair %s: %s + %s, seed=%s", run_id, args.dynamic, args.control, ctx.seed)
        res = run_pair(ctx, args.dynamic, args.control, offset_s=args.offset,
                       close_artifacts=args.close_artifacts, run_id=run_id,
                       operator_checks=checks)
        path = write_pair(res, ctx.cfg.results_dir)
    td_ok = res["teardown"]["ok"] is not False
    m = res["dynamic"].get("metrics") or {}
    print(f"pair {res['pair']['dynamic_id']}+{res['pair']['control_id']}: {res['verdict']}"
          f" (dynamic={res['dynamic']['verdict']}, control={res['control']['verdict']})"
          + (f" mttd={m['mttd_s']}s" if m.get("mttd_s") is not None else "")
          + ("" if td_ok else " TEARDOWN-NIEZGODNY") + f" → {path}")
    for reason in res["reasons"]:
        print(f"    {reason}")
    if not td_ok:
        print(f"    teardown: {res['teardown']['error']}")
    if res["verdict"] in ("invalid", "error") or not td_ok or res.get("interrupted"):
        return EXIT_ABORT
    return EXIT_FAIL if res["verdict"] in ("fail", "timeout") else EXIT_OK


def cmd_reset(args, ctx: Context) -> int:
    if not args.yes:
        raise UsageError("reset kasuje całą konfigurację routera — potwierdź opcją --yes")
    run_id = new_run_id(ctx.clock.now())
    with run_log(ctx.cfg.results_dir, run_id):
        log.info("reset %s: %s", run_id, args.router)
        try:
            res = run_reset(ctx, args.router, run_id)
        except HarnessError as e:          # przed jakimkolwiek działaniem na routerze
            print(f"błąd: {e}", file=sys.stderr)
            return EXIT_ABORT
        path = write_reset(res, ctx.cfg.results_dir)
    t = res["timing"]
    if res["ok"]:
        print(f"{args.router}: reset ok, MGMT po {t['mgmt_return_s']} s, bramka zgodna → {path}")
        return EXIT_OK
    print(f"{args.router}: reset NIEUDANY: {res['error']} → {path}")
    if res.get("cleanup"):
        print(f"    sprzątanie plików resetu: {res['cleanup']}")
    for ln in (res["gate"] or {}).get("export_diff", []) + (res["gate"] or {}).get("objects_diff", []):
        print(f"    {ln}")
    return EXIT_ABORT


def cmd_campaign(args, ctx: Context) -> int:
    plan = campaign_mod.load_plan(args.plan, ctx.cfg)
    checks = load_operator_checks(args.operator_checks) if args.operator_checks else None
    n_pairs = sum(st["repeat"] for st in plan["steps"] if st["control_path"] is not None)
    if checks is not None and n_pairs != 1:
        raise UsageError(f"--operator-checks wymaga planu z dokładnie jednym przebiegiem pary "
                         f"(jest {n_pairs}) — każdy przebieg ma własny cel i odczyt z węzła")
    total = sum(st["repeat"] for st in plan["steps"])
    print(f"kampania {plan['campaign_id']}: reset na starcie {plan['reset_at_start'] or '—'}, "
          f"{len(plan['steps'])} kroków, {total} przebiegów, close_artifacts={plan['close_artifacts']}")
    for st in plan["steps"]:
        print(f"  {st['index']}. {st['id']}" + (f"+{st['control_id']}" if st["control_path"] else "")
              + f" {st['target']} ×{st['repeat']}"
              + (f" offset={st['offset']}" if st["offset"] is not None else ""))
    for w in plan["order_warnings"]:
        print(f"  ostrzeżenie: {w}")
    if args.check:
        return EXIT_OK
    run_id = new_run_id(ctx.clock.now())
    with run_log(ctx.cfg.results_dir, run_id):
        summary = campaign_mod.run_campaign(ctx, plan, run_id, operator_checks=checks)
    counts = ", ".join(f"{k}={v}" for k, v in sorted(summary["counts"].items())) or "brak przebiegów"
    print(f"kampania {plan['campaign_id']} ({run_id}): {counts}")
    for r in summary["resets"]:
        print(f"  reset {r['router_id']} ({r['reason']}): {'ok' if r['ok'] else 'NIEUDANY'}"
              + ("" if r["ok"] else f" — {r['error']}"))
    if summary["aborted"]:
        print(f"  PRZERWANA: {summary['aborted']}")
        return EXIT_ABORT
    return EXIT_FAIL if any(r["verdict"] in ("fail", "timeout") for r in summary["runs"]) else EXIT_OK


def cmd_summary(args) -> int:
    rows = [r for d in summary_mod.collect(args.paths) for r in summary_mod.run_rows(d)]
    if not rows:
        raise UsageError("brak wyników przebiegów we wskazanych ścieżkach")
    aggs = summary_mod.aggregate(rows)
    sys.stdout.write(summary_mod.markdown(rows, aggs))
    if args.csv:
        summary_mod.write_csv(args.csv, rows, summary_mod.RUN_FIELDS)
    if args.agg_csv:
        summary_mod.write_csv(args.agg_csv, aggs, summary_mod.AGG_FIELDS)
    return EXIT_OK


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
        if args.cmd == "summary":            # bez konfiguracji i bez dostępu do labu
            return cmd_summary(args)
        cfg = config_mod.load(config_mod.resolve_path(args.config))
        ctx = context_factory(cfg, getattr(args, "seed", None))
        if args.cmd == "run":
            return cmd_run(args, ctx)
        if args.cmd == "pair":
            return cmd_pair(args, ctx)
        if args.cmd == "gate":
            return cmd_gate(args, ctx)
        if args.cmd == "reset":
            return cmd_reset(args, ctx)
        if args.cmd == "campaign":
            return cmd_campaign(args, ctx)
    except UsageError as e:
        print(f"błąd: {e}", file=sys.stderr)
        return EXIT_USAGE
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())

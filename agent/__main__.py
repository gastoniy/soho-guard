"""CLI i cykl agenta: python -m agent --router r1 --once (--dry-run | --no-remediate)."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from agent import evidence, l1_router, mitigate, policy, report
from agent.config import ConfigError, Context, Paths, load_context
from agent.findings import ACCESS_LOST_RULE, access_lost_violation, fingerprint, reconcile
from agent.publish import MAIN, Publisher, PublishError, should_publish, state_digest
from agent.static_eval import EvalResult, evaluate

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from validate_report import validate_report, validate_state  # noqa: E402

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_BUSY = 3
MAX_NOTE = 500
TEST_BRANCH = re.compile(r"^test/[a-z0-9][a-z0-9-]*$")
LAYER_PENDING = {"l2": "warstwa L2 dochodzi w iteracji 4", "l3": "warstwa L3 dochodzi w iteracji 5"}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _read_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"nie można odczytać {path}: {exc}") from exc


def _first(state: dict | None, resource: str, attr: str) -> str | None:
    rows = (state or {}).get(resource) or []
    return str(rows[0][attr]) if rows and rows[0].get(attr) is not None else None


def _note(items: list[str]) -> str:
    return "; ".join(items)[:MAX_NOTE]


def _collection(l1: l1_router.L1Result, notes: list[str]) -> dict:
    if l1.state is None:
        status = "unavailable"
    elif l1.failed_menus or notes:
        status = "degraded"
    else:
        status = "ok"
    layer = {"required": True, "status": status, "duration_ms": l1.duration_ms}
    if notes and l1.state is not None:
        layer["note"] = _note(notes)
    return {
        "l1": layer,
        "l2": {"required": True, "status": "unavailable", "note": LAYER_PENDING["l2"]},
        "l3": {"required": False, "status": "unavailable", "note": LAYER_PENDING["l3"]},
    }


def _publish(publisher: Publisher, state_path: Path, state_doc: dict, runtime_doc: dict, message: str) -> str:
    """Wynik zapisuje się dopiero po próbie: błąd pusha trafi do raportu następnego cyklu (R3)."""
    if not should_publish(state_doc, bool(publisher.pending()), runtime_doc["published"]):
        return "nie"
    try:
        publisher.publish(state_path, message)
    except PublishError as exc:
        print(f"[PUBLIKACJA] {exc}", file=sys.stderr)
        runtime_doc["publish_error"] = str(exc)
        return "błąd"
    runtime_doc["publish_error"] = None
    runtime_doc["published"] = {"digest": state_digest(state_doc), "at": state_doc["heartbeat"]["at"]}
    return "tak"


def run_cycle(ctx: Context, out_dir: Path, clock=_utc_now, connector=l1_router.connect_monitor,
              publisher: Publisher | None = None, sync_error: str | None = None) -> int:
    """Bez publishera to --dry-run: tylko zapis lokalny, własny łańcuch what-if."""
    started = clock()
    run_id = report.new_ulid(started)
    state_path = out_dir / "state.json"
    runtime_path = out_dir / "runtime.json"
    prev_state = _read_json(state_path, None)
    if prev_state is None and publisher:
        prev_state = publisher.published_state()
    if publisher:
        publisher.quarantine_orphans(((prev_state or {}).get("last_report") or {}).get("report_seq", 0))
    runtime = _read_json(runtime_path, {})

    errors: list[dict] = []

    def add_error(stage: str, code: str, message: str):
        errors.append({"stage": stage, "code": code, "message": message[:MAX_NOTE]})

    # Awaria łącza zgłaszana jest raz: przy braku synchronizacji cykl nie próbuje pusha.
    if sync_error:
        add_error("publish", "publish.sync-failed", sync_error)
    elif runtime.get("publish_error"):
        add_error("publish", "publish.push-failed", runtime["publish_error"])
    for code, message in ctx.config_errors:
        add_error("evaluate", code, message)
    if ctx.universal_pin != ctx.release_tag:
        add_error("evaluate", "policy.version-mismatch",
                  f"site.yml wskazuje {ctx.universal_pin}, wdrożone jest {ctx.release_tag}")

    universal = policy.load_universal(ctx.paths.policy_dir)
    local_doc, local_errors = policy.load_local(ctx.local_policy_path)
    notes: list[str] = []
    if local_errors:
        add_error("evaluate", "local-policy.invalid", _note(local_errors))
        notes.append("polityka lokalna nieważna, drift z ustawieniami domyślnymi")
    if ctx.config_errors:
        notes.append("wzorzec baseline nieważny")

    l1 = l1_router.collect(ctx, connector)
    for code, message in l1.errors:
        add_error("collect-l1", code, message)

    detected = report.timestamp(clock())
    if l1.state is not None:
        result = evaluate(l1.state, universal, local_doc, ctx.baseline)
        result.evaluated_rules.add(ACCESS_LOST_RULE)
    else:
        result = EvalResult([], set(), set(), [], [])
        if l1.auth_rejected:
            result.violations.append(access_lost_violation("monitor"))
        # Bez odczytu żadna reguła nie jest oceniona: otwarte findingi zostają w stanie.
        result.known_rules.update(f["rule"] for f in (prev_state or {}).get("open_findings", []))
    result.known_rules.add(ACCESS_LOST_RULE)
    if result.unevaluated:
        rules = ", ".join(u["rule"] for u in result.unevaluated)
        notes.append(f"nie oceniono {len(result.unevaluated)} reguł: {rules}")
        for item in result.unevaluated:
            print(f"[WARN] {item['rule']}: {item['reason']}", file=sys.stderr)

    prev_version = (prev_state or {}).get("policy", {}).get("universal_version", ctx.release_tag)
    prev_digest = runtime.get("local_digest", ctx.local_digest)
    reconciled = reconcile(
        result.violations,
        (prev_state or {}).get("open_findings", []),
        now=detected,
        evaluated_rules=result.evaluated_rules,
        known_rules=result.known_rules,
        absorbed={fingerprint(*item) for item in result.absorbed},
        universal_changed=prev_version != ctx.release_tag,
        local_changed=prev_digest != ctx.local_digest,
    )
    actions = mitigate.plan_actions(reconciled.findings, dry_run=publisher is None)
    collection = _collection(l1, notes)
    coverage = report.derive_coverage(collection)
    posture = report.state_posture(reconciled.open_findings, coverage)
    error_kinds = sorted({f"{e['stage']}:{e['code']}" for e in errors})

    finished = clock()
    run = {
        "run_id": run_id,
        "run_seq": (prev_state or {}).get("last_run", {}).get("run_seq", 0) + 1,
        "trigger": ctx.trigger,
        "started_at": report.timestamp(started),
        "finished_at": report.timestamp(finished),
        "agent_version": ctx.agent_version,
        "errors": errors,
    }

    wants_report = report.should_report(prev_state, posture, coverage, reconciled, actions,
                                        error_kinds, runtime.get("error_kinds", []))
    report_doc = report_bytes = None
    last_report = (prev_state or {}).get("last_report")
    if wants_report:
        report_doc = report.build_report(
            ctx, run=run, identity=_first(l1.state, "identity", "name"),
            version=_first(l1.state, "system_resource", "version"), collection=collection,
            reconciled=reconciled, actions=actions, prev_state=prev_state,
            evaluation_mode="what-if" if publisher is None else "enforce")
        report_bytes = report.to_bytes(report_doc)
        last_report = {"run_id": run_id, "report_seq": report_doc["integrity"]["report_seq"],
                       "sha256": report.sha256_hex(report_bytes)}
    state_doc = report.build_state_doc(ctx, run=run, posture=posture, coverage=coverage,
                                       open_findings=reconciled.open_findings, last_report=last_report)

    # R10: nic nie zostaje zapisane, jeśli dokument łamie kontrakt.
    problems = validate_state(state_doc)
    if report_doc is not None:
        problems += validate_report(report_doc)
    if problems:
        for problem in problems:
            print(f"[KONTRAKT] {problem}", file=sys.stderr)
        return EXIT_FAILED

    if report_doc is not None:
        data = l1.raw and evidence.without_secrets(l1.raw)
        evidence.store(out_dir / "evidence", run_id, "l1",
                       data or {"result": "rejected" if l1.auth_rejected else "unavailable"})
        moment = started.strftime("%Y/%m")
        name = f"{report_doc['integrity']['report_seq']:06d}-{run_id}.json"
        reports_dir = publisher.reports_dir if publisher else out_dir / "reports" / "what-if"
        report.write_atomic(reports_dir / moment / name, report_bytes)
    report.write_atomic(state_path, report.to_bytes(state_doc))
    runtime_doc = {"local_digest": ctx.local_digest, "error_kinds": error_kinds,
                   "published": runtime.get("published"),
                   "publish_error": None if sync_error else runtime.get("publish_error")}
    report.write_atomic(runtime_path, report.to_bytes(runtime_doc))

    published = "-"
    if publisher and sync_error:
        published = "błąd"
    elif publisher:
        message = f"agent({ctx.router_id}): {posture}, {coverage}, przebieg {run_id}"
        published = _publish(publisher, state_path, state_doc, runtime_doc, message)
        report.write_atomic(runtime_path, report.to_bytes(runtime_doc))

    print(f"{ctx.router_id}: posture={posture} coverage={coverage} otwarte={len(reconciled.open_findings)} "
          f"nowe={report_doc['verdict']['findings_new'] if report_doc else 0} "
          f"rozwiązane={len(reconciled.resolved)} raport={'tak' if report_doc else 'nie'} "
          f"publikacja={published} błędy={','.join(error_kinds) or '-'}")
    return EXIT_FAILED if published == "błąd" else EXIT_OK


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent", description="Agent soho-guard: jeden cykl dla routera")
    parser.add_argument("--router", required=True, help="identyfikator routera z site.yml")
    parser.add_argument("--once", action="store_true", help="wykonaj jeden cykl (jedyny tryb, ADR-001)")
    parser.add_argument("--dry-run", action="store_true",
                        help="raport i stan lokalnie, bez publikacji i bez zmian na routerze")
    parser.add_argument("--no-remediate", action="store_true", help="publikacja bez remediacji, akcje tylko opisane")
    parser.add_argument("--publish-branch", metavar="test/NAZWA", help="publikacja na gałąź testową zamiast main (z --no-remediate)")
    parser.add_argument("--trigger", choices=["timer", "manual"], default="manual",
                        help="źródło uruchomienia zapisywane w raporcie")
    return parser


def main(argv=None, paths: Paths | None = None, clock=_utc_now, connector=None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not args.once:
        parser.error("wymagane --once")
    if args.dry_run and (args.no_remediate or args.publish_branch):
        parser.error("--dry-run nie publikuje: nie łączy się z --no-remediate ani --publish-branch")
    if not args.dry_run and not args.no_remediate:
        parser.error("remediacja powstaje w iteracji 3: wymagane --dry-run albo --no-remediate")
    if args.publish_branch and not TEST_BRANCH.match(args.publish_branch):
        parser.error("--publish-branch: wymagana nazwa test/<nazwa> (małe litery, cyfry, myślnik)")

    os.umask(0o027)
    paths = paths or Paths()
    try:
        ctx = load_context(args.router, paths)
        ctx.trigger = args.trigger
        lock_dir = paths.data_dir / args.router
        lock_dir.mkdir(parents=True, exist_ok=True)
        with open(lock_dir / "run.lock", "a", encoding="utf-8") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                print(f"{args.router}: poprzedni cykl jeszcze trwa", file=sys.stderr)
                return EXIT_BUSY
            connect = connector or l1_router.connect_monitor
            if args.dry_run:
                out_dir = paths.data_dir / "dry-run" / args.router
                out_dir.mkdir(parents=True, exist_ok=True)
                return run_cycle(ctx, out_dir, clock, connect)

            branch = args.publish_branch or MAIN
            out_dir = paths.data_dir / "publish" / branch / args.router
            out_dir.mkdir(parents=True, exist_ok=True)
            sync_error = None
            try:
                if Publisher(ctx, branch, out_dir).sync():
                    ctx = load_context(args.router, paths)
                    ctx.trigger = args.trigger
            except PublishError as exc:
                print(f"[PUBLIKACJA] {exc}", file=sys.stderr)
                sync_error = str(exc)
            return run_cycle(ctx, out_dir, clock, connect, Publisher(ctx, branch, out_dir), sync_error)
    except (ConfigError, PublishError) as exc:
        print(f"[KONFIGURACJA] {exc}", file=sys.stderr)
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())

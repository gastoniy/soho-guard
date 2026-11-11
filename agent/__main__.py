"""CLI i cykl agenta: python -m agent --router r1 --once [--dry-run | --no-remediate]."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from agent import dynamic_eval, evidence, l1_router, l2_rita, l2_zeek, l3_ti, mitigate, policy, report, selfcheck
from agent.config import ConfigError, Context, Paths, load_context
from agent.findings import ACCESS_LOST_RULE, access_lost_violation, fingerprint, reconcile
from agent.publish import MAIN, Publisher, PublishError, should_publish, state_digest
from agent.static_eval import EvalResult, evaluate, ignored_attrs

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from validate_report import validate_report, validate_state  # noqa: E402

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_BUSY = 3
MAX_NOTE = 500
TEST_BRANCH = re.compile(r"^test/[a-z0-9][a-z0-9-]*$")
LAYER_UNAVAILABLE = "brak danych L2"
SAMPLES_FILE = "l2-samples.json"


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


def _postures(posture: str, report_doc: dict | None) -> tuple[str, str]:
    """Posture do komunikatu commita i podsumowania (K1, K2). Stan opisuje sytuację po
    akcjach, raport tego cyklu jego findingi: przy różnicy (naprawa potwierdzona w cyklu,
    brak danych z routera) pokazujemy oba, inaczej jak dotąd sam stan."""
    reported = report_doc["verdict"]["posture"] if report_doc else posture
    if reported == posture:
        return posture, posture
    return f"raport {reported}, stan {posture}", f"{posture} (raport: {reported})"


def _note(items: list[str]) -> str:
    return "; ".join(items)[:MAX_NOTE]


def _read_samples(path: Path) -> list[dict]:
    """Utrata próbek tylko chwilowo osłabia wykrywanie rozbieżności, więc nie zatrzymuje cyklu."""
    try:
        ring = json.loads(path.read_text(encoding="utf-8"))
        return [s for s in ring if isinstance(s.get("at"), (int, float)) and isinstance(s.get("targets"), list)]
    except FileNotFoundError:
        return []
    except (OSError, ValueError, AttributeError) as exc:
        print(f"[WARN] {path.name}: próbki pominięte ({exc})", file=sys.stderr)
        return []


def _l2_layer(zeek: l2_zeek.ZeekData | None, reason: str | None, rita: l2_rita.RitaData | None,
              notes: list[str], info: list[str] | None = None) -> dict:
    """L2 ok tylko z czytelnym Zeekiem, świeżym importem RITA (≤ 2 h) i zaliczoną
    samokontrolą; notes obniżają status, info tylko go opisują."""
    info = info or []
    if zeek is None:
        return {"required": True, "status": "unavailable", "note": _note([reason or LAYER_UNAVAILABLE, *notes])}
    layer = {"required": True, "status": "degraded" if notes or rita is None else "ok",
             "sources": ["zeek", "rita"] if rita is not None else ["zeek"],
             "window": {"from": dynamic_eval.iso(zeek.since), "to": dynamic_eval.iso(zeek.until)}}
    if notes or info:
        layer["note"] = _note([*notes, *info])
    return layer


def _l3_layer(ti: l3_ti.TiResult) -> dict:
    layer = {"required": False, "status": ti.status}
    if ti.status != "unavailable":
        layer["sources"] = [l3_ti.PROVIDER]
    if ti.note:
        layer["note"] = _note([ti.note])
    return layer


def _collection(l1: l1_router.L1Result, notes: list[str], l2: dict, l3: dict) -> dict:
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
        "l2": l2,
        "l3": l3,
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
              publisher: Publisher | None = None, sync_error: str | None = None,
              mode: str = mitigate.DRY_RUN, remediate_connector=l1_router.connect_remediate,
              rita=None, ti=None) -> int:
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
    dynamic_rules = policy.load_dynamic(ctx.paths.policy_dir)
    local_doc, local_errors = policy.load_local(ctx.local_policy_path)
    notes: list[str] = []
    if local_errors:
        add_error("evaluate", "local-policy.invalid", _note(local_errors))
        notes.append("polityka lokalna nieważna, drift z ustawieniami domyślnymi")
    if any(code == "baseline.invalid" for code, _ in ctx.config_errors):
        notes.append("wzorzec baseline nieważny")

    l1 = l1_router.collect(ctx, connector, clock=clock)
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

    # L2: okno logów Zeeka i próbki tablicy połączeń z tego oraz wcześniejszych cykli.
    now = clock().timestamp()
    samples_path = out_dir / SAMPLES_FILE
    ring = dynamic_eval.merge_samples(_read_samples(samples_path), l1.samples, run_id, now)
    zeek = l2_reason = None
    l2_notes = [l1.samples_note] if l1.samples_note else []
    if any(code == "dynamic-baseline.invalid" for code, _ in ctx.config_errors):
        l2_notes.append("baseline dynamiczny nieważny")
    if ctx.wan_address is None:
        l2_reason = "inventory.yml: brak addressing.wan_address, ruchu nie da się przypisać"
        add_error("collect-l2", "l2.attribution-unavailable", l2_reason)
    else:
        try:
            zeek = l2_zeek.read(ctx.paths.zeek_dir, ctx.wan_address, now)
        except l2_zeek.ZeekError as exc:
            l2_reason = "logi Zeeka nieczytelne"
            add_error("collect-l2", "l2.read-failed", str(exc))
    # Samokontrola: niezaliczona obniża pokrycie i blokuje ocenę, nigdy nie tworzy findingu.
    check = selfcheck.check(ctx.paths.zeek_dir, ctx.wan_address, zeek, l1.state, now)
    for code, message in check.errors:
        add_error("collect-l2", code, message)
    l2_notes += check.degraded
    zeek_eval = None if check.zeek_blocked else zeek
    if check.attribution:
        zeek = zeek_eval = None
        l2_reason = f"atrybucja niepewna: {check.attribution}"
    # RITA: tanie zapytanie o ostatni import, beacony tylko po nowym (D2).
    rita_data = None
    rita_reason = l2_reason
    rita_cache = out_dir / l2_rita.CACHE_FILE
    if ctx.wan_address is not None and not check.attribution:
        try:
            rita_data = l2_rita.collect((rita or l2_rita.connect)(ctx), ctx.wan_address, rita_cache)
            if rita_data is None:
                rita_reason = "RITA nie ma jeszcze zakończonego importu"
                l2_notes.append(rita_reason)
            elif now - rita_data.imported.ended_at > l2_rita.MAX_IMPORT_AGE_S:
                l2_notes.append("ostatni import RITA starszy niż 2 h")
        except l2_rita.RitaError as exc:
            rita_reason = "wyniki RITA niedostępne"
            l2_notes.append(rita_reason)
            add_error("collect-l2", "l2.rita-failed", str(exc))
    dynamic = dynamic_eval.evaluate(dynamic_rules, zeek_eval, ring if l1.samples else None,
                                    ctx.dynamic_baseline, check.zeek_blocked or l2_reason, rita_data, rita_reason)
    # L3: reputacja celów findingów dynamicznych, tylko jako potwierdzenie (D4).
    targets, ti_rules = dynamic_eval.ti_targets(dynamic.violations, dynamic_rules)
    ti_result = l3_ti.corroborate(targets, lambda: (ti or l3_ti.connect)(ctx), out_dir / l3_ti.CACHE_FILE,
                                  now, report.write_atomic)
    dynamic_eval.corroborate(dynamic.violations, ti_result.verdicts, ti_rules)
    if ti_result.status != "ok":
        add_error("collect-l3", "l3.lookup-failed", ti_result.note or "TI niedostępne")
    result.violations += dynamic.violations
    result.evaluated_rules |= dynamic.evaluated_rules
    result.known_rules |= {r["id"] for r in dynamic_rules}
    if zeek is not None and dynamic.unevaluated:
        l2_notes.append(f"nie oceniono: {', '.join(u['rule'] for u in dynamic.unevaluated)}")
        for item in dynamic.unevaluated:
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
        remediation_attempted=set(runtime.get("remediation_attempted", [])),
    )
    holds = []
    if mode == mitigate.FULL and publisher.branch == MAIN and ctx.universal_pin != ctx.release_tag:
        holds.append("wersja polityki niezgodna z site.yml")
    # D5: przy podejrzeniu przejęcia automatyczne zmiany mogłyby zatrzeć ślady (ADR-003).
    if any(f["compromise_indicator"] for f in reconciled.open_findings):
        holds.append("otwarty wskaźnik kompromitacji")
    hold = f"{', '.join(holds)}: zmiany na routerze wstrzymane" if holds else None
    actions = mitigate.plan_actions(reconciled.findings, mode, hold)
    collection = _collection(l1, notes, _l2_layer(zeek, l2_reason, rita_data, l2_notes, check.info),
                             _l3_layer(ti_result))
    coverage = report.derive_coverage(collection)

    def assemble():
        posture = report.state_posture(reconciled.open_findings, coverage)
        error_kinds = sorted({f"{e['stage']}:{e['code']}" for e in errors})
        run = {
            "run_id": run_id,
            "run_seq": (prev_state or {}).get("last_run", {}).get("run_seq", 0) + 1,
            "trigger": ctx.trigger,
            "started_at": report.timestamp(started),
            "finished_at": report.timestamp(clock()),
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
        problems = validate_state(state_doc)
        if report_doc is not None:
            problems += validate_report(report_doc)
        for problem in problems:
            print(f"[KONTRAKT] {problem}", file=sys.stderr)
        return posture, error_kinds, report_doc, report_bytes, state_doc, problems

    # R10: nic nie zostaje zapisane ani zmienione na routerze, jeśli dokument łamie kontrakt.
    posture, error_kinds, report_doc, report_bytes, state_doc, problems = assemble()
    if problems:
        return EXIT_FAILED

    attempted = set(runtime.get("remediation_attempted", []))
    repaired = 0
    if mode == mitigate.FULL and actions:
        outcome = mitigate.execute_actions(
            mitigate.ActionEnv(ctx=ctx, run_id=run_id, clock=clock, state=l1.state,
                               rules={r["id"]: r for r in universal}, ignored=ignored_attrs(local_doc),
                               publisher=publisher, sync_error=sync_error, monitor_connector=connector,
                               remediate_connector=remediate_connector, evidence_dir=out_dir / "evidence"),
            actions, reconciled.findings)
        for code, message in outcome.errors:
            add_error("act", code, message)
        # Stan po akcjach: naprawiony finding zostaje w raporcie, ale nie jest już otwarty.
        reconciled.open_findings = [f for f in reconciled.open_findings if f["fingerprint"] not in outcome.repaired]
        attempted |= outcome.attempted
        repaired = len(outcome.repaired)
        posture, error_kinds, report_doc, report_bytes, state_doc, problems = assemble()
        if problems:
            return EXIT_FAILED
    attempted &= {f["fingerprint"] for f in reconciled.open_findings}

    if report_doc is not None:
        data = l1.raw and evidence.without_secrets(l1.raw)
        evidence.store(out_dir / "evidence", run_id, "l1",
                       data or {"result": "rejected" if l1.auth_rejected else "unavailable"})
        behavioral = [f for f in reconciled.findings if f.violation.evidence is not None]
        if behavioral:
            evidence.store(out_dir / "evidence", run_id, report.L2_EVIDENCE, {"findings": [
                {"fingerprint": f.fingerprint, "rule": f.violation.rule, "object_key": f.violation.object_key,
                 **(f.violation.detail or {})} for f in behavioral]})
        moment = started.strftime("%Y/%m")
        name = f"{report_doc['integrity']['report_seq']:06d}-{run_id}.json"
        reports_dir = publisher.reports_dir if publisher else out_dir / "reports" / "what-if"
        report.write_atomic(reports_dir / moment / name, report_bytes)
    report.write_atomic(state_path, report.to_bytes(state_doc))
    report.write_atomic(samples_path, json.dumps(ring).encode("utf-8"))
    if rita_data is not None and rita_data.fresh_query:
        l2_rita.save(rita_data, ctx.wan_address, rita_cache, report.write_atomic)
    runtime_doc = {"local_digest": ctx.local_digest, "error_kinds": error_kinds,
                   "published": runtime.get("published"), "remediation_attempted": sorted(attempted),
                   "publish_error": None if sync_error else runtime.get("publish_error")}
    report.write_atomic(runtime_path, report.to_bytes(runtime_doc))

    in_message, in_summary = _postures(posture, report_doc)
    published = "-"
    if publisher and sync_error:
        published = "błąd"
    elif publisher:
        message = f"agent({ctx.router_id}): {in_message}, {coverage}, przebieg {run_id}"
        published = _publish(publisher, state_path, state_doc, runtime_doc, message)
        report.write_atomic(runtime_path, report.to_bytes(runtime_doc))

    print(f"{ctx.router_id}: posture={in_summary} coverage={coverage} otwarte={len(reconciled.open_findings)} "
          f"nowe={report_doc['verdict']['findings_new'] if report_doc else 0} "
          f"naprawione={repaired} rozwiązane={len(reconciled.resolved)} raport={'tak' if report_doc else 'nie'} "
          f"publikacja={published} błędy={','.join(error_kinds) or '-'}")
    return EXIT_FAILED if published == "błąd" else EXIT_OK


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent", description="Agent soho-guard: jeden cykl dla routera")
    parser.add_argument("--router", required=True, help="identyfikator routera z site.yml")
    parser.add_argument("--once", action="store_true", help="wykonaj jeden cykl (jedyny tryb, ADR-001)")
    parser.add_argument("--dry-run", action="store_true",
                        help="raport i stan lokalnie, bez publikacji i bez zmian na routerze")
    parser.add_argument("--no-remediate", action="store_true", help="publikacja, akcje tylko opisane; router bez zmian")
    parser.add_argument("--publish-branch", metavar="test/NAZWA", help="publikacja na gałąź testową zamiast main")
    parser.add_argument("--trigger", choices=["timer", "manual"], default="manual",
                        help="źródło uruchomienia zapisywane w raporcie")
    return parser


def main(argv=None, paths: Paths | None = None, clock=_utc_now, connector=None, remediate_connector=None,
         rita=None, ti=None) -> int:
    """rita, ti: fabryki klientów ClickHouse i TI (atrapy w testach)."""
    parser = _parser()
    args = parser.parse_args(argv)
    if not args.once:
        parser.error("wymagane --once")
    if args.dry_run and (args.no_remediate or args.publish_branch):
        parser.error("--dry-run nie publikuje: nie łączy się z --no-remediate ani --publish-branch")
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
                return run_cycle(ctx, out_dir, clock, connect, rita=rita, ti=ti)

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
            return run_cycle(ctx, out_dir, clock, connect, Publisher(ctx, branch, out_dir), sync_error,
                             mitigate.NO_REMEDIATE if args.no_remediate else mitigate.FULL,
                             remediate_connector or l1_router.connect_remediate, rita=rita, ti=ti)
    except (ConfigError, PublishError) as exc:
        print(f"[KONFIGURACJA] {exc}", file=sys.stderr)
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())

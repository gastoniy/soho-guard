"""Mitygacja: wybór akcji wg R8 i ich wykonanie z weryfikacją ponownym odczytem."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from agent import evidence, l1_router, proposal
from agent.config import Context
from agent.findings import Finding
from agent.normalize import (
    PATH_TO_KEY,
    RESOURCES,
    SINGLETONS,
    _is_runtime_entry,
    _match_predicate,
    is_service_config,
    build_state,
    coerce,
    fetch_resources,
)
from agent.report import timestamp, write_atomic
from agent.static_eval import check_rule

DRY_RUN = "dry-run"
NO_REMEDIATE = "no-remediate"
FULL = "full"
MAX_REASON = 500


def _set_text(finding: Finding) -> str:
    return ", ".join(f"{k}={val}" for k, val in sorted(finding.violation.remediate["set"].items()))


def _plan(finding: Finding, mode: str, hold: str | None) -> tuple[str, str, str]:
    v = finding.violation
    if v.ioc or (v.trust or {}).get("divergence"):
        return "alert", "proposed", "R8: wskaźnik kompromitacji lub rozbieżność warstw, wyłącznie alert"
    if v.rule_source == "local" and v.drift:
        return "open-pr", "proposed", "R8: drift, decyzja człowieka przez PR"
    if v.rule_source == "local":
        return "alert", "proposed", "R8: reguła lokalna, zmiana baseline jej nie rozwiąże"
    if not v.remediate:
        return "none", "skipped", "reguła uniwersalna bez remediate, naruszenie widoczne w raporcie"
    if mode == DRY_RUN:
        return "auto-remediate", "proposed", f"dry-run: remediacja niewykonana, planowane {_set_text(finding)}"
    if mode == NO_REMEDIATE:
        return "auto-remediate", "skipped", f"--no-remediate: remediacja wyłączona, planowane {_set_text(finding)}"
    if hold:
        return "auto-remediate", "skipped", f"{hold}, planowane {_set_text(finding)}"
    return "auto-remediate", "proposed", f"rule_source=universal; mitigation_mode=auto; planowane {_set_text(finding)}"


def plan_actions(findings: list[Finding], mode: str = DRY_RUN, hold: str | None = None) -> list[dict]:
    """Dokładnie jedna akcja na nowy finding; utrzymujące się nie dostają kolejnej, więc
    nieudana naprawa nie jest ponawiana. hold: powód wstrzymania zmian na routerze."""
    actions = []
    for finding in findings:
        if finding.status != "new":
            continue
        kind, status, reason = _plan(finding, mode, hold)
        actions.append({
            "action_id": f"A-{len(actions) + 1:02d}",
            "fingerprint": finding.fingerprint,
            "type": kind,
            "status": status,
            "reason": reason[:MAX_REASON],
            "started_at": None,
            "finished_at": None,
            "external_ref": None,
            "verification": None,
            "local_ref": None,
        })
    return actions


@dataclass
class ActionEnv:
    ctx: Context
    run_id: str
    clock: Callable
    state: dict | None
    rules: dict[str, dict]
    ignored: dict[str, set[str]]
    publisher: object
    sync_error: str | None
    monitor_connector: Callable
    remediate_connector: Callable
    evidence_dir: Path


@dataclass
class Outcome:
    errors: list[tuple[str, str]] = field(default_factory=list)
    repaired: set[str] = field(default_factory=set)     # weryfikacja potwierdziła naprawę
    attempted: set[str] = field(default_factory=set)    # próba bez potwierdzenia


def _unverified() -> dict:
    return {"performed": False, "layers": [], "result": "not-verifiable"}


def _describe(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}"


def _apply(api, finding: Finding) -> None:
    """Wiersz wybiera świeży odczyt: .id nie wchodzi do stanu, a kolejność menu może się zmienić."""
    v = finding.violation
    resource = PATH_TO_KEY[v.path]
    menu = api.path(*RESOURCES[resource])
    attrs = dict(v.remediate["set"])
    if resource not in SINGLETONS:
        rows = [dict(r) for r in menu]
        selected = [r for r in rows if not _is_runtime_entry(r)
                    and (resource != "services" or is_service_config(r))
                    and all(_match_predicate(coerce(r.get(a)), c) for a, c in (v.where or {}).items())]
        if len(selected) != 1:
            raise ValueError(f"selektor reguły wskazał {len(selected)} wierszy zamiast jednego")
        attrs[".id"] = selected[0][".id"]
    tuple(menu("set", **attrs))


def _remediate(env: ActionEnv, items: list[tuple[dict, Finding]], outcome: Outcome) -> None:
    ref_name = "remediation"
    log = [{"action_id": a["action_id"], "rule": f.violation.rule, "path": f.violation.path,
            "object_key": f.violation.object_key, "set": f.violation.remediate["set"], "result": "planned"}
           for a, f in items]
    # Zapis przed zmianą: przerwanie cyklu zostawia ślad na węźle.
    evidence.store(env.evidence_dir, env.run_id, ref_name, {"actions": log})

    applied: list[tuple[dict, Finding]] = []
    api = None
    connect_error = None
    try:
        password = l1_router.read_password(env.ctx, "remediate")
        api = env.remediate_connector(env.ctx, password)
    except Exception as exc:  # noqa: BLE001 (różne wyjątki biblioteki i gniazda)
        connect_error = _describe(exc)
    try:
        for (action, finding), entry in zip(items, log):
            action["started_at"] = timestamp(env.clock())
            action["local_ref"] = evidence.local_ref(env.run_id, ref_name)
            problem = connect_error
            if problem is None:
                try:
                    _apply(api, finding)
                    applied.append((action, finding))
                    entry["result"] = "applied"
                    continue
                except Exception as exc:  # noqa: BLE001 (TrapError, gniazdo, selektor)
                    problem = _describe(exc)
            entry["result"] = "failed"
            action.update(status="failed", verification=_unverified(), finished_at=timestamp(env.clock()),
                          reason=f"remediacja nieudana: {problem}"[:MAX_REASON])
            outcome.attempted.add(finding.fingerprint)
            outcome.errors.append(("act.remediate-failed", f"{finding.violation.rule}: {problem}"))
    finally:
        if api is not None:
            try:
                api.close()
            except Exception:  # noqa: BLE001 (sesja i tak jest kończona)
                pass

    _verify(env, applied, outcome)
    for (_, finding), entry in zip(items, log):
        entry["verified"] = finding.fingerprint in outcome.repaired
    evidence.store(env.evidence_dir, env.run_id, ref_name, {"actions": log})


def _verify(env: ActionEnv, applied: list[tuple[dict, Finding]], outcome: Outcome) -> None:
    """Odczyt kontem monitor i ta sama reguła co przy wykryciu."""
    if not applied:
        return
    fresh = None
    problem = None
    try:
        api = env.monitor_connector(env.ctx, l1_router.read_password(env.ctx, "monitor"))
        try:
            menus = {PATH_TO_KEY[f.violation.path]: RESOURCES[PATH_TO_KEY[f.violation.path]] for _, f in applied}
            fresh = build_state(fetch_resources(api, menus))
        finally:
            api.close()
    except Exception as exc:  # noqa: BLE001 (różne wyjątki biblioteki i gniazda)
        problem = _describe(exc)

    for action, finding in applied:
        v = finding.violation
        result = "not-verifiable"
        if fresh is not None:
            check = check_rule(env.rules[v.rule], fresh)
            if check.evaluated:
                still = any(item.object_key == v.object_key for item in check.violations)
                result = "still-present" if still else "resolved"
        action["finished_at"] = timestamp(env.clock())
        if result == "resolved":
            action.update(status="succeeded", verification={"performed": True, "layers": ["L1"], "result": result},
                          reason=f"rule_source=universal; mitigation_mode=auto; ustawiono {_set_text(finding)}"[:MAX_REASON])
            outcome.repaired.add(finding.fingerprint)
            continue
        performed = result == "still-present"
        action.update(status="failed",
                      verification={"performed": True, "layers": ["L1"], "result": result} if performed else _unverified(),
                      reason=f"zmiana wysłana, wynik weryfikacji: {result}"[:MAX_REASON])
        outcome.attempted.add(finding.fingerprint)
        outcome.errors.append(("act.remediate-failed", f"{v.rule}: weryfikacja {result}" + (f", {problem}" if problem else "")))


def _open_pr(env: ActionEnv, items: list[tuple[dict, Finding]], outcome: Outcome) -> None:
    """Jeden PR na cykl: nowe findingi driftu dzielą gałąź i odnośnik."""
    started = timestamp(env.clock())
    url = problem = None
    ref = evidence.local_ref(env.run_id, "baseline-proposal")
    try:
        if env.sync_error:
            raise RuntimeError("brak synchronizacji z repo instalacji")
        text = proposal.render(env.publisher.read_site_file(env.ctx.baseline_rel), env.state,
                               [f.violation for _, f in items], env.ignored)
        source = env.evidence_dir / env.run_id / "baseline-proposal.yml"
        write_atomic(source, text.encode("utf-8"))
        url = env.publisher.push_proposal(env.ctx.baseline_rel, source, env.run_id,
                                          f"agent({env.ctx.router_id}): akceptacja driftu, przebieg {env.run_id}")
    except Exception as exc:  # noqa: BLE001 (po naprawach raport musi powstać mimo błędu PR)
        problem = _describe(exc)
        outcome.errors.append(("act.pr-failed", problem))
    finished = timestamp(env.clock())
    for action, _ in items:
        action.update(started_at=started, finished_at=finished)
        if problem:
            action.update(status="failed", reason=f"propozycja PR nieudana: {problem}"[:MAX_REASON])
        else:
            action.update(status="succeeded", external_ref=url, local_ref=ref,
                          reason="R8: drift, gałąź z propozycją baseline; scalenie PR akceptuje zmianę")


def execute_actions(env: ActionEnv, actions: list[dict], findings: list[Finding]) -> Outcome:
    by_fingerprint = {f.fingerprint: f for f in findings}
    pending = [(a, by_fingerprint[a["fingerprint"]]) for a in actions if a["status"] == "proposed"]
    outcome = Outcome()

    repairs = [item for item in pending if item[0]["type"] == "auto-remediate"]
    if repairs:
        _remediate(env, repairs, outcome)

    proposals = [item for item in pending if item[0]["type"] == "open-pr"]
    if proposals:
        _open_pr(env, proposals, outcome)

    # Alert to raport: trwały zapis prowadzi do publikacji, także po powrocie łącza.
    for action, _ in pending:
        if action["type"] == "alert":
            moment = timestamp(env.clock())
            action.update(status="succeeded", started_at=moment, finished_at=moment)
    return outcome

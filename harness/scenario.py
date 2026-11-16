"""Przebieg jednego scenariusza:

  warunki wstępne H8 (Git, z czekaniem) → bramka H5 → odczyt obiektu w baseline →
  apply poza oknem odczytu L1 (scenariusz bez detekcji: ok. 12 min przed heartbeatem, H10) →
  potwierdzenie odczytem (`t0`, H3; `apply: none` — BEN-001: `t0` = zaplanowany moment, bez odczytu) →
    wykrywany: czekanie na raport do budżetu → oracle + czasy H11 + end_state własnym odczytem
    bez detekcji: okno H10 (commit stanu z run_seq ≥ +2) → oracle na raportach z okna
  → teardown (`--tags revert` + bramka; `apply: none` — sama bramka) → artefakty PR/issue (H9)
  → wynik JSON (H7).

Playbook dostaje `probe_pre` = odczyt obiektu przed apply (revert przywraca wartość zależną od
routera, np. adres Winbox w POL-006). Nieudany teardown nie zmienia werdyktu scenariusza:
`teardown.ok = false`, CLI przerywa (kod 3), kampania wykonuje pełny reset (H4).
Harness nie wyzwala cyklu agenta — czeka na timer.
"""
from __future__ import annotations

import hashlib
import logging
import random
import sys
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

import yaml

from . import REPO_ROOT, HarnessError, UsageError
from . import artifacts as artifacts_mod
from . import gate as gate_mod
from . import probes as probes_mod
from .config import Config
from .oracle import evaluate, oracle_eval
from .results import RESULT_VERSION, harness_commit, new_run_id
from .router import Ansible, Ssh
from .sitelab import SiteLab, preconditions, router_profile
from .timing import (Clock, check_offset, grid_offset, in_avoid_window, iso, last_grid, parse_ts,
                     plan_apply, plan_h10)

sys.path.insert(0, str(REPO_ROOT / "tools"))
import manifest_lint  # noqa: E402

log = logging.getLogger("harness")


@dataclass
class Context:
    cfg: Config
    ansible: Ansible
    site: SiteLab
    clock: Clock
    rng: random.Random
    seed: int | None = None     # ziarno rng (zapisywane w wyniku — powtarzalność przesunięć)
    ssh: Ssh | None = None
    github: artifacts_mod.GitHub | None = None


def load_manifest(path: Path) -> dict:
    try:
        errs = manifest_lint.validate(path)
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        raise UsageError(f"manifest {path}: {e}") from None
    if errs:
        raise UsageError(f"manifest {path} niezgodny z kontraktem:\n  " + "\n  ".join(errs))
    return doc


def _rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _skeleton(ctx: Context, manifest: dict, manifest_path: Path, router_id: str,
              run_id: str | None) -> dict:
    now = ctx.clock.now()
    return {
        "result_version": RESULT_VERSION,
        "run_id": run_id or new_run_id(now),
        "harness_commit": harness_commit(),
        "started_at": iso(now),
        "finished_at": None,
        "manifest": {
            "path": _rel(manifest_path),
            "id": manifest["id"],
            "class": manifest["class"],
            "sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        },
        "target": {
            "router_id": router_id,
            "manifest_router_id": manifest["target"]["router_id"],
            "target_override": router_id != manifest["target"]["router_id"],
            "profile": None,
        },
        "versions": {"agent": None, "policy_pin": None, "policy_deployed": None},
        "site_lab": {"sha_before": None, "sha_after": None, "report_commit": None},
        "preconditions": {"ok": None, "errors": []},
        "gate_before": None,
        "timing": {"rng_seed": ctx.seed},
        "report": None,
        "window": None,
        "metrics": None,
        "oracle": {"violations": []},
        "router_read": {"path": None, "pre": None, "confirm": None, "end": None,
                        "end_state_expected": manifest["expect"].get("end_state")},
        "teardown": {"ok": None, "revert": None, "gate": None, "error": None},
        "artifacts": None,
        "verdict": None,
        "reasons": [],
    }


# ---------------------------------------------------------------- kroki
def _wait_preconditions(ctx: Context, router_id: str, exp: dict, res: dict):
    """H8 z czekaniem do `precondition_wait_s`; zwraca (sha, site.yml, stan, błędy)."""
    deadline = ctx.clock.now() + timedelta(seconds=ctx.cfg.timing.precondition_wait_s)
    waited: list[str] = []
    while True:
        sha = ctx.site.fetch()
        site_doc = ctx.site.site(sha)
        state = ctx.site.state(sha, router_id)
        pre = preconditions(site_doc, state, exp)
        remaining = (deadline - ctx.clock.now()).total_seconds()
        if not pre or remaining <= 0:
            if not pre and waited:
                log.info("warunki wstępne spełnione po %.0f s", ctx.cfg.timing.precondition_wait_s
                         - remaining)
            break
        if pre != waited:
            log.info("warunki wstępne niespełnione (%s), czekam do %d s", "; ".join(pre),
                     ctx.cfg.timing.precondition_wait_s)
        waited = pre
        ctx.clock.sleep(min(ctx.cfg.timing.poll_interval_s, remaining))
    res["site_lab"]["sha_before"] = sha
    res["target"]["profile"] = router_profile(site_doc, router_id)
    res["versions"]["policy_pin"] = (site_doc.get("policy") or {}).get("universal_version")
    res["versions"]["policy_deployed"] = (state.get("policy") or {}).get("universal_version")
    res["preconditions"] = {"ok": not pre, "errors": pre,
                            "state_run_seq": (state.get("last_run") or {}).get("run_seq")}
    return sha, site_doc, state, pre


def _read_probe(ctx: Context, rcfg, probe) -> dict | None:
    return probes_mod.select(ctx.ansible.read(rcfg, probe.path), probe.where)


def _wait_detection(ctx, m, router_id, sha_before, apply_started, t0, res):
    exp = m["expect"]
    deadline = t0 + timedelta(seconds=exp["max_detection_time_s"] + ctx.cfg.timing.report_grace_s)
    res["timing"]["deadline"] = iso(deadline)
    while True:
        head = ctx.site.fetch()
        det = ctx.site.find_detection(sha_before, head, router_id, exp["rule"], apply_started)
        remaining = (deadline - ctx.clock.now()).total_seconds()
        if det is not None or remaining <= 0:
            return det, deadline
        ctx.clock.sleep(min(ctx.cfg.timing.poll_interval_s, remaining))


def cycles_after(t0, finished_at, cycle_s: int) -> int:
    """Numer cyklu po t0, w którym zakończył się przebieg (1 = pierwszy cykl startujący po t0).

    t0 leży poza oknem odczytu L1, więc cykl startujący przed t0 zmiany nie widział."""
    return int(round((last_grid(finished_at, cycle_s) - last_grid(t0, cycle_s)).total_seconds()
                     / cycle_s))


def _wait_window(ctx, m, router_id, sha_before, base_seq, t0, res):
    """H10: pierwszy commit stanu z run_seq ≥ base_seq + 2, którego przebieg jest co najmniej
    drugim cyklem po t0. Sam `run_seq` nie wystarcza: stan sprzed t0 bywa sprzed wielu cykli
    (commit co ≥ 1800 s), więc +2 mogło się uzbierać jeszcze przed t0."""
    deadline = t0 + timedelta(seconds=ctx.cfg.windows[m["class"]])
    res["timing"]["deadline"] = iso(deadline)
    cyc = ctx.cfg.timing.cycle_s
    while True:
        head = ctx.site.fetch()
        for ref in ctx.site.state_commits_since(sha_before, head, router_id):
            last = ref.state.get("last_run") or {}
            if (last.get("run_seq", -1) >= base_seq + 2
                    and cycles_after(t0, parse_ts(last["finished_at"]), cyc) >= 2):
                return ref, deadline
        remaining = (deadline - ctx.clock.now()).total_seconds()
        if remaining <= 0:
            return None, deadline
        ctx.clock.sleep(min(ctx.cfg.timing.poll_interval_s, remaining))


def _report_summary(ref, rep: dict, finding: dict | None) -> dict:
    fp = finding["fingerprint"] if finding else None
    return {
        "path": ref.path,
        "run_id": rep["run"]["run_id"],
        "run_seq": rep["run"].get("run_seq"),
        "first_seen_at": finding["first_seen_at"] if finding else None,
        "committed_at": iso(ref.committed_at),
        "posture": rep["verdict"]["posture"],
        "coverage": rep["verdict"]["coverage"],
        "actions": [{k: a.get(k) for k in ("type", "status", "finished_at")}
                    | {"verification": (a.get("verification") or {}).get("result")}
                    for a in rep.get("actions", []) if fp is None or a.get("fingerprint") == fp],
    }


# ---------------------------------------------------------------- przebieg
def run_scenario(ctx: Context, manifest_path: Path, target: str | None = None,
                 offset_s: float | None = None, close_artifacts: bool = False,
                 run_id: str | None = None) -> dict:
    m = load_manifest(manifest_path)
    exp = m["expect"]
    router_id = target or m["target"]["router_id"]
    rcfg = ctx.cfg.router(router_id)
    if offset_s is not None:
        check_offset(offset_s, ctx.cfg.timing)
    if not exp["detected"] and m["class"] not in ctx.cfg.windows:
        raise UsageError(f"harness.yml: brak windows.{m['class']} (H10)")
    res = _skeleton(ctx, m, manifest_path, router_id, run_id)
    verdict, reasons = None, []
    applied = False       # od tej chwili teardown (revert + bramka, albo sama bramka)
    playbook = m["apply"].get("playbook")
    probe = None
    extra = {}            # dla playbooka: probe_pre
    sha_before = site_doc = None
    reports = []          # (ReportRef, raport) do odczytu artefaktów

    try:
        if playbook:
            probe = probes_mod.get(m["id"])
            res["router_read"]["path"] = probe.path

        # --- H8 ---
        sha_before, site_doc, state, pre = _wait_preconditions(ctx, router_id, exp, res)
        if pre:
            verdict, reasons = "invalid", pre
            return res

        # --- bramka przed apply ---
        g = gate_mod.check(ctx.ssh, ctx.ansible, ctx.site, sha_before, site_doc, rcfg)
        res["gate_before"] = g.as_dict()
        if not g.ok:
            verdict, reasons = "invalid", [g.summary() + " (przed apply)"]
            return res

        # --- obiekt w baseline ---
        if probe is not None:
            row = _read_probe(ctx, rcfg, probe)
            res["router_read"]["pre"] = probes_mod.view(row, probe)
            extra = {"probe_pre": res["router_read"]["pre"]}
            diffs = probes_mod.matches(row, probe.baseline)
            if diffs:
                verdict = "invalid"
                reasons = ["router nie w baseline przed apply: " + "; ".join(diffs)]
                return res

        # --- plan apply ---
        if exp["detected"]:
            planned, off = plan_apply(ctx.clock.now(), ctx.cfg.timing, ctx.rng, offset_s)
        else:
            hb = state["heartbeat"]
            planned, off, predicted = plan_h10(ctx.clock.now(), parse_ts(hb["at"]),
                                               hb["interval_s"], ctx.cfg.timing, ctx.rng, offset_s)
            res["timing"]["predicted_heartbeat_at"] = iso(predicted)
        res["timing"].update(planned_apply_at=iso(planned), planned_offset_s=round(off, 3))
        log.info("%s %s: apply o %s (przesunięcie %.1f s)", m["id"], router_id, iso(planned), off)
        ctx.clock.sleep_until(planned)

        # --- H8 ponownie tuż przed apply (stan mógł się zmienić w czasie czekania) ---
        sha_before = ctx.site.fetch()
        state = ctx.site.state(sha_before, router_id)
        pre = preconditions(ctx.site.site(sha_before), state, exp)
        res["site_lab"]["sha_before"] = sha_before
        res["preconditions"].update(ok=not pre, errors=pre,
                                    state_run_seq=(state.get("last_run") or {}).get("run_seq"))
        if pre:
            verdict, reasons = "invalid", pre
            return res

        apply_started = ctx.clock.now()
        res["timing"]["apply_started_at"] = iso(apply_started)
        applied = True
        if playbook:
            ctx.ansible.playbook(playbook, rcfg, "apply", extra)

            # --- t0 = potwierdzenie zmiany własnym odczytem (H3) ---
            row = _read_probe(ctx, rcfg, probe)
            res["router_read"]["confirm"] = probes_mod.view(row, probe)
            diffs = probes_mod.matches(row, probe.applied)
            if diffs:
                raise HarnessError("apply niepotwierdzony odczytem: " + "; ".join(diffs))
        t0 = ctx.clock.now()
        res["timing"].update(
            t0=iso(t0),
            t0_grid_offset_s=round(grid_offset(t0, ctx.cfg.timing.cycle_s), 3),
            t0_in_avoid_window=in_avoid_window(t0, ctx.cfg.timing),
        )
        log.info("%s %s: t0=%s", m["id"], router_id, iso(t0))

        if exp["detected"]:
            det, deadline = _wait_detection(ctx, m, router_id, sha_before, apply_started, t0, res)
            if det is None:
                verdict = "timeout"
                reasons = [f"brak raportu z findingiem {exp['rule']} (new) do {iso(deadline)}"]
                return res
            reports = [(det.ref, det.report)]
            res["site_lab"]["report_commit"] = det.ref.commit
            res["versions"]["agent"] = det.report["run"].get("agent_version")
            res["report"] = _report_summary(det.ref, det.report, det.finding)
            log.info("%s %s: raport %s", m["id"], router_id, det.ref.path)
            state_at = ctx.site.state(det.ref.commit, router_id)

            end_diffs = None
            es = exp.get("end_state")
            if es:
                want = probe.baseline if es == "baseline" else probe.applied
                row = _read_probe(ctx, rcfg, probe)
                res["router_read"]["end"] = probes_mod.view(row, probe)
                end_diffs = probes_mod.matches(row, want)

            ev = evaluate(m, det, state_at, t0, end_diffs)
            res["metrics"] = ev["metrics"]
            violations = ev["violations"]
        else:
            base_seq = (state.get("last_run") or {}).get("run_seq", 0)
            closing, deadline = _wait_window(ctx, m, router_id, sha_before, base_seq, t0, res)
            if closing is None:
                verdict = "timeout"
                reasons = [f"okno H10: brak commitu stanu z run_seq ≥ {base_seq + 2} "
                           f"do {iso(deadline)}"]
                return res
            refs = ctx.site.reports_since(sha_before, closing.commit, router_id)
            reports = [(r, ctx.site.report(r)) for r in refs]
            violations = []
            for _, rep in reports or [(None, None)]:
                violations += [v for v in oracle_eval(m, rep, closing.state) if v not in violations]
            res["window"] = {
                "base_run_seq": base_seq,
                "closing_commit": closing.commit,
                "closing_committed_at": iso(closing.committed_at),
                "closing_run_seq": closing.state["last_run"]["run_seq"],
                "closing_cycles_after_t0": cycles_after(
                    t0, parse_ts(closing.state["last_run"]["finished_at"]), ctx.cfg.timing.cycle_s),
                "closing_posture": closing.state.get("posture"),
                "reports": [r.path for r, _ in reports],
            }
            res["metrics"] = {"window_s": round((closing.committed_at - t0).total_seconds(), 3)}
            if reports:
                res["versions"]["agent"] = reports[0][1]["run"].get("agent_version")

        res["oracle"]["violations"] = violations
        verdict = "fail" if violations else "pass"
        reasons = violations
        return res

    except HarnessError as e:
        verdict, reasons = "error", [str(e)]
        return res

    except KeyboardInterrupt:
        verdict, reasons = "error", ["przerwane przez operatora (SIGINT)"]
        res["interrupted"] = True
        return res

    finally:
        if applied:
            _teardown(ctx, playbook, rcfg, sha_before, site_doc, res, extra)
        if reports and ctx.github is not None:
            _artifacts(ctx, router_id, reports, close_artifacts, res)
        try:
            res["site_lab"]["sha_after"] = ctx.site.fetch()
        except HarnessError as e:
            log.warning("sha_after: %s", e)
        res["verdict"], res["reasons"] = verdict, reasons
        res["finished_at"] = iso(ctx.clock.now())
        log.info("%s %s: werdykt %s%s", m["id"], router_id, verdict,
                 "" if res["teardown"]["ok"] in (True, None) else " (teardown niezgodny)")


def _teardown(ctx, playbook, rcfg, sha_before, site_doc, res, extra=None) -> None:
    td = res["teardown"]
    if not playbook:
        td["revert"] = "skipped"          # apply: none — nic do cofania, sama bramka
    else:
        try:
            ctx.ansible.playbook(playbook, rcfg, "revert", extra)
            td["revert"] = "ok"
        except HarnessError as e:
            td.update(revert="error", error=str(e), ok=False)
            log.error("teardown: %s", e)
            return
    try:
        g = gate_mod.check(ctx.ssh, ctx.ansible, ctx.site, sha_before, site_doc, rcfg)
    except HarnessError as e:
        td.update(error=f"bramka: {e}", ok=False)
        log.error("teardown: bramka: %s", e)
        return
    td["gate"] = g.as_dict()
    td["ok"] = g.ok
    if not g.ok:
        td["error"] = g.summary() + " (po revert)"
        log.error("teardown: %s", td["error"])
        for ln in g.export_diff + g.objects_diff:
            log.error("  %s", ln)


def _artifacts(ctx, router_id, reports, close_artifacts, res) -> None:
    out = []
    try:
        for ref, rep in reports:
            a = artifacts_mod.collect(ctx.github, ctx.clock, router_id, rep, ref.path,
                                      ctx.cfg.artifacts.timeout_s, ctx.cfg.artifacts.poll_s)
            a["report"] = ref.path
            if close_artifacts and a["status"] != "not-expected":
                if res["teardown"]["ok"] is False:
                    # router nie wrócił do baseline: artefakt agenta zostaje jako sygnał dla operatora
                    a["closed"] = []
                    a["close_skipped"] = "teardown niezgodny — artefakty pozostawione"
                else:
                    a["closed"] = artifacts_mod.close(ctx.github, a, res["run_id"])
            out.append(a)
    except HarnessError as e:
        out.append({"status": "error", "error": str(e)})
        log.warning("artefakty: %s", e)
    res["artifacts"] = out

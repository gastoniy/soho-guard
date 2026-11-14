"""Przebieg jednego scenariusza wykrywanego (iteracja 1):

  warunki wstępne H8 (Git) → odczyt obiektu w baseline → apply poza oknem odczytu L1 →
  potwierdzenie odczytem (`t0`, H3) → czekanie na raport do budżetu → oracle + czasy H11 +
  end_state własnym odczytem → teardown (`--tags revert`) → wynik JSON (H7).

Harness nie wyzwala cyklu agenta — czeka na timer. Bramka (H5), okno H10 dla scenariuszy bez
detekcji i pełny reset dochodzą w kolejnych iteracjach.
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
from . import probes as probes_mod
from .config import Config
from .oracle import evaluate
from .results import RESULT_VERSION, harness_commit, new_run_id
from .router import Ansible
from .sitelab import SiteLab, preconditions, router_profile
from .timing import Clock, check_offset, grid_offset, in_avoid_window, iso, plan_apply

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


def _skeleton(ctx: Context, manifest: dict, manifest_path: Path, router_id: str) -> dict:
    now = ctx.clock.now()
    return {
        "result_version": RESULT_VERSION,
        "run_id": new_run_id(now),
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
        "timing": {"rng_seed": ctx.seed},
        "report": None,
        "metrics": None,
        "oracle": {"violations": []},
        "router_read": {"path": None, "pre": None, "confirm": None, "end": None,
                        "end_state_expected": manifest["expect"].get("end_state")},
        "teardown": {"revert": None, "error": None},
        "verdict": None,
        "reasons": [],
    }


def run_scenario(ctx: Context, manifest_path: Path, target: str | None = None,
                 offset_s: float | None = None) -> dict:
    m = load_manifest(manifest_path)
    exp = m["expect"]
    router_id = target or m["target"]["router_id"]
    rcfg = ctx.cfg.router(router_id)
    if offset_s is not None:
        check_offset(offset_s, ctx.cfg.timing)
    res = _skeleton(ctx, m, manifest_path, router_id)
    verdict, reasons = None, []
    applied = False
    playbook = m["apply"].get("playbook")

    try:
        if not exp["detected"]:
            raise HarnessError("scenariusze bez detekcji (okno H10) — iteracja 2")
        if not playbook:
            raise HarnessError("scenariusze z `apply: none` — iteracja 3")
        probe = probes_mod.get(m["id"])
        res["router_read"]["path"] = probe.path

        # --- warunki wstępne H8 (stan z Gita) ---
        sha_before = ctx.site.fetch()
        res["site_lab"]["sha_before"] = sha_before
        site_doc = ctx.site.site(sha_before)
        state = ctx.site.state(sha_before, router_id)
        res["target"]["profile"] = router_profile(site_doc, router_id)
        res["versions"]["policy_pin"] = (site_doc.get("policy") or {}).get("universal_version")
        res["versions"]["policy_deployed"] = (state.get("policy") or {}).get("universal_version")
        pre = preconditions(site_doc, state, exp)
        res["preconditions"] = {"ok": not pre, "errors": pre,
                                "state_run_seq": (state.get("last_run") or {}).get("run_seq")}
        if pre:
            verdict, reasons = "invalid", pre
            return res

        # --- obiekt w baseline przed apply (do iteracji 2 zastępuje bramkę) ---
        row = probes_mod.select(ctx.ansible.read(rcfg, probe.path), probe.where)
        res["router_read"]["pre"] = row
        diffs = probes_mod.matches(row, probe.baseline)
        if diffs:
            verdict = "invalid"
            reasons = ["router nie w baseline przed apply: " + "; ".join(diffs)]
            return res

        # --- apply poza oknem odczytu L1 ---
        planned, off = plan_apply(ctx.clock.now(), ctx.cfg.timing, ctx.rng, offset_s)
        res["timing"].update(planned_apply_at=iso(planned), planned_offset_s=round(off, 3))
        log.info("%s %s: apply o %s (przesunięcie %.1f s)", m["id"], router_id, iso(planned), off)
        ctx.clock.sleep_until(planned)
        apply_started = ctx.clock.now()
        res["timing"]["apply_started_at"] = iso(apply_started)
        applied = True
        ctx.ansible.playbook(playbook, rcfg, "apply")

        # --- t0 = potwierdzenie zmiany własnym odczytem (H3) ---
        row = probes_mod.select(ctx.ansible.read(rcfg, probe.path), probe.where)
        res["router_read"]["confirm"] = row
        diffs = probes_mod.matches(row, probe.applied)
        if diffs:
            raise HarnessError("apply niepotwierdzony odczytem: " + "; ".join(diffs))
        t0 = ctx.clock.now()
        res["timing"].update(
            t0=iso(t0),
            t0_grid_offset_s=round(grid_offset(t0, ctx.cfg.timing.cycle_s), 3),
            t0_in_avoid_window=in_avoid_window(t0, ctx.cfg.timing),
        )
        log.info("%s %s: t0=%s, czekam na raport (budżet %d s)", m["id"], router_id, iso(t0),
                 exp["max_detection_time_s"])

        # --- czekanie na raport agenta ---
        deadline = t0 + timedelta(seconds=exp["max_detection_time_s"]
                                  + ctx.cfg.timing.report_grace_s)
        res["timing"]["deadline"] = iso(deadline)
        while True:
            head = ctx.site.fetch()
            det = ctx.site.find_detection(sha_before, head, router_id, exp["rule"], apply_started)
            remaining = (deadline - ctx.clock.now()).total_seconds()
            if det is not None or remaining <= 0:
                break
            ctx.clock.sleep(min(ctx.cfg.timing.poll_interval_s, remaining))

        if det is None:
            verdict = "timeout"
            reasons = [f"brak raportu z findingiem {exp['rule']} (new) do {iso(deadline)}"]
            return res

        rep = det.report
        res["site_lab"]["report_commit"] = det.ref.commit
        res["versions"]["agent"] = rep["run"].get("agent_version")
        res["report"] = {
            "path": det.ref.path,
            "run_id": rep["run"]["run_id"],
            "run_seq": rep["run"].get("run_seq"),
            "first_seen_at": det.finding["first_seen_at"],
            "committed_at": iso(det.ref.committed_at),
            "posture": rep["verdict"]["posture"],
            "coverage": rep["verdict"]["coverage"],
            "actions": [{k: a.get(k) for k in ("type", "status", "finished_at")}
                        | {"verification": (a.get("verification") or {}).get("result")}
                        for a in rep.get("actions", [])
                        if a.get("fingerprint") == det.finding["fingerprint"]],
        }
        state_at = ctx.site.state(det.ref.commit, router_id)

        # --- end_state własnym odczytem ---
        end_diffs = None
        es = exp.get("end_state")
        if es:
            want = probe.baseline if es == "baseline" else probe.applied
            row = probes_mod.select(ctx.ansible.read(rcfg, probe.path), probe.where)
            res["router_read"]["end"] = row
            end_diffs = probes_mod.matches(row, want)

        ev = evaluate(m, det, state_at, t0, end_diffs)
        res["metrics"] = ev["metrics"]
        res["oracle"]["violations"] = ev["violations"]
        verdict = "fail" if ev["violations"] else "pass"
        reasons = ev["violations"]
        return res

    except HarnessError as e:
        verdict, reasons = "error", [str(e)]
        return res

    finally:
        if applied:
            try:
                ctx.ansible.playbook(playbook, rcfg, "revert")
                res["teardown"]["revert"] = "ok"
            except HarnessError as e:
                res["teardown"].update(revert="error", error=str(e))
                if verdict in ("pass", "fail", "timeout"):
                    reasons = reasons + [f"teardown: {e}"]
                    verdict = "error"
        try:
            res["site_lab"]["sha_after"] = ctx.site.fetch()
        except HarnessError as e:
            log.warning("sha_after: %s", e)
        res["verdict"], res["reasons"] = verdict, reasons
        res["finished_at"] = iso(ctx.clock.now())

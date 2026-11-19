"""Skoordynowany przebieg pary DYN-011b + CTL-001 (iteracja 5).

Jeden ruch okresowy z klienta za r1 (sterowany ręcznie przez operatora, potwierdzenia w terminalu)
obsługuje oba ramiona:
  * DYN-011b (r1, detekcja): raport z regułą `policy.dynamic.beacon` jako `new` w budżecie;
  * CTL-001 (r2, kontrola atrybucji L2, D-B4): r2 obserwowany przez cały przebieg DYN-011b —
    do pierwszego commitu stanu r2 z przebiegiem ≥ 2 cykle po wykryciu na r1 — bez findingu.

Warunki startu z węzła (`operator_checks`, skrypt `check-rita-dyn011b.sh`): okno zbioru RITA
≥ 23 h, ostatni import < 2 h, 0 połączeń WAN r1 → cel w ostatnich 26 h. Zbiór młodszy niż 24 h
daje zawyżony wynik (krótsze przedziały) — wynik pary to dokumentuje.

Werdykt pary = najgorsze z ramion. Teardown: zatrzymanie ruchu (potwierdzenie operatora) → pełny
reset routerów wg `teardown.reset` manifestów → czekanie na rozwiązanie findingu na r1
(`resolve_timeouts[<id>]`, D-B5: finding RITA znika ok. 24–25 h po ostatnim połączeniu (okno
zbioru RITA 24 h); w tym czasie naprawy na r1 są wstrzymane).
"""
from __future__ import annotations

import hashlib
import logging
from datetime import timedelta
from pathlib import Path

import yaml

from . import HarnessError, UsageError
from . import gate as gate_mod
from . import generate as generate_mod
from .oracle import evaluate, oracle_eval
from .reset import run_reset
from .results import RESULT_VERSION, harness_commit, new_run_id, write_reset
from .scenario import (Context, SIDE_EFFECTS, _artifacts, _report_summary, _side_effect_reports,
                       _stop_generate, _wait_detection, _wait_resolved, cycles_after,
                       load_manifest, _rel)
from .sitelab import preconditions, router_profile
from .timing import check_offset, grid_offset, in_avoid_window, iso, parse_ts, plan_apply

log = logging.getLogger("harness")

# ------------------------------------------------------------------ warunki startu (operator)
OPERATOR_CHECK_KEYS = {"checked_at", "target", "wan", "dataset_window_h", "import_age_s",
                       "target_conns_26h", "rita_config"}
OPERATOR_CHECK_REQUIRED = ("checked_at", "target", "dataset_window_h", "import_age_s",
                           "target_conns_26h")
MIN_DATASET_WINDOW_H = 23
MAX_IMPORT_AGE_S = 7200
MAX_CHECK_AGE_S = 10800       # odczyt z węzła najwyżej 3 h przed apply


def load_operator_checks(path: Path) -> dict:
    """Plik YAML z wyniku `check-rita-dyn011b.sh` (blok `operator_checks:` albo sama mapa)."""
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        raise UsageError(f"operator_checks {path}: {e}") from None
    if isinstance(doc, dict) and set(doc) == {"operator_checks"}:
        doc = doc["operator_checks"]
    if not isinstance(doc, dict):
        raise UsageError(f"operator_checks {path}: oczekiwano mapy")
    unknown = sorted(set(doc) - OPERATOR_CHECK_KEYS)
    missing = [k for k in OPERATOR_CHECK_REQUIRED if doc.get(k) in (None, "")]
    if unknown or missing:
        raise UsageError(f"operator_checks {path}: nieznane klucze {unknown}, brak {missing}")
    try:
        parse_ts(str(doc["checked_at"]))
        float(doc["dataset_window_h"]), float(doc["import_age_s"]), int(doc["target_conns_26h"])
    except (TypeError, ValueError) as e:
        raise UsageError(f"operator_checks {path}: niepoprawna wartość ({e})") from None
    return {**doc, "checked_at": str(doc["checked_at"]), "target": str(doc["target"])}


def evaluate_checks(checks: dict, now) -> list[str]:
    """Naruszenia warunków startu (→ `invalid`); pusta lista = zbiór RITA w stanie ustalonym."""
    out = []
    if float(checks["dataset_window_h"]) < MIN_DATASET_WINDOW_H:
        out.append(f"okno zbioru RITA {checks['dataset_window_h']} h < {MIN_DATASET_WINDOW_H} h "
                   f"(zbiór młodszy niż 24 h zawyża wynik)")
    if float(checks["import_age_s"]) >= MAX_IMPORT_AGE_S:
        out.append(f"ostatni import RITA sprzed {checks['import_age_s']} s (≥ {MAX_IMPORT_AGE_S} s)")
    if int(checks["target_conns_26h"]) != 0:
        out.append(f"cel {checks['target']}: {checks['target_conns_26h']} połączeń z WAN w 26 h "
                   f"(para nie jest świeża — wybierz inny adres)")
    age = (now - parse_ts(checks["checked_at"])).total_seconds()
    if age > MAX_CHECK_AGE_S:
        out.append(f"odczyt z węzła sprzed {int(age)} s (> {MAX_CHECK_AGE_S} s) — powtórz")
    return out


# ------------------------------------------------------------------ wynik
def _manifest_ref(m: dict, path: Path) -> dict:
    return {"path": _rel(path), "id": m["id"], "class": m["class"],
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def _skeleton(ctx: Context, dyn: dict, dyn_path: Path, ctl: dict, ctl_path: Path,
              run_id: str | None) -> dict:
    now = ctx.clock.now()
    arm = lambda rid: {"router_id": rid, "preconditions": {"ok": None, "errors": []},
                       "gate_before": None, "sha_before": None, "profile": None,
                       "oracle": {"violations": []}, "verdict": None, "reasons": []}
    return {
        "result_version": RESULT_VERSION,
        "kind": "pair",
        "run_id": run_id or new_run_id(now),
        "harness_commit": harness_commit(),
        "started_at": iso(now),
        "finished_at": None,
        "pair": {"dynamic_id": dyn["id"], "control_id": ctl["id"],
                 "dynamic_router": dyn["target"]["router_id"],
                 "control_router": ctl["target"]["router_id"]},
        "manifest": {"dynamic": _manifest_ref(dyn, dyn_path),
                     "control": _manifest_ref(ctl, ctl_path)},
        "versions": {"agent": None, "policy_pin": None, "policy_deployed": None},
        "operator_checks": None,
        "generate": None,
        "timing": {"rng_seed": ctx.seed},
        "dynamic": {**arm(dyn["target"]["router_id"]), "report": None, "metrics": None,
                    "side_effects": None},
        "control": {**arm(ctl["target"]["router_id"]), "window": None},
        "teardown": {"ok": None, "revert": None, "reset_dynamic": None, "reset_control": None,
                     "resolved": None, "error": None},
        "artifacts": None,
        "verdict": None,
        "reasons": [],
    }


def _check_both(ctx, routers: dict[str, str], exp: dict[str, dict], res: dict):
    """Warunki wstępne H8 + bramka dla obu routerów; zapis do ramion res. Zwraca (ok, sha_map)."""
    ok, sha_map = True, {}
    for arm, rid in routers.items():
        sha = ctx.site.fetch()
        site_doc = ctx.site.site(sha)
        state = ctx.site.state(sha, rid)
        pre = preconditions(site_doc, state, exp[arm])
        res[arm]["sha_before"] = sha
        res[arm]["profile"] = router_profile(site_doc, rid)
        res[arm]["preconditions"] = {"ok": not pre, "errors": pre,
                                     "state_run_seq": (state.get("last_run") or {}).get("run_seq")}
        if arm == "dynamic":
            res["versions"]["policy_pin"] = (site_doc.get("policy") or {}).get("universal_version")
            res["versions"]["policy_deployed"] = (state.get("policy") or {}).get("universal_version")
        if pre:
            res[arm]["reasons"] = pre
            ok = False
            continue
        g = gate_mod.check(ctx.ssh, ctx.ansible, ctx.site, sha, site_doc, ctx.cfg.router(rid))
        res[arm]["gate_before"] = g.as_dict()
        sha_map[arm] = sha
        if not g.ok:
            res[arm]["reasons"] = [g.summary() + " (przed apply)"]
            ok = False
    return ok, sha_map


def _arm_reasons(res) -> list[str]:
    return [f"{a}: {'; '.join(res[a]['reasons'])}" for a in ("dynamic", "control")
            if res[a]["reasons"]]


# ------------------------------------------------------------------ przebieg
def run_pair(ctx: Context, dyn_path: Path, ctl_path: Path, offset_s: float | None = None,
             close_artifacts: bool = False, run_id: str | None = None,
             operator_checks: dict | None = None) -> dict:
    dyn = load_manifest(dyn_path)
    ctl = load_manifest(ctl_path)
    if dyn["class"] != "dynamic" or not dyn["expect"]["detected"]:
        raise UsageError(f"pair: pierwszy manifest musi być dynamiczny z detekcją ({dyn['id']})")
    if ctl["class"] != "control" or ctl["expect"]["detected"]:
        raise UsageError(f"pair: drugi manifest musi być control bez detekcji ({ctl['id']})")
    dyn_rid = dyn["target"]["router_id"]
    ctl_rid = ctl["target"]["router_id"]
    if dyn_rid == ctl_rid:
        raise UsageError("pair: ramiona muszą być na różnych routerach (atrybucja L2)")
    if offset_s is not None:
        check_offset(offset_s, ctx.cfg.timing)
    pool = ctx.cfg.endpoint(dyn["generate"]["to_endpoint"])
    if operator_checks is not None and operator_checks["target"] not in pool:
        raise UsageError(f"operator_checks: cel {operator_checks['target']} spoza "
                         f"endpoints.{dyn['generate']['to_endpoint']}")

    res = _skeleton(ctx, dyn, dyn_path, ctl, ctl_path, run_id)
    routers = {"dynamic": dyn_rid, "control": ctl_rid}
    exp = {"dynamic": dyn["expect"], "control": ctl["expect"]}
    applied = False
    reports: list = []        # (ref, raport) do artefaktów (ramię dynamic)
    verdict, reasons = None, []

    try:
        # --- warunki startu z węzła (zbiór RITA w stanie ustalonym, świeży cel) ---
        if operator_checks is None:
            log.warning("pair: brak operator_checks — wynik nie dokumentuje stanu zbioru RITA")
            res["operator_checks"] = {"provided": False}
            target = pool[0]
        else:
            errs = evaluate_checks(operator_checks, ctx.clock.now())
            res["operator_checks"] = {"provided": True, **operator_checks, "violations": errs}
            target = operator_checks["target"]
            if errs:
                verdict, reasons = "invalid", ["operator_checks: " + e for e in errs]
                return res
        res["generate"] = {"from": dyn["generate"]["from"],
                           "to_endpoint": dyn["generate"]["to_endpoint"], "target": target}

        # --- H8 + bramka na obu routerach ---
        ok, _ = _check_both(ctx, routers, exp, res)
        if not ok:
            verdict, reasons = "invalid", _arm_reasons(res)
            return res

        # --- plan apply poza oknem odczytu L1 ---
        planned, off = plan_apply(ctx.clock.now(), ctx.cfg.timing, ctx.rng, offset_s)
        res["timing"].update(planned_apply_at=iso(planned), planned_offset_s=round(off, 3))
        log.info("pair %s+%s: start o %s (przesunięcie %.1f s)", dyn["id"], ctl["id"], iso(planned),
                 off)
        ctx.clock.sleep_until(planned)

        # --- H8 ponownie tuż przed startem ---
        ok, sha_map = _check_both(ctx, routers, exp, res)
        if not ok:
            verdict, reasons = "invalid", _arm_reasons(res)
            return res

        # --- apply (DYN-011b: none) + start ruchu; t0 = start (generate.t0_marker) ---
        apply_started = ctx.clock.now()
        res["timing"]["apply_started_at"] = iso(apply_started)
        applied = True
        playbook = dyn["apply"].get("playbook")
        if playbook:
            ctx.ansible.playbook(playbook, ctx.cfg.router(dyn_rid), "apply",
                                 {"covert_target": target})
        res["generate"] = generate_mod.run_generate(ctx, dyn, ctx.cfg.router(dyn_rid), target)
        t0 = generate_mod.started_at(res["generate"])
        res["timing"].update(
            t0=iso(t0), t0_grid_offset_s=round(grid_offset(t0, ctx.cfg.timing.cycle_s), 3),
            t0_in_avoid_window=in_avoid_window(t0, ctx.cfg.timing))
        log.info("pair: t0=%s (%s → %s)", iso(t0), dyn_rid, target)

        # --- ramię DYN-011b: czekanie na detekcję na r1 ---
        det, deadline = _wait_detection(ctx, dyn, dyn_rid, sha_map["dynamic"], apply_started, t0,
                                        res)
        if det is None:
            res["dynamic"]["verdict"] = "timeout"
            res["dynamic"]["reasons"] = [
                f"brak raportu z findingiem {dyn['expect']['rule']} (new) do {iso(deadline)}"]
            head = ctx.site.fetch()
            _eval_control(ctx, ctl, ctl_rid, sha_map["control"], head,
                          ctx.site.state(head, ctl_rid), t0, res, closed_by="dynamic-timeout")
            verdict, reasons = "timeout", _combine(res)[1]
            return res

        reports = [(det.ref, det.report)]
        res["versions"]["agent"] = det.report["run"].get("agent_version")
        res["dynamic"]["report"] = _report_summary(det.ref, det.report, det.finding)
        log.info("pair: raport %s", det.ref.path)

        se_rules = SIDE_EFFECTS.get(dyn["id"], ())
        if se_rules:
            se = _side_effect_reports(ctx, dyn_rid, sha_map["dynamic"], det.ref.commit, se_rules,
                                      apply_started)
            res["dynamic"]["side_effects"] = [{"rule": r, "report": ref.path} for ref, _, r in se]
            reports += [(ref, rep) for ref, rep, _ in se if ref.path != det.ref.path]

        state_at = ctx.site.state(det.ref.commit, dyn_rid)
        ev = evaluate(dyn, det, state_at, t0, None)
        res["dynamic"]["metrics"] = ev["metrics"]
        res["dynamic"]["oracle"]["violations"] = ev["violations"]
        res["dynamic"]["verdict"] = "fail" if ev["violations"] else "pass"
        res["dynamic"]["reasons"] = ev["violations"]

        # --- ramię CTL-001 (D-B4): r2 do wykrycia na r1 + 2 cykle ---
        detected_at = parse_ts(det.finding["first_seen_at"])
        closing, cdeadline = _wait_control(ctx, ctl_rid, sha_map["control"], detected_at)
        if closing is None:
            res["control"]["verdict"] = "timeout"
            res["control"]["reasons"] = [f"brak commitu stanu {ctl_rid} ≥ 2 cykle po wykryciu "
                                         f"na {dyn_rid} do {iso(cdeadline)}"]
        else:
            _eval_control(ctx, ctl, ctl_rid, sha_map["control"], closing.commit, closing.state,
                          detected_at, res, closed_by="detection+2")
        verdict, reasons = _combine(res)
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
            _teardown_pair(ctx, dyn, ctl, routers, res)
        if reports and ctx.github is not None:
            _artifacts(ctx, dyn_rid, reports, close_artifacts, res)
        res["verdict"], res["reasons"] = verdict, reasons
        res["finished_at"] = iso(ctx.clock.now())
        td_ok = res["teardown"]["ok"]
        log.info("pair %s+%s: werdykt %s%s", dyn["id"], ctl["id"], verdict,
                 "" if td_ok in (True, None) else " (teardown niezgodny)")


def _wait_control(ctx, ctl_rid, sha_before, since):
    """Pierwszy commit stanu r2 z przebiegiem co najmniej 2 cykle po `since`; limit
    `windows.control` od `since` (stan bez zmian commitowany co ≥ 1800 s)."""
    deadline = since + timedelta(seconds=ctx.cfg.windows["control"])
    cyc = ctx.cfg.timing.cycle_s
    while True:
        head = ctx.site.fetch()
        for ref in ctx.site.state_commits_since(sha_before, head, ctl_rid):
            last = ref.state.get("last_run") or {}
            if (last.get("finished_at")
                    and cycles_after(since, parse_ts(last["finished_at"]), cyc) >= 2):
                return ref, deadline
        remaining = (deadline - ctx.clock.now()).total_seconds()
        if remaining <= 0:
            return None, deadline
        ctx.clock.sleep(min(ctx.cfg.timing.poll_interval_s, remaining))


def _eval_control(ctx, ctl, ctl_rid, sha_before, commit, state_at, since, res, closed_by):
    """CTL-001: w oknie r2 nie dostał findingu i jest no-violations (atrybucja do r1)."""
    refs = ctx.site.reports_since(sha_before, commit, ctl_rid)
    reports = [(r, ctx.site.report(r)) for r in refs]
    violations = []
    for _, rep in reports or [(None, None)]:
        violations += [v for v in oracle_eval(ctl, rep, state_at) if v not in violations]
    last = state_at.get("last_run") or {}
    cyc = (cycles_after(since, parse_ts(last["finished_at"]), ctx.cfg.timing.cycle_s)
           if last.get("finished_at") else 0)
    res["control"]["window"] = {"closed_by": closed_by, "since": iso(since),
                                "closing_commit": commit, "cycles_after": cyc,
                                "posture": state_at.get("posture"),
                                "reports": [r.path for r, _ in reports]}
    if cyc < 2:       # r2 nie obserwował ≥ 2 cykli → kontrola nieważna
        res["control"]["verdict"] = "invalid"
        res["control"]["reasons"] = [f"kontrola nie obserwowała ruchu ({cyc} cykli)"]
        return
    res["control"]["oracle"]["violations"] = violations
    res["control"]["verdict"] = "fail" if violations else "pass"
    res["control"]["reasons"] = violations


def _combine(res):
    vd, vc = res["dynamic"]["verdict"], res["control"]["verdict"]
    reasons = ["dynamic: " + r for r in res["dynamic"]["reasons"]] + \
              ["control: " + r for r in res["control"]["reasons"]]
    for bad in ("invalid", "error", "timeout", "fail"):
        if bad in (vd, vc):
            return bad, reasons
    return "pass", reasons


def _teardown_pair(ctx, dyn, ctl, routers, res):
    """Zatrzymanie ruchu → revert (jeśli playbook) → pełny reset wg `teardown.reset` manifestów →
    czekanie na rozwiązanie findingu na routerze dynamicznym (D-B5)."""
    td = res["teardown"]
    dyn_rid = routers["dynamic"]
    _stop_generate(ctx, dyn, dyn_rid, res)

    playbook = dyn["apply"].get("playbook")
    if playbook:
        try:
            ctx.ansible.playbook(playbook, ctx.cfg.router(dyn_rid), "revert",
                                 {"covert_target": (res["generate"] or {}).get("target")})
            td["revert"] = "ok"
        except HarnessError as e:
            td["revert"] = "error"        # niefatalne: pełny reset i tak przywraca baseline
            log.error("teardown: revert: %s (pełny reset to naprawi)", e)
    else:
        td["revert"] = "skipped"

    reset_ok = True
    for arm, m in (("dynamic", dyn), ("control", ctl)):
        rid = routers[arm]
        if not (m.get("teardown") or {}).get("reset"):
            continue
        rid_run = new_run_id(ctx.clock.now())
        log.info("pair: teardown — pełny reset %s (%s)", rid, rid_run)
        try:
            reset = run_reset(ctx, rid, rid_run)
        except (HarnessError, UsageError) as e:
            td[f"reset_{arm}"] = {"run_id": rid_run, "ok": False, "error": str(e)}
            reset_ok = False
            continue
        path = write_reset(reset, ctx.cfg.results_dir)
        td[f"reset_{arm}"] = {"run_id": rid_run, "ok": reset["ok"], "error": reset["error"],
                              "path": path.name, "gate": reset["gate"]}
        if reset.get("interrupted"):
            raise KeyboardInterrupt
        reset_ok = reset_ok and reset["ok"]

    if not reset_ok:
        td.update(ok=False, error="pełny reset niezgodny")
        return
    stop = (res["generate"] or {}).get("stop")
    if stop is not None and not stop.get("confirmed"):
        td.update(ok=False, error="zatrzymanie ruchu niepotwierdzone — bez czekania na rozwiązanie")
        return
    resolved, why = _wait_resolved(ctx, dyn_rid, ctx.cfg.resolve_timeout(dyn["id"]))
    td["resolved"] = resolved
    td["ok"] = resolved["ok"]
    if not resolved["ok"]:
        td["error"] = why
        log.error("teardown: %s", why)

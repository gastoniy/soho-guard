"""Kampania: plan YAML (`harness/campaigns/*.yml`) → pełne resety na start, przebiegi kroków
z powtórzeniami i losowym przesunięciem (ziarno kampanii), zbiorczy wynik JSON.

Plan:
  campaign_id: static-pol003          # [a-z0-9-]
  description: "…"                    # opcjonalnie
  reset_at_start: [r2, r1]            # pełny reset (H4) przed pierwszym krokiem; domyślnie brak
  close_artifacts: true               # H9: --close-artifacts dla wszystkich przebiegów; domyślnie false
  steps:
    - { manifest: scenarios/policy/policy-socks-enabled.yml, target: r2, repeat: 10 }
    - { manifest: …, target: r1, repeat: 1, offset: 100 }   # offset: stałe przesunięcie [s]
    - { manifest: <dynamic>, control: <control> }          # para (iteracja 5): repeat 1, bez target

Przerwanie kampanii (kod 3): nieudany reset, werdykt `invalid` lub `error`, Ctrl-C. Niezgodna bramka
po teardownie: pełny reset routera i ponowna bramka (w resecie); zgodna → kampania idzie dalej
(przebieg zostaje z `teardown.ok = false`), niezgodna → przerwanie. `fail`/`timeout` nie przerywa
(kod 1 na końcu). Kolejność H8 (statyka r2 → r1 → benign → dynamic/control) tylko ostrzega.
Wynik zbiorczy zapisywany po każdym przebiegu (stan kampanii przetrwa przerwanie).
"""
from __future__ import annotations

import hashlib
import logging
import re
from collections import Counter
from pathlib import Path

import yaml

from . import REPO_ROOT, HarnessError, UsageError
from .config import load_yaml_unique
from .logs import run_log
from .reset import run_reset
from .pair import run_pair
from .results import (RESULT_VERSION, harness_commit, new_run_id, write, write_campaign, write_pair,
                      write_reset)
from .scenario import load_manifest, run_scenario
from .timing import check_offset, iso

log = logging.getLogger("harness")

PLAN_KEYS = {"campaign_id", "description", "reset_at_start", "close_artifacts", "steps"}
STEP_KEYS = {"manifest", "target", "repeat", "offset", "control"}
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
# H8: statyka → BEN-001 → dynamika (DYN-011b razem z CTL-001)
CLASS_RANK = {"policy": 0, "site": 0, "benign": 1, "dynamic": 2, "control": 2}
STATIC_ROUTER_ORDER = ("r2", "r1")


def _resolve(manifest: str) -> Path:
    p = Path(manifest)
    return p if p.is_absolute() else REPO_ROOT / p


def load_plan(path: Path, cfg) -> dict:
    """Plan po walidacji: kroki z wczytanym manifestem, routerem docelowym i ostrzeżeniami H8."""
    try:
        doc = load_yaml_unique(path.read_text(encoding="utf-8"))
    except OSError as e:
        raise UsageError(f"plan {path}: {e}") from None
    except yaml.YAMLError as e:     # także zduplikowane klucze
        raise UsageError(f"plan {path}: błędny YAML: {e}") from None
    if not isinstance(doc, dict):
        raise UsageError(f"plan {path}: oczekiwano mapy YAML")
    unknown = sorted(set(doc) - PLAN_KEYS)
    if unknown:
        raise UsageError(f"plan {path}: nieznane klucze {unknown}")
    cid = doc.get("campaign_id")
    if not isinstance(cid, str) or not _ID_RE.match(cid):
        raise UsageError(f"plan {path}: campaign_id musi pasować do [a-z0-9-]")
    resets = doc.get("reset_at_start") or []
    if not isinstance(resets, list) or any(not isinstance(r, str) for r in resets):
        raise UsageError(f"plan {path}: reset_at_start musi być listą routerów")
    for r in resets:
        rc = cfg.router(r)
        if not rc.upload or cfg.build_dir is None or cfg.ssh_known_hosts is None:
            raise UsageError(f"plan {path}: reset {r} wymaga w harness.yml build_dir, "
                             f"ssh.known_hosts i routers.{r}.upload")
    close = doc.get("close_artifacts", False)
    if not isinstance(close, bool):
        raise UsageError(f"plan {path}: close_artifacts musi być true/false")
    steps_doc = doc.get("steps")
    if not isinstance(steps_doc, list) or not steps_doc:
        raise UsageError(f"plan {path}: steps musi być niepustą listą")

    steps = []
    for i, st in enumerate(steps_doc, 1):
        where = f"plan {path}: steps[{i}]"
        if not isinstance(st, dict) or "manifest" not in st:
            raise UsageError(f"{where}: wymagany klucz manifest")
        unknown = sorted(set(st) - STEP_KEYS)
        if unknown:
            raise UsageError(f"{where}: nieznane klucze {unknown}")
        mpath = _resolve(str(st["manifest"]))
        m = load_manifest(mpath)
        cpath = cm = None
        if "control" in st:
            # para: routery z manifestów; każdy przebieg = nowy cel i odczyt z węzła → repeat 1
            if "target" in st or st.get("repeat", 1) != 1:
                raise UsageError(f"{where}: krok pary nie przyjmuje target, a repeat musi być 1")
            cpath = _resolve(str(st["control"]))
            cm = load_manifest(cpath)
            if cm["class"] != "control" or m["class"] != "dynamic":
                raise UsageError(f"{where}: para wymaga manifest: dynamic i control: control")
            if (cm.get("teardown") or {}).get("reset"):
                t = cm["target"]["router_id"]
                rc = cfg.router(t)
                if not rc.upload or cfg.build_dir is None or cfg.ssh_known_hosts is None:
                    raise UsageError(f"{where}: teardown {t} (pełny reset) wymaga w harness.yml "
                                     f"build_dir, ssh.known_hosts i routers.{t}.upload")
        target = st.get("target") or m["target"]["router_id"]
        cfg.router(target)
        repeat = st.get("repeat", 1)
        if not isinstance(repeat, int) or isinstance(repeat, bool) or repeat < 1:
            raise UsageError(f"{where}: repeat musi być liczbą całkowitą ≥ 1")
        offset = st.get("offset")
        if offset is not None:
            check_offset(float(offset), cfg.timing)
        if not m["expect"]["detected"] and m["class"] not in cfg.windows:
            raise UsageError(f"{where}: brak windows.{m['class']} w harness.yml (H10)")
        if "generate" in m:
            cfg.endpoint(m["generate"]["to_endpoint"])        # pula adresów (krok generate)
            if (m.get("teardown") or {}).get("reset"):        # teardown dynamiczny = pełny reset
                rc = cfg.router(target)
                if not rc.upload or cfg.build_dir is None or cfg.ssh_known_hosts is None:
                    raise UsageError(f"{where}: teardown {target} (pełny reset) wymaga w harness.yml "
                                     f"build_dir, ssh.known_hosts i routers.{target}.upload")
        steps.append({"index": i, "manifest_path": mpath, "manifest": str(st["manifest"]),
                      "control_path": cpath, "control_id": cm["id"] if cm else None,
                      "id": m["id"], "class": m["class"], "target": target,
                      "repeat": repeat, "offset": None if offset is None else float(offset)})
    return {"campaign_id": cid, "description": doc.get("description"), "path": path,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "reset_at_start": list(resets), "close_artifacts": close, "steps": steps,
            "order_warnings": order_warnings(steps)}


def order_warnings(steps: list[dict]) -> list[str]:
    out = []
    for prev, cur in zip(steps, steps[1:]):
        rp, rc = CLASS_RANK[prev["class"]], CLASS_RANK[cur["class"]]
        if rc < rp:
            out.append(f"krok {cur['index']} ({cur['id']}, {cur['class']}) po kroku "
                       f"{prev['index']} ({prev['id']}, {prev['class']}) — H8: statyka → benign → dynamika")
        elif rc == rp == 0 and prev["target"] != cur["target"]:
            order = STATIC_ROUTER_ORDER
            if (prev["target"] in order and cur["target"] in order
                    and order.index(cur["target"]) < order.index(prev["target"])):
                out.append(f"krok {cur['index']} ({cur['id']} {cur['target']}) po "
                           f"{prev['id']} {prev['target']} — H8: statyka najpierw r2, potem r1")
    return out


def _new_summary(ctx, plan: dict, run_id: str) -> dict:
    return {
        "result_version": RESULT_VERSION,
        "kind": "campaign",
        "run_id": run_id,
        "campaign_id": plan["campaign_id"],
        "description": plan["description"],
        "plan": {"path": _rel(plan["path"]), "sha256": plan["sha256"]},
        "harness_commit": harness_commit(),
        "seed": ctx.seed,
        "close_artifacts": plan["close_artifacts"],
        "started_at": iso(ctx.clock.now()),
        "finished_at": None,
        "order_warnings": plan["order_warnings"],
        "steps": [{k: s[k] for k in ("index", "manifest", "id", "control_id", "target", "repeat",
                                     "offset")}
                  for s in plan["steps"]],
        "resets": [],
        "runs": [],
        "aborted": None,
        "counts": {},
    }


def _rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _reset(ctx, router_id: str, reason: str, summary: dict) -> bool:
    rid = new_run_id(ctx.clock.now())
    with run_log(ctx.cfg.results_dir, rid):
        log.info("kampania %s: pełny reset %s (%s)", summary["campaign_id"], router_id, reason)
        try:
            res = run_reset(ctx, router_id, rid)
        except (HarnessError, UsageError) as e:
            summary["resets"].append({"run_id": rid, "router_id": router_id, "reason": reason,
                                      "ok": False, "error": str(e), "path": None})
            return False
        res["campaign"] = {"id": summary["campaign_id"], "run_id": summary["run_id"],
                           "reason": reason}
        path = write_reset(res, ctx.cfg.results_dir)
    summary["resets"].append({"run_id": rid, "router_id": router_id, "reason": reason,
                              "ok": res["ok"], "error": res["error"], "path": path.name,
                              "mgmt_return_s": res["timing"]["mgmt_return_s"],
                              "ssh_ready_s": res["timing"]["ssh_ready_s"]})
    if res.get("interrupted"):
        raise KeyboardInterrupt
    return bool(res["ok"])


def _save(ctx, summary: dict) -> Path:
    summary["counts"] = dict(Counter(r["verdict"] for r in summary["runs"]))
    return write_campaign(summary, ctx.cfg.results_dir)


def _run_pair_step(ctx, plan, st, rid, run_id, operator_checks):
    res = run_pair(ctx, st["manifest_path"], st["control_path"], offset_s=st["offset"],
                   close_artifacts=plan["close_artifacts"], run_id=rid,
                   operator_checks=operator_checks)
    res["campaign"] = {"id": plan["campaign_id"], "run_id": run_id, "step": st["index"],
                       "index": 1, "of": 1}
    path = write_pair(res, ctx.cfg.results_dir)
    m = res["dynamic"].get("metrics") or {}
    row = {"run_id": rid, "step": st["index"], "index": 1,
           "manifest_id": f"{res['pair']['dynamic_id']}+{res['pair']['control_id']}",
           "router_id": st["target"], "verdict": res["verdict"], "mttd_s": m.get("mttd_s"),
           "window_s": None, "teardown_ok": res["teardown"]["ok"], "reasons": res["reasons"],
           "path": path.name}
    return res, row


def run_campaign(ctx, plan: dict, run_id: str, operator_checks: dict | None = None) -> dict:
    summary = _new_summary(ctx, plan, run_id)
    for w in plan["order_warnings"]:
        log.warning("kolejność: %s", w)
    total = sum(s["repeat"] for s in plan["steps"])
    log.info("kampania %s (%s): %d kroków, %d przebiegów, seed=%s", plan["campaign_id"], run_id,
             len(plan["steps"]), total, ctx.seed)
    try:
        for r in plan["reset_at_start"]:
            if not _reset(ctx, r, "start", summary):
                summary["aborted"] = f"nieudany reset {r} na starcie kampanii"
                return summary
            _save(ctx, summary)

        n = 0
        for st in plan["steps"]:
            for i in range(1, st["repeat"] + 1):
                n += 1
                rid = new_run_id(ctx.clock.now())
                if st["control_path"] is not None:
                    with run_log(ctx.cfg.results_dir, rid):
                        log.info("kampania %s [%d/%d]: krok %d para %s+%s", plan["campaign_id"], n,
                                 total, st["index"], st["id"], st["control_id"])
                        res, row = _run_pair_step(ctx, plan, st, rid, run_id, operator_checks)
                    summary["runs"].append(row)
                    _save(ctx, summary)
                    if res.get("interrupted"):
                        raise KeyboardInterrupt
                    if res["verdict"] in ("invalid", "error"):
                        summary["aborted"] = (f"para {row['manifest_id']}: {res['verdict']} — "
                                              + "; ".join(res["reasons"])[:500])
                        return summary
                    continue
                with run_log(ctx.cfg.results_dir, rid):
                    log.info("kampania %s [%d/%d]: krok %d %s %s [%d/%d]", plan["campaign_id"], n,
                             total, st["index"], st["id"], st["target"], i, st["repeat"])
                    res = run_scenario(ctx, st["manifest_path"], target=st["target"],
                                       offset_s=st["offset"],
                                       close_artifacts=plan["close_artifacts"], run_id=rid,
                                       gen_index=i - 1)
                    res["campaign"] = {"id": plan["campaign_id"], "run_id": run_id,
                                       "step": st["index"], "index": i, "of": st["repeat"]}
                    res["repeat"] = {"index": i, "of": st["repeat"]}
                    path = write(res, ctx.cfg.results_dir)
                m = res.get("metrics") or {}
                summary["runs"].append({
                    "run_id": rid, "step": st["index"], "index": i,
                    "manifest_id": st["id"], "router_id": st["target"],
                    "verdict": res["verdict"], "mttd_s": m.get("mttd_s"),
                    "window_s": m.get("window_s"), "teardown_ok": res["teardown"]["ok"],
                    "reasons": res["reasons"], "path": path.name,
                })
                _save(ctx, summary)
                if res.get("interrupted"):
                    raise KeyboardInterrupt
                if res["verdict"] in ("invalid", "error"):
                    summary["aborted"] = (f"{st['id']} {st['target']} [{i}/{st['repeat']}]: "
                                          f"{res['verdict']} — " + "; ".join(res["reasons"])[:500])
                    return summary
                if res["teardown"]["ok"] is False:
                    log.warning("kampania: teardown niezgodny po %s — pełny reset %s", rid,
                                st["target"])
                    if not _reset(ctx, st["target"], f"teardown {rid}", summary):
                        summary["aborted"] = (f"pełny reset {st['target']} po niezgodnym "
                                              f"teardownie {rid} nieudany")
                        return summary
                    _save(ctx, summary)
        return summary
    except KeyboardInterrupt:
        summary["aborted"] = "przerwane przez operatora (Ctrl-C)"
        summary["interrupted"] = True
        return summary
    finally:
        summary["finished_at"] = iso(ctx.clock.now())
        path = _save(ctx, summary)
        log.info("kampania %s: %s, %s → %s", plan["campaign_id"],
                 "PRZERWANA: " + summary["aborted"] if summary["aborted"] else "zakończona",
                 summary["counts"], path.name)

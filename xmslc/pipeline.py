"""End-to-end orchestration: generate/ingest -> normalise -> profile -> detect -> evaluate."""
from __future__ import annotations

import random
import time
from collections import Counter, defaultdict
from datetime import timedelta

from .config import Config, build_config
from .detectors.correlator import run_correlator
from .detectors.iforest import run_iforest
from .detectors.profiles import build_profiles
from .detectors.rules import run_rules
from .evaluation import evaluate
from .generator import EPOCH, Generator, to_raw
from .knowledge import STAGES
from .normaliser import normalise

DETECTORS = {"A": "Independent rules", "B": "Isolation Forest", "C": "Multi-stage correlation"}


def _public_alert(a, cap=400):
    d = {k: v for k, v in a.items() if not k.startswith("_") and k != "evidence_ids"}
    d["evidence_count"] = len(a["evidence_ids"])
    d["evidence_sample"] = a["evidence_ids"][:6]
    return d


def _public_incident(i):
    d = {k: v for k, v in i.items() if k != "evidence_ids"}
    d["stages"] = [{k: v for k, v in s.items() if k != "evidence_all"} for s in i["stages"]]
    d["evidence_sample"] = i["evidence_ids"][:10]
    return d


def _timed(label, fn, steps):
    t0 = time.perf_counter()
    out = fn()
    steps.append({"step": label, "ms": round((time.perf_counter() - t0) * 1000, 1)})
    return out


def analyse(events, chains, eval_start, cfg: Config, steps, extras=None):
    ev_by_id = {e["event_id"]: e for e in events}
    eval_end = max((e["timestamp"] for e in events), default=eval_start) + timedelta(seconds=1)
    profiles, org = _timed("Learn baseline profiles", lambda: build_profiles(events, eval_start, cfg.burst_window_min), steps)
    users = sorted({e["user"] for e in events})
    alerts_a = _timed("Detector A - rules", lambda: run_rules(events, profiles, org, eval_start, cfg), steps)
    alerts_b, info_b = _timed("Detector B - Isolation Forest", lambda: run_iforest(events, profiles, org, eval_start, cfg, cfg.seed), steps)
    inc_c, suppressed = _timed("Detector C - correlation", lambda: run_correlator(events, profiles, org, eval_start, cfg, ev_by_id), steps)
    metrics = None
    if chains is not None:
        metrics = _timed("Evaluate against ground truth", lambda: {
            "A": evaluate(alerts_a, chains, ev_by_id, len(users), eval_start, eval_end),
            "B": evaluate(alerts_b, chains, ev_by_id, len(users), eval_start, eval_end),
            "C": evaluate(inc_c, chains, ev_by_id, len(users), eval_start, eval_end)}, steps)
        # annotate suppressed chains with ground truth + explain misses
        for s in suppressed:
            s["matched"] = [c["chain_id"] for c in chains if c["user"] == s["user"] and
                            min(e for e in [s["start"]]) <= c["end"] + timedelta(seconds=60) and s["end"] >= c["start"] - timedelta(seconds=60)]
    return {"ev_by_id": ev_by_id, "profiles": profiles, "org": org, "users": users, "alerts_a": alerts_a,
            "alerts_b": alerts_b, "info_b": info_b, "inc_c": inc_c, "suppressed": suppressed, "metrics": metrics,
            "eval_end": eval_end}


def _miss_reason(chain, sup, cfg):
    cands = [s for s in sup if chain["chain_id"] in s.get("matched", [])]
    planned = ", ".join(chain["planned_stages"]) or "none"
    if cands:
        s = max(cands, key=lambda x: x["score"])
        return (f"Correlator saw {len(s['stage_ids'])} stage(s) ({', '.join(s['stages'])}) with score {s['score']:g}: {s['reason']}. "
                f"Attacker planned stages: {planned}.")
    return (f"No stage was triggered strongly enough to link events (planned stages: {planned}). "
            "Typical causes: attacker stealth stretched events beyond the windows, or log records were dropped.")


def _findings(summary):
    m = summary["metrics"]
    if not m:
        return []
    A, B, C = m["A"], m["B"], m["C"]
    out = []
    pc = lambda x: f"{x * 100:.0f}%"  # noqa: E731
    out.append(f"Detector C (multi-stage correlation) detected {C['detected_chains']} of {C['attack_chains']} attack chains "
               f"(recall {pc(C['recall'])}), compared with {pc(A['recall'])} for independent rules and {pc(B['recall'])} for Isolation Forest.")
    out.append(f"To get there, rules raised {A['alerts']} alerts and Isolation Forest {B['alerts']}, whereas the correlator raised {C['alerts']} "
               f"consolidated incident(s); investigation precision was {pc(C['precision'])} (C) vs {pc(A['precision'])} (A) and {pc(B['precision'])} (B).")
    if A["alerts"]:
        red = (1 - C['alerts'] / A['alerts']) * 100
        out.append(f"Alert volume versus rules: the correlator presents {abs(red):.0f}% {'fewer' if red >= 0 else 'more'} items for an analyst to triage.")
    out.append(f"False-positive rate over benign user-days: A {pc(A['fpr'])}, B {pc(B['fpr'])}, C {pc(C['fpr'])}.")
    if C["control_chains"]:
        out.append(f"Benign travel/VPN control: {C['control_flagged']} of {C['control_chains']} flagged by C, "
                   f"{A['control_flagged']} by A and {B['control_flagged']} by B.")
    if C["mttd_min"] is not None:
        t = f"Mean time to detection: C {C['mttd_min']:g} min"
        if A["mttd_min"] is not None:
            t += f", A {A['mttd_min']:g} min"
        if B["mttd_min"] is not None:
            t += f", B {B['mttd_min']:g} min (batch windows cannot alert before they close)"
        out.append(t + ".")
    if C["fidelity"] is not None:
        out.append(f"Evidence localisation (fidelity F1): C {C['fidelity']:.2f}"
                   + (f", rules {A['fidelity']:.2f} (each alert cites a single trigger event)" if A["fidelity"] is not None else "")
                   + (f", Isolation Forest {B['fidelity']:.2f} (cites every event of the flagged window, which here is dominated by the attack)" if B["fidelity"] is not None else "")
                   + ". Fidelity measures WHERE the evidence points; only C also supplies reasons (stage, rule, counter-evidence, ATT&CK mapping).")
    if C["missed_chains"]:
        out.append(f"{C['missed_chains']} attack chain(s) were missed by C - the table of ground-truth chains below gives the reason for each miss.")
    out.append("All numbers come from synthetic data: they compare the three methods under identical, documented assumptions and do not predict real-world performance.")
    return out


def run_synthetic(overrides: dict | None = None):
    cfg = build_config(overrides)
    steps = []
    gen = Generator(cfg)
    events_true, chains, users_meta = _timed("Generate synthetic logs", gen.generate, steps)
    raw = [to_raw(e) for e in events_true]
    if cfg.drop_rate > 0:
        rr = random.Random(cfg.seed + 777)
        raw = [r for r in raw if rr.random() >= cfg.drop_rate]
    events, qrep = _timed("Normalise to common schema", lambda: normalise(raw), steps)
    eval_start = EPOCH + timedelta(days=cfg.baseline_days)
    res = analyse(events, chains, eval_start, cfg, steps)
    return _assemble(cfg, events, raw, chains, users_meta, qrep, eval_start, res, steps, custom=False)


def run_custom(records: list[dict], overrides: dict | None, baseline_fraction: float):
    cfg = build_config(overrides)
    steps = []
    events, qrep = _timed("Normalise to common schema", lambda: normalise(records), steps)
    if not events:
        raise ValueError("No valid events could be parsed from the input. Check column names and timestamps.")
    t0, t1 = events[0]["timestamp"], events[-1]["timestamp"]
    bf = min(max(baseline_fraction, 0.1), 0.9)
    eval_start = t0 + (t1 - t0) * bf
    res = analyse(events, None, eval_start, cfg, steps)
    return _assemble(cfg, events, records, None, [], qrep, eval_start, res, steps, custom=True)


def _assemble(cfg, events, raw, chains, users_meta, qrep, eval_start, res, steps, custom):
    ev_by_id = res["ev_by_id"]
    gt_map, flags = {}, defaultdict(set)
    if chains:
        for c in chains:
            for i in c["event_ids"]:
                gt_map[i] = {"chain_id": c["chain_id"], "scenario": c["scenario"], "label": c["label"]}
    for a in res["alerts_a"]:
        for i in a["evidence_ids"]:
            flags[i].add("A")
    for a in res["alerts_b"]:
        for i in a["evidence_ids"]:
            flags[i].add("B")
    for a in res["inc_c"]:
        for i in a["evidence_ids"]:
            flags[i].add("C")
    # per-hour distribution and per-day alert counts
    hours = {"normal": [0] * 24, "attack": [0] * 24}
    for e in events:
        hours["attack" if e["event_id"] in gt_map and gt_map[e["event_id"]]["label"] == "attack" else "normal"][e["timestamp"].hour] += 1
    day0 = events[0]["timestamp"].replace(hour=0, minute=0, second=0)
    n_days = max(1, (events[-1]["timestamp"] - day0).days + 1)
    per_day = {k: [0] * n_days for k in "ABC"}
    for k, lst in (("A", res["alerts_a"]), ("B", res["alerts_b"]), ("C", res["inc_c"])):
        for a in lst:
            d = (a["time"] - day0).days
            if 0 <= d < n_days:
                per_day[k][d] += 1
    types = Counter(e["event_type"] for e in events)
    chains_out = []
    if chains:
        m = res["metrics"]
        for c in chains:
            row = {"chain_id": c["chain_id"], "scenario": c["scenario"], "label": c["label"], "user": c["user"],
                   "start": c["start"], "end": c["end"], "n_events": len(c["event_ids"]), "planned_stages": c["planned_stages"],
                   "description": c["description"], "detected": {k: m[k]["per_chain"][c["chain_id"]] for k in "ABC"}}
            if c["label"] == "attack" and not row["detected"]["C"]["detected"]:
                row["miss_reason_c"] = _miss_reason(c, res["suppressed"], cfg)
            chains_out.append(row)
    summary = {
        "config": cfg.to_dict(), "custom": custom,
        "dataset": {"events": len(events), "users": len(res["users"]), "types": dict(types),
                    "start": events[0]["timestamp"], "end": events[-1]["timestamp"], "eval_start": eval_start,
                    "baseline_events": sum(e["timestamp"] < eval_start for e in events),
                    "eval_events": sum(e["timestamp"] >= eval_start for e in events),
                    "attack_events": sum(1 for v in gt_map.values() if v["label"] == "attack"),
                    "users_meta": [{"user": u["user"], "dept": u["dept"], "role": u["role"]} for u in users_meta][:200],
                    "cold_start_users": sum(1 for p in res["profiles"].values() if p["cold"]),
                    "profiled_users": len(res["profiles"])},
        "quality": qrep, "steps": steps, "hours": hours, "per_day": per_day, "day0": day0,
        "detectors": {
            "A": {"name": DETECTORS["A"], "total": len(res["alerts_a"]), "alerts": [_public_alert(a) for a in res["alerts_a"][:400]],
                  "by_rule": dict(Counter(a["rule"] for a in res["alerts_a"]))},
            "B": {"name": DETECTORS["B"], "total": len(res["alerts_b"]), "alerts": [_public_alert(a) for a in res["alerts_b"][:400]],
                  "info": res["info_b"]},
            "C": {"name": DETECTORS["C"], "total": len(res["inc_c"]),
                  "incidents": [_public_incident(i) for i in res["inc_c"][:200]],
                  "suppressed": [{k: v for k, v in s.items() if k != "evidence_ids"} for s in res["suppressed"][:100]],
                  "stage_counts": dict(Counter(x for i in res["inc_c"] for x in i["stage_ids"]))},
        },
        "metrics": {k: {kk: vv for kk, vv in v.items() if kk != "per_chain"} for k, v in res["metrics"].items()} if res["metrics"] else None,
        "chains": chains_out, "findings": [],
    }
    summary["findings"] = _findings(summary)
    store = {"events": events, "raw": raw, "gt_map": gt_map, "flags": flags, "ev_by_id": ev_by_id,
             "alerts_a": res["alerts_a"], "alerts_b": res["alerts_b"], "inc_c": res["inc_c"]}
    return summary, store

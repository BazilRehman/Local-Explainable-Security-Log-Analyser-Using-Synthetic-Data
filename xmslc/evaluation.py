"""Scoring of detector output against the hidden ground-truth attack chains."""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

TOL = timedelta(seconds=60)


def _interval(a, ev_by_id):
    times = [ev_by_id[i]["timestamp"] for i in a["evidence_ids"] if i in ev_by_id]
    if not times:
        return a["time"], a["time"]
    return min(times), max(times)


def match(alerts, chains, ev_by_id):
    """Attach the ground-truth chain ids each alert overlaps (same user, overlapping time)."""
    by_user = defaultdict(list)
    for c in chains:
        by_user[c["user"]].append(c)
    for a in alerts:
        a["_t0"], a["_t1"] = _interval(a, ev_by_id)
        a["matched"] = [c["chain_id"] for c in by_user.get(a["user"], [])
                        if a["_t0"] <= c["end"] + TOL and a["_t1"] >= c["start"] - TOL]


def _prf(p, r):
    return 2 * p * r / (p + r) if (p + r) > 0 else 0.0


def evaluate(alerts, chains, ev_by_id, n_users, eval_start, eval_end):
    match(alerts, chains, ev_by_id)
    cmap = {c["chain_id"]: c for c in chains}
    attacks = [c for c in chains if c["label"] == "attack"]
    attack_ids = {c["chain_id"] for c in attacks}
    control_ids = {c["chain_id"] for c in chains if c["label"] != "attack"}
    tp_alerts = [a for a in alerts if set(a["matched"]) & attack_ids]
    ctrl_alerts = [a for a in alerts if (set(a["matched"]) & control_ids) and not (set(a["matched"]) & attack_ids)]
    fp_alerts = [a for a in alerts if not (set(a["matched"]) & attack_ids)]
    per_chain = {}
    for c in chains:
        m = [a for a in alerts if c["chain_id"] in a["matched"]]
        if m:
            first = min(a["time"] for a in m)
            delay = max(0.0, (first - c["start"]).total_seconds() / 60)
            ev = set().union(*[set(a["evidence_ids"]) for a in m])
            truth = set(c["event_ids"])
            hit = len(ev & truth)
            pr, rc = hit / len(ev) if ev else 0.0, hit / len(truth) if truth else 0.0
            per_chain[c["chain_id"]] = {"detected": True, "delay_min": round(delay, 1), "n_alerts": len(m),
                                        "evidence_precision": round(pr, 3), "evidence_recall": round(rc, 3),
                                        "evidence_f1": round(_prf(pr, rc), 3), "alert_ids": [a["alert_id"] for a in m][:12]}
        else:
            per_chain[c["chain_id"]] = {"detected": False, "delay_min": None, "n_alerts": 0, "alert_ids": []}
    det = [cid for cid in attack_ids if per_chain[cid]["detected"]]
    recall = len(det) / len(attacks) if attacks else 0.0
    precision = len(det) / (len(det) + len(fp_alerts)) if (len(det) + len(fp_alerts)) else 0.0
    # false-positive rate over benign user-days
    days = max(1, round((eval_end - eval_start).total_seconds() / 86400))
    attack_days = {(c["user"], c["start"].date()) for c in attacks}
    benign_days = max(1, n_users * days - len(attack_days))
    fp_days = {(a["user"], a["_t0"].date()) for a in fp_alerts if (a["user"], a["_t0"].date()) not in attack_days}
    delays = [per_chain[c]["delay_min"] for c in det]
    fid = [per_chain[c]["evidence_f1"] for c in det]
    by_scen = defaultdict(lambda: [0, 0])
    for c in chains:
        by_scen[c["scenario"]][0] += 1
        by_scen[c["scenario"]][1] += bool(per_chain[c["chain_id"]]["detected"])
    return {
        "alerts": len(alerts), "tp_alerts": len(tp_alerts), "fp_alerts": len(fp_alerts), "control_alerts": len(ctrl_alerts),
        "attack_chains": len(attacks), "detected_chains": len(det), "missed_chains": len(attacks) - len(det),
        "recall": round(recall, 4), "precision": round(precision, 4), "f1": round(_prf(precision, recall), 4),
        "fpr": round(len(fp_days) / benign_days, 4), "fp_user_days": len(fp_days), "benign_user_days": benign_days,
        "mttd_min": round(sum(delays) / len(delays), 2) if delays else None,
        "alerts_per_attack": round(len(tp_alerts) / len(det), 2) if det else None,
        "fidelity": round(sum(fid) / len(fid), 4) if fid else None,
        "control_chains": len(control_ids), "control_flagged": sum(per_chain[c]["detected"] for c in control_ids),
        "per_chain": per_chain,
        "by_scenario": {k: {"total": v[0], "detected": v[1]} for k, v in by_scen.items()},
    }

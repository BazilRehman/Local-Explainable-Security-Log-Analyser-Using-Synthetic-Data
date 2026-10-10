"""Detector B - unsupervised Isolation Forest over per-user time-window features.

Trained on the attack-free baseline period only, then scores every later window.  It is
the 'black-box anomaly detector' baseline: the post-hoc feature deviations attached to
each alert are an approximation, not something the model itself produces.
"""
from __future__ import annotations

import math
from collections import defaultdict
from datetime import timedelta

import numpy as np
from sklearn.ensemble import IsolationForest

from ..knowledge import IF_FEATURES
from .profiles import device_known, empty_profile, ip_known, off_hours

FEATURES = [f[0] for f in IF_FEATURES]


def _vector(user, evs, win_start, profile, org):
    f = dict.fromkeys(FEATURES, 0.0)
    ips = set()
    for e in evs:
        et = e["event_type"]
        if e["src_ip"]:
            ips.add(e["src_ip"])
        if et == "login_failure":
            f["n_fail"] += 1
        elif et == "login_success":
            f["n_success"] += 1
            f["new_ip_logins"] += not ip_known(e["src_ip"], profile)
            f["new_device_logins"] += not device_known(e["device"], profile)
            f["offhours_logins"] += off_hours(e["timestamp"], profile)
        elif et == "file_read":
            f["n_files"] += 1
        elif et in ("admin_action", "priv_change"):
            f["n_admin"] += 1
        elif et == "outbound_transfer":
            f["n_out"] += 1
            f["log_bytes_out"] += e["bytes"]
            dests = profile["dests"] or org["dests"]
            f["new_dest"] += e["resource"] not in dests
    f["log_bytes_out"] = math.log10(1 + f["log_bytes_out"])
    f["n_distinct_ips"] = len(ips)
    hr = win_start.hour + win_start.minute / 60
    f["hour_sin"] = math.sin(2 * math.pi * hr / 24)
    f["hour_cos"] = math.cos(2 * math.pi * hr / 24)
    return [f[k] for k in FEATURES]


def run_iforest(events, profiles, org, eval_start, p, seed=0):
    if not events:
        return [], {"trained_on": 0}
    origin = events[0]["timestamp"].replace(hour=0, minute=0, second=0)
    win = timedelta(minutes=p.if_window_min)
    buckets = defaultdict(list)
    for e in events:
        idx = int((e["timestamp"] - origin) / win)
        buckets[(e["user"], idx)].append(e)
    rows_train, rows_eval = [], []
    for (user, idx), evs in buckets.items():
        ws = origin + idx * win
        we = ws + win
        prof = profiles.get(user) or empty_profile()
        item = (user, ws, we, evs, _vector(user, evs, ws, prof, org))
        if we <= eval_start:
            rows_train.append(item)
        elif ws >= eval_start:
            rows_eval.append(item)
    fallback = len(rows_train) < 20
    train = rows_train if not fallback else rows_train + rows_eval
    info = {"trained_on": len(train), "scored": len(rows_eval), "fallback_all_data": fallback, "features": FEATURES}
    if not train or not rows_eval:
        return [], info
    X = np.array([r[4] for r in train], dtype=float)
    model = IsolationForest(n_estimators=p.if_trees, contamination=float(p.if_contamination), random_state=seed)
    model.fit(X)
    med = np.median(X, axis=0)
    mad = np.median(np.abs(X - med), axis=0) * 1.4826
    sd = X.std(axis=0)
    scale = np.where(mad > 1e-9, mad, np.where(sd > 1e-9, sd, 1.0))
    Xe = np.array([r[4] for r in rows_eval], dtype=float)
    pred = model.predict(Xe)
    raw = -model.score_samples(Xe)
    thr = -float(model.offset_)
    info["threshold"] = round(thr, 4)
    alerts = []
    for (user, ws, we, evs, vec), yhat, sc in zip(rows_eval, pred, raw):
        if yhat != -1:
            continue
        z = (np.array(vec) - med) / scale
        top = np.argsort(-np.abs(z))[:3]
        alerts.append({
            "alert_id": "", "detector": "B", "user": user, "time": we, "window_start": ws, "window_end": we,
            "score": round(float(sc), 4), "threshold": round(thr, 4), "n_events": len(evs),
            "evidence_ids": [e["event_id"] for e in evs],
            "top_features": [{"feature": FEATURES[i], "value": round(float(vec[i]), 3), "baseline_median": round(float(med[i]), 3),
                              "robust_z": round(float(z[i]), 1)} for i in top if abs(z[i]) > 0.5],
            "reason": "Window is statistically unusual compared with the baseline distribution (model gives no causal explanation).",
        })
    alerts.sort(key=lambda a: (a["time"], a["user"]))
    for i, a in enumerate(alerts, 1):
        a["alert_id"] = f"B-{i:04d}"
    return alerts, info

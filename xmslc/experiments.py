"""Multi-seed experiments: aggregate statistics, paired significance tests and robustness sweeps."""
from __future__ import annotations

import math
import statistics as st

from scipy import stats

from .pipeline import run_synthetic

METRICS = ["recall", "precision", "f1", "fpr", "mttd_min", "alerts", "fidelity"]
LOWER_BETTER = {"fpr", "mttd_min", "alerts"}


def _ci95(vals):
    n = len(vals)
    if n < 2:
        return None
    m, sd = st.mean(vals), st.stdev(vals)
    h = stats.t.ppf(0.975, n - 1) * sd / math.sqrt(n)
    return [round(m - h, 4), round(m + h, 4)]


def _agg(vals):
    vals = [v for v in vals if v is not None]
    if not vals:
        return None
    return {"mean": round(st.mean(vals), 4), "sd": round(st.stdev(vals), 4) if len(vals) > 1 else 0.0,
            "ci95": _ci95(vals), "n": len(vals), "min": round(min(vals), 4), "max": round(max(vals), 4)}


def _paired(c, other, metric):
    pairs = [(x, y) for x, y in zip(c, other) if x is not None and y is not None]
    n = len(pairs)
    if n < 3:
        return {"n": n, "note": "need at least 3 paired runs"}
    x, y = [p[0] for p in pairs], [p[1] for p in pairs]
    d = [a - b for a, b in pairs]
    sd = st.stdev(d)
    out = {"n": n, "mean_diff": round(st.mean(d), 4), "cohen_dz": round(st.mean(d) / sd, 3) if sd > 1e-12 else None}
    if sd > 1e-12:
        t = stats.ttest_rel(x, y)
        out.update({"t": round(float(t.statistic), 3), "p_t": float(t.pvalue)})
    else:
        out.update({"t": None, "p_t": 1.0 if abs(st.mean(d)) < 1e-12 else 0.0, "note": "zero variance in differences"})
    try:
        w = stats.wilcoxon(x, y, zero_method="wilcox")
        out["p_w"] = float(w.pvalue)
    except ValueError:
        out["p_w"] = None
    return out


def run_experiment(overrides: dict, n_runs: int = 10):
    n_runs = max(3, min(int(n_runs), 30))
    base = int(overrides.get("seed", 42))
    per = {k: {m: [] for m in METRICS} for k in "ABC"}
    seeds, scen = [], {k: {} for k in "ABC"}
    for i in range(n_runs):
        sd = base + i
        seeds.append(sd)
        s, _ = run_synthetic({**overrides, "seed": sd})
        for k in "ABC":
            mm = s["metrics"][k]
            for m in METRICS:
                per[k][m].append(mm[m])
            for sc, v in mm["by_scenario"].items():
                a = scen[k].setdefault(sc, [0, 0])
                a[0] += v["total"]
                a[1] += v["detected"]
    summary = {k: {m: _agg(per[k][m]) for m in METRICS} for k in "ABC"}
    comps = []
    families = ["f1", "recall", "precision", "fpr", "alerts"]
    n_tests = len(families) * 2
    for other in ("A", "B"):
        for m in families:
            r = _paired(per["C"][m], per[other][m], m)
            r.update({"pair": f"C vs {other}", "metric": m, "lower_is_better": m in LOWER_BETTER})
            if "p_t" in r:
                r["p_t_adj"] = min(1.0, r["p_t"] * n_tests)
                better = (r["mean_diff"] < 0) if m in LOWER_BETTER else (r["mean_diff"] > 0)
                r["direction"] = "C better" if better and r["mean_diff"] != 0 else ("no difference" if r["mean_diff"] == 0 else "C worse")
                r["significant"] = r["p_t_adj"] < 0.05
            comps.append(r)
    scen_out = {k: {sc: {"total": v[0], "detected": v[1], "rate": round(v[1] / v[0], 3) if v[0] else None}
                    for sc, v in scen[k].items()} for k in "ABC"}
    return {"n_runs": n_runs, "seeds": seeds, "per_seed": per, "summary": summary, "comparisons": comps,
            "by_scenario": scen_out, "bonferroni_tests": n_tests}


SWEEPS = {"drop_rate": [0.0, 0.1, 0.2, 0.3, 0.4], "noise_level": [0.1, 0.3, 0.5, 0.7, 1.0], "stealth": [0.0, 0.25, 0.5, 0.75, 1.0]}


def run_robustness(overrides: dict, var: str, runs_per_level: int = 3):
    """One robustness sweep: vary a single stress variable, average over seeds, per detector."""
    if var not in SWEEPS:
        raise ValueError(f"unknown sweep variable '{var}'")
    runs_per_level = max(2, min(int(runs_per_level), 8))
    base = int(overrides.get("seed", 42))
    rows = []
    for lv in SWEEPS[var]:
        acc = {k: {m: [] for m in ("recall", "precision", "f1", "fpr")} for k in "ABC"}
        for i in range(runs_per_level):
            s, _ = run_synthetic({**overrides, var: lv, "seed": base + 1000 + i})
            for k in "ABC":
                for m in acc[k]:
                    acc[k][m].append(s["metrics"][k][m])
        rows.append({"level": lv, **{k: {m: round(st.mean(v), 4) for m, v in acc[k].items()} for k in "ABC"}})
    return {"variable": var, "runs_per_level": runs_per_level, "rows": rows}

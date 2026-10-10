"""Detector C - context-aware multi-stage log correlation (the proposed method).

For every user a finite-state tracker follows six ordered attack stages (S1..S6).  A stage
is entered when an event matches its definition *relative to that user's own baseline*.
Stages only link while consecutive stage events fall inside a sliding chain window.  The
chain score is the sum of stage weights plus an order bonus and a velocity bonus; an
incident is raised when the score and the number of distinct stages both reach their
thresholds.  Every point of the score can be traced to concrete log events.
"""
from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta

from ..knowledge import STAGES, classify_chain
from .profiles import (device_known, empty_profile, geo_known, ip_known, off_hours)


def _new_state():
    return {"stages": {}, "first_t": None, "last_t": None, "incident": None}


def _expire(q, t, minutes):
    lim = timedelta(minutes=minutes)
    while q and t - q[0][0] > lim:
        q.popleft()


def _hhmm(h: float) -> str:
    return f"{int(h) % 24:02d}:{int((h % 1) * 60):02d}"


def _triggers(e, prof, org, f1, f2, files, st, p):
    """Return the stages this event satisfies: list of (stage, evidence_ids, detail, discounted)."""
    out = []
    et, t = e["event_type"], e["timestamp"]
    if et == "login_failure":
        if len(f1) >= p.s1_fail_threshold:
            ips = sorted({i for _, _, i in f1 if i})
            out.append((1, [i for _, i, _ in f1],
                        {"count": len(f1), "reasons": [
                            f"{len(f1)} failed logins within {p.s1_window_min} min (threshold {p.s1_fail_threshold})"
                            + (f" from {', '.join(ips[:3])}" if ips else "") + " - consistent with password guessing or credential stuffing."]}, False))
    elif et == "login_success":
        recent = [(tt, i, ip) for tt, i, ip in f2]
        by_fail = len(recent) >= p.s2_fail_min
        novel_ip = not ip_known(e["src_ip"], prof)
        discount = bool(e["via_vpn"]) and 1 not in st["stages"] and not by_fail
        if by_fail or novel_ip:
            reasons = []
            if by_fail:
                reasons.append(f"Login succeeded after {len(recent)} failed attempts within {p.s2_window_min} min.")
            if novel_ip:
                known = ", ".join(sorted(prof["ips"])[:3]) or "none"
                reasons.append(f"Source IP {e['src_ip']} never appears in this user's baseline (known: {known}).")
            if discount:
                reasons.append(f"Session came through the corporate VPN, so its weight is multiplied by {p.vpn_discount:g}.")
            out.append((2, [e["event_id"]] + ([i for _, i, _ in recent] if by_fail else []),
                        {"recent_failures": len(recent), "novel_ip": novel_ip, "reasons": reasons}, discount))
        reasons = []
        if not device_known(e["device"], prof):
            reasons.append(f"Device '{e['device']}' is not among the user's baseline devices ({', '.join(sorted(prof['devices'])) or 'none'}).")
        if off_hours(t, prof):
            reasons.append(f"Login at {t:%H:%M} is outside this user's learned working range {_hhmm(prof['hour_lo'])}-{_hhmm(prof['hour_hi'])}.")
        if not geo_known(e["geo"], prof):
            reasons.append(f"Country {e['geo']} is not in the user's baseline countries ({', '.join(sorted(prof['geos'])) or 'none'}).")
        if reasons:
            if discount:
                reasons.append(f"Session came through the corporate VPN, so its weight is multiplied by {p.vpn_discount:g}.")
            out.append((3, [e["event_id"]], {"reasons": reasons}, discount))
    elif et in ("admin_action", "priv_change"):
        routine = prof["admin_count"] > 0
        if prof["cold"]:
            hit = et == "priv_change"
        else:
            hit = (not routine) or (et == "priv_change" and prof["priv_count"] == 0)
        if hit:
            why = ("this user has no routine administrative activity in the baseline" if not routine
                   else "this user never changed privileges during the baseline")
            out.append((4, [e["event_id"]], {"reasons": [f"{et.replace('_', ' ').capitalize()} on '{e['resource']}': {why}."]}, False))
    elif et == "file_read":
        thr = max(p.bulk_min_files, p.bulk_baseline_factor * prof["file_burst_max"])
        if len(files) >= thr:
            out.append((5, [i for _, i in files], {"count": len(files), "threshold": thr, "reasons": [
                f"{len(files)} file reads within {p.burst_window_min} min versus a personal baseline peak of {prof['file_burst_max']} "
                f"(effective threshold {thr:.0f} = max({p.bulk_min_files}, {p.bulk_baseline_factor:g} x baseline peak))."]}, False))
    elif et == "outbound_transfer":
        new_dest = e["resource"] not in (prof["dests"] | org["dests"])
        lim = max(p.bytes_min_mb * 1e6, p.bytes_baseline_factor * prof["bytes_max"])
        big = e["bytes"] > lim
        if new_dest or big:
            reasons = []
            if new_dest:
                reasons.append(f"Destination '{e['resource']}' was never seen anywhere in the organisation's baseline traffic.")
            if big:
                reasons.append(f"Transfer of {e['bytes'] / 1e6:,.1f} MB exceeds the size limit {lim / 1e6:,.1f} MB (max of {p.bytes_min_mb:g} MB and {p.bytes_baseline_factor:g} x the user's largest baseline transfer).")
            out.append((6, [e["event_id"]], {"bytes": e["bytes"], "dest": e["resource"], "reasons": reasons}, False))
    return out


def _weights(p):
    return {1: p.w1, 2: p.w2, 3: p.w3, 4: p.w4, 5: p.w5, 6: p.w6}


def score_state(st, p):
    w = _weights(p)
    stages = sorted(st["stages"].values(), key=lambda s: (s["time"], s["sid"]))
    pts = {s["sid"]: round(w[s["sid"]] * (p.vpn_discount if s["discounted"] else 1.0), 2) for s in stages}
    transitions = sum(1 for a, b in zip(stages, stages[1:]) if b["sid"] > a["sid"])
    order = min(transitions, 5) * p.order_bonus
    span = (stages[-1]["time"] - stages[0]["time"]).total_seconds() / 60 if stages else 0
    velocity = p.velocity_bonus if len(stages) >= 3 and span <= p.velocity_window_min else 0.0
    raw = sum(pts.values()) + order + velocity
    return {"stage_points": pts, "transitions": transitions, "order_bonus": order, "velocity_bonus": velocity,
            "span_min": round(span, 1), "raw": round(raw, 1), "total": round(min(100.0, raw), 1)}


def _group_timeline(evs, stage_of):
    rows = []
    for e in evs:
        key = (e["event_type"], e["src_ip"], e["device"])
        if rows and rows[-1]["key"] == key and (e["timestamp"] - rows[-1]["end"]).total_seconds() <= 180:
            r = rows[-1]
            r["end"], r["count"], r["bytes"] = e["timestamp"], r["count"] + 1, r["bytes"] + e["bytes"]
            r["stages"] |= stage_of.get(e["event_id"], set())
            if len(r["ids"]) < 6:
                r["ids"].append(e["event_id"])
        else:
            rows.append({"key": key, "start": e["timestamp"], "end": e["timestamp"], "count": 1, "bytes": e["bytes"],
                         "type": e["event_type"], "ip": e["src_ip"], "device": e["device"], "geo": e["geo"],
                         "resource": e["resource"], "stages": set(stage_of.get(e["event_id"], set())), "ids": [e["event_id"]]})
    out = []
    for r in rows:
        dur = (r["end"] - r["start"]).total_seconds()
        d = f" in {int(dur // 60)}m{int(dur % 60):02d}s" if r["count"] > 1 else ""
        t, n = r["type"], r["count"]
        if t == "login_failure":
            s = f"{n} failed login{'s' if n > 1 else ''} from {r['ip']} ({r['device']}, {r['geo']}){d}"
        elif t == "login_success":
            s = f"Successful login from {r['ip']} on device {r['device']} ({r['geo']})"
        elif t == "file_read":
            s = f"{n} file read{'s' if n > 1 else ''}{d}, e.g. {r['resource']}"
        elif t == "admin_action":
            s = f"{n} admin action{'s' if n > 1 else ''}: {r['resource']}"
        elif t == "priv_change":
            s = f"Privilege change: {r['resource']}"
        else:
            s = f"Outbound transfer of {r['bytes'] / 1e6:,.1f} MB to {r['resource']}"
        out.append({"start": r["start"], "end": r["end"], "type": t, "count": n, "summary": s,
                    "stages": sorted(r["stages"]), "event_ids": r["ids"]})
    return out


def _counter_evidence(st, prof, p, ev_by_id):
    notes = []
    logins = [ev_by_id[i] for s in (2, 3) if s in st["stages"] for i in st["stages"][s]["evidence"] if ev_by_id[i]["event_type"] == "login_success"]
    if logins:
        e = logins[0]
        if device_known(e["device"], prof) and prof["devices"]:
            notes.append(f"The login device '{e['device']}' is a known baseline device - weak evidence of legitimacy (typical for insider activity).")
        if ip_known(e["src_ip"], prof) and prof["ips"]:
            notes.append(f"The source IP {e['src_ip']} is known from the baseline.")
        if geo_known(e["geo"], prof) and prof["geos"]:
            notes.append(f"The country {e['geo']} matches the user's baseline.")
        if e["via_vpn"]:
            notes.append("The session came through the corporate VPN gateway (benign signal; discount applied to context stages).")
    if 1 not in st["stages"] and 2 in st["stages"]:
        notes.append("No failed-login burst preceded the login, so a credential-guessing explanation is not supported - consistent with a replayed session or stolen credentials.")
    if prof["admin_count"] > 0 and 4 not in st["stages"]:
        notes.append("This account performs routine administrative actions, so admin activity is not treated as privilege abuse.")
    if prof["cold"]:
        notes.append("The user has very little baseline history (cold start); novelty checks are less reliable.")
    return notes


def _actions(st):
    seen, out = set(), []
    order = {"Containment": 0, "Investigation": 1, "Hardening": 2}
    for sid in sorted(st["stages"], reverse=True):
        for cat, text in STAGES[sid]["actions"]:
            if text not in seen:
                seen.add(text)
                out.append({"category": cat, "action": text, "because": f"{STAGES[sid]['id']} {STAGES[sid]['name']}"})
    out.sort(key=lambda a: order[a["category"]])
    return out


def _severity(score):
    return "critical" if score >= 80 else "high" if score >= 65 else "medium" if score >= 50 else "low"


def _build(st, user, prof, p, ev_by_id, inc_id):
    final = score_state(st, p)
    w = _weights(p)
    stages = sorted(st["stages"].values(), key=lambda s: (s["time"], s["sid"]))
    stage_of = defaultdict(set)
    ev_ids = []
    for s in stages:
        for i in s["evidence"]:
            stage_of[i].add(s["sid"])
            ev_ids.append(i)
    ev_ids = sorted(set(ev_ids), key=lambda i: (ev_by_id[i]["timestamp"], i))
    timeline = _group_timeline([ev_by_id[i] for i in ev_ids], stage_of)
    sids = set(st["stages"])
    login = next((ev_by_id[i] for i in ev_ids if ev_by_id[i]["event_type"] == "login_success"), None)
    assessment = classify_chain(sids, False, bool(login and device_known(login["device"], prof) and prof["devices"]))
    at = st["incident"]["alert_time"]
    first = stages[0]["time"]
    breakdown = [{"term": f"{STAGES[s['sid']]['id']} {STAGES[s['sid']]['name']}", "points": final["stage_points"][s["sid"]],
                  "formula": f"weight {w[s['sid']]:g}" + (f" x VPN discount {p.vpn_discount:g}" if s["discounted"] else ""),
                  "kind": "stage"} for s in stages]
    breakdown.append({"term": "Order bonus", "points": final["order_bonus"], "kind": "bonus",
                      "formula": f"{final['transitions']} in-order stage transition(s) x {p.order_bonus:g} (max 5 counted)"})
    breakdown.append({"term": "Velocity bonus", "points": final["velocity_bonus"], "kind": "bonus",
                      "formula": f"{len(stages)} stages spanning {final['span_min']:g} min (needs >= 3 stages within {p.velocity_window_min} min)"})
    return {
        "incident_id": inc_id, "alert_id": inc_id, "detector": "C", "user": user, "time": at, "first_event_time": first,
        "last_stage_time": stages[-1]["time"], "score": final["total"], "score_at_alert": st["incident"]["score_at_alert"],
        "raw_score": final["raw"], "severity": _severity(final["total"]), "assessment": assessment,
        "n_stages": len(stages), "stage_ids": sorted(sids),
        "stages": [{"sid": s["sid"], "id": STAGES[s["sid"]]["id"], "name": STAGES[s["sid"]]["name"], "time": s["time"],
                    "points": final["stage_points"][s["sid"]], "discounted": s["discounted"],
                    "signal": STAGES[s["sid"]]["signal"], "why": STAGES[s["sid"]]["why"], "logic": STAGES[s["sid"]]["logic"],
                    "reasons": s["detail"].get("reasons", []), "evidence_count": len(s["evidence"]), "evidence_all": s["evidence"],
                    "evidence_sample": s["evidence"][:8],
                    "mitre": [{"id": a, "name": b} for a, b in STAGES[s["sid"]]["mitre"]]} for s in stages],
        "score_breakdown": breakdown, "timeline": timeline,
        "counter_evidence": _counter_evidence(st, prof, p, ev_by_id), "actions": _actions(st),
        "mitre": sorted({(a, b) for s in stages for a, b in STAGES[s["sid"]]["mitre"]}),
        "evidence_ids": ev_ids, "evidence_count": len(ev_ids),
        "time_to_alert_min": round((at - first).total_seconds() / 60, 1),
        "narrative": (f"Account '{user}' progressed through {len(stages)} correlated stage(s) "
                      f"({' -> '.join(STAGES[s['sid']]['id'] for s in stages)}) between {first:%Y-%m-%d %H:%M} and "
                      f"{stages[-1]['time']:%H:%M}. The score reached {st['incident']['score_at_alert']:g}/100 at "
                      f"{at:%H:%M:%S}, {round((at - first).total_seconds() / 60, 1):g} min after the first correlated signal, crossing the "
                      f"alert threshold of {p.alert_threshold:g}. Assessment: {assessment.lower()}."),
    }


def run_correlator(events, profiles, org, eval_start, p, ev_by_id):
    by_user = defaultdict(list)
    for e in events:
        by_user[e["user"]].append(e)
    chain_win = timedelta(minutes=p.chain_window_min)
    incidents, suppressed, raw_states = [], [], []

    def close(st, user):
        if st["stages"] and st["incident"] is None and len(st["stages"]) >= 2:
            sc = score_state(st, p)
            suppressed.append((user, st, sc))

    for user, evs in by_user.items():
        prof = profiles.get(user) or empty_profile()
        st = _new_state()
        f1, f2, files = deque(), deque(), deque()
        for e in evs:
            t, et = e["timestamp"], e["event_type"]
            _expire(f1, t, p.s1_window_min)
            _expire(f2, t, p.s2_window_min)
            _expire(files, t, p.burst_window_min)
            if et == "login_failure":
                f1.append((t, e["event_id"], e["src_ip"]))
                f2.append((t, e["event_id"], e["src_ip"]))
            elif et == "file_read":
                files.append((t, e["event_id"]))
            if st["stages"] and t - st["last_t"] > chain_win:
                close(st, user)
                st = _new_state()
            if t < eval_start:
                continue
            added = False
            for sid, ids, detail, disc in _triggers(e, prof, org, f1, f2, files, st, p):
                st["last_t"] = t
                if sid in st["stages"]:
                    s = st["stages"][sid]
                    s["evidence"] = list(dict.fromkeys(s["evidence"] + ids))
                    s["detail"].update({k: v for k, v in detail.items() if k != "reasons"})
                    continue
                st["stages"][sid] = {"sid": sid, "time": t, "evidence": list(dict.fromkeys(ids)), "detail": detail, "discounted": disc}
                if st["first_t"] is None:
                    st["first_t"] = t
                added = True
            if added and st["incident"] is None:
                sc = score_state(st, p)
                if sc["total"] >= p.alert_threshold and len(st["stages"]) >= p.min_stages:
                    st["incident"] = {"alert_time": t, "score_at_alert": sc["total"], "user": user}
                    raw_states.append((user, st, prof))
        close(st, user)
    raw_states.sort(key=lambda x: x[1]["incident"]["alert_time"])
    for i, (user, st, prof) in enumerate(raw_states, 1):
        incidents.append(_build(st, user, prof, p, ev_by_id, f"C-{i:04d}"))
    sup = []
    for user, st, sc in suppressed:
        stages = sorted(st["stages"].values(), key=lambda s: (s["time"], s["sid"]))
        reasons = []
        if sc["total"] < p.alert_threshold:
            reasons.append(f"score {sc['total']:g} is below the alert threshold {p.alert_threshold:g}")
        if len(stages) < p.min_stages:
            reasons.append(f"only {len(stages)} distinct stage(s) observed, {p.min_stages} required")
        disc = [STAGES[s['sid']]['id'] for s in stages if s["discounted"]]
        if disc:
            reasons.append(f"{', '.join(disc)} discounted because the session came through the corporate VPN")
        sup.append({"user": user, "start": stages[0]["time"], "end": stages[-1]["time"], "score": sc["total"],
                    "stages": [f"{STAGES[s['sid']]['id']} {STAGES[s['sid']]['name']}" for s in stages],
                    "stage_ids": [s["sid"] for s in stages], "reason": "; ".join(reasons) or "chain closed before reaching the threshold",
                    "evidence_ids": sorted({i for s in stages for i in s["evidence"]})})
    sup.sort(key=lambda s: -s["score"])
    return incidents, sup

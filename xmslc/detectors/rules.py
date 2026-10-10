"""Detector A - independent, single-event rule-based alerting (the conventional baseline).

Every rule looks at ONE event (or one short counter) in isolation, exactly like a
simple SIEM correlation rule.  No baselines per user, no memory of earlier alerts.
"""
from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta

from ..knowledge import RULES
from .profiles import INTERNAL_PREFIX

_RULE = {r["id"]: r for r in RULES}


def run_rules(events, profiles, org, eval_start, p):
    alerts = []
    fails = defaultdict(deque)
    files = defaultdict(deque)
    last_fire = {}
    admin_users = {u for u, pr in profiles.items() if pr["admin_count"] > 0}
    allowed = set(org["dests"])
    fw = timedelta(minutes=p.rule_fail_window_min)
    bw = timedelta(minutes=p.rule_bulk_window_min)
    cool = timedelta(minutes=10)

    def fire(rid, e, reason, evidence):
        key = (rid, e["user"])
        r = _RULE[rid]
        alerts.append({
            "alert_id": "", "detector": "A", "rule": rid, "rule_name": r["name"], "user": e["user"],
            "time": e["timestamp"], "severity": r["severity"], "reason": reason,
            "evidence_ids": list(evidence), "logic": r["logic"],
        })
        last_fire[key] = e["timestamp"]

    def cooled(rid, e):
        t = last_fire.get((rid, e["user"]))
        return t is None or e["timestamp"] - t > cool

    for e in events:
        t, u, et = e["timestamp"], e["user"], e["event_type"]
        if et == "login_failure":
            q = fails[u]
            q.append((t, e["event_id"]))
            while q and t - q[0][0] > fw:
                q.popleft()
        elif et == "file_read":
            q = files[u]
            q.append((t, e["event_id"]))
            while q and t - q[0][0] > bw:
                q.popleft()
        if t < eval_start:
            continue
        if et == "login_failure":
            q = fails[u]
            if len(q) >= p.rule_fail_threshold and cooled("R1", e):
                fire("R1", e, f"{len(q)} failed logins within {p.rule_fail_window_min} min (threshold {p.rule_fail_threshold}).",
                     [i for _, i in q][-1:])
        elif et == "login_success":
            h = t.hour + t.minute / 60
            if h < p.business_start or h >= p.business_end:
                fire("R2", e, f"Login at {t:%H:%M} is outside business hours {p.business_start:02d}:00-{p.business_end:02d}:00.", [e["event_id"]])
            if e["src_ip"] and not e["src_ip"].startswith(INTERNAL_PREFIX) and not e["via_vpn"]:
                fire("R3", e, f"Login from non-corporate IP {e['src_ip']} without VPN.", [e["event_id"]])
            if e["geo"] and e["geo"] != "AE":
                fire("R4", e, f"Login from country {e['geo']} (home country is AE).", [e["event_id"]])
        elif et in ("admin_action", "priv_change"):
            if u not in admin_users:
                fire("R5", e, f"{et.replace('_', ' ')} on '{e['resource']}' by a user with no administrative role in the baseline.", [e["event_id"]])
        elif et == "file_read":
            q = files[u]
            if len(q) >= p.rule_bulk_files and cooled("R6", e):
                fire("R6", e, f"{len(q)} file reads within {p.rule_bulk_window_min} min (threshold {p.rule_bulk_files}).", [i for _, i in q][-1:])
        elif et == "outbound_transfer":
            mb = e["bytes"] / 1e6
            if mb >= p.rule_bytes_mb:
                fire("R7", e, f"Outbound transfer of {mb:,.1f} MB to {e['resource']} (limit {p.rule_bytes_mb:g} MB).", [e["event_id"]])
            elif e["resource"] not in allowed:
                fire("R7", e, f"Outbound transfer to {e['resource']}, which is not on the approved-destination list.", [e["event_id"]])
    for i, a in enumerate(alerts, 1):
        a["alert_id"] = f"A-{i:04d}"
    return alerts

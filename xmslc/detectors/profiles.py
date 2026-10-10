"""Baseline behavioural profiles.

Everything the detectors know about "normal" is learned here from the baseline period
(events before ``eval_start``).  No ground-truth labels are ever used.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

INTERNAL_PREFIX = "10.20."
MIN_EVENTS_FOR_PROFILE = 8


def max_burst(times, window_s: float) -> int:
    """Largest number of timestamps falling inside any window of ``window_s`` seconds."""
    best, j = 0, 0
    for i, t in enumerate(times):
        while (t - times[j]).total_seconds() > window_s:
            j += 1
        best = max(best, i - j + 1)
    return best


def _pct(vals, q):
    s = sorted(vals)
    if not s:
        return None
    k = (len(s) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def build_profiles(events: list[dict], eval_start, burst_window_min: int = 10):
    by_user = defaultdict(list)
    for e in events:
        if e["timestamp"] < eval_start:
            by_user[e["user"]].append(e)
    org_dests, org_geos = set(), set()
    profiles = {}
    for user, evs in by_user.items():
        logins = [e for e in evs if e["event_type"] == "login_success"]
        # working hours come from ALL activity (a login happens once a day, work happens all day)
        hours = [e["timestamp"].hour + e["timestamp"].minute / 60 for e in evs if e["event_type"] != "login_failure"]
        files = [e["timestamp"] for e in evs if e["event_type"] == "file_read"]
        outs = [e for e in evs if e["event_type"] == "outbound_transfer"]
        p = {
            "n_events": len(evs), "cold": len(evs) < MIN_EVENTS_FOR_PROFILE,
            "ips": {e["src_ip"] for e in logins if e["src_ip"]} | {e["src_ip"] for e in evs if e["src_ip"] and e["event_type"] != "login_failure"},
            "devices": {e["device"] for e in evs if e["device"] and e["event_type"] != "login_failure"},
            "geos": {e["geo"] for e in evs if e["geo"] and e["event_type"] != "login_failure"},
            "dests": {e["resource"] for e in outs if e["resource"]},
            "hour_lo": (_pct(hours, 0.01) - 1.0) if hours else 6.0,
            "hour_hi": (_pct(hours, 0.99) + 1.0) if hours else 20.0,
            "admin_count": sum(e["event_type"] == "admin_action" for e in evs),
            "priv_count": sum(e["event_type"] == "priv_change" for e in evs),
            "file_burst_max": max_burst(files, burst_window_min * 60),
            "bytes_max": max([e["bytes"] for e in outs] or [0]),
            "n_logins": len(logins),
        }
        profiles[user] = p
        org_dests |= p["dests"]
        org_geos |= p["geos"]
    org = {"dests": org_dests, "geos": org_geos}
    return profiles, org


def empty_profile():
    return {"n_events": 0, "cold": True, "ips": set(), "devices": set(), "geos": set(), "dests": set(),
            "hour_lo": 6.0, "hour_hi": 20.0, "admin_count": 0, "priv_count": 0, "file_burst_max": 0,
            "bytes_max": 0, "n_logins": 0}


def ip_known(ip: str, prof: dict) -> bool:
    if not ip or ip in prof["ips"]:
        return True
    return bool(prof["cold"] and ip.startswith(INTERNAL_PREFIX))


def device_known(dev: str, prof: dict) -> bool:
    return (not dev) or (not prof["devices"]) or dev in prof["devices"]


def geo_known(geo: str, prof: dict) -> bool:
    return (not geo) or (not prof["geos"]) or geo in prof["geos"]


def off_hours(ts, prof: dict) -> bool:
    h = ts.hour + ts.minute / 60
    return h < prof["hour_lo"] or h > prof["hour_hi"]

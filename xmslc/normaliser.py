"""Log normalisation layer.

Four heterogeneous log sources (authentication, file server, privilege management,
network gateway) and arbitrary user-supplied CSV/JSON are converted into ONE common
event schema.  A data-quality report records what was parsed, repaired or rejected.
"""
from __future__ import annotations

import csv
import io
import json
import re
from collections import Counter
from datetime import datetime, timezone

EVENT_TYPES = ["login_success", "login_failure", "file_read", "admin_action", "priv_change", "outbound_transfer"]
SOURCE_OF = {"login_success": "auth", "login_failure": "auth", "file_read": "file",
             "admin_action": "priv", "priv_change": "priv", "outbound_transfer": "net"}

COMMON_SCHEMA = [
    ("event_id", "Unique record identifier (preserved from the source when present)."),
    ("timestamp", "UTC time of the event, second resolution."),
    ("user", "Account that performed the action."),
    ("event_type", "One of: " + ", ".join(EVENT_TYPES) + "."),
    ("src_ip", "Source IP address of the client."),
    ("device", "Host / device identifier."),
    ("geo", "Two-letter country code of the source IP."),
    ("resource", "File path, admin page or destination host."),
    ("bytes", "Bytes read or sent (0 when not applicable)."),
    ("via_vpn", "True when the session came through the corporate VPN gateway."),
    ("session_id", "Identifier tying events of one session together."),
    ("source", "Originating log source: auth, file, priv or net."),
]

SOURCE_FIELD_MAP = {
    "auth": {"timestamp": "ts", "user": "account", "event_type": "outcome (SUCCESS/FAILURE)", "src_ip": "client_ip",
             "device": "host", "geo": "country", "via_vpn": "via_vpn", "session_id": "session"},
    "file": {"timestamp": "time", "user": "uid", "event_type": "action (READ)", "src_ip": "client",
             "device": "workstation", "geo": "geo", "resource": "path", "bytes": "size_bytes", "via_vpn": "vpn",
             "session_id": "sess"},
    "priv": {"timestamp": "@timestamp", "user": "actor", "event_type": "operation", "src_ip": "src",
             "device": "machine", "geo": "cc", "resource": "target", "via_vpn": "vpn_flag", "session_id": "sid"},
    "net": {"timestamp": "event_time (epoch)", "user": "username", "event_type": "(implicit: outbound_transfer)",
            "src_ip": "src_addr", "device": "device_name", "geo": "geoip", "resource": "dst_host",
            "bytes": "bytes_out", "via_vpn": "tunnel", "session_id": "session_ref"},
}

_TYPE_ALIASES = {
    "login_success": ["login_success", "logon_success", "auth_success", "login_ok", "success", "signin_success"],
    "login_failure": ["login_failure", "login_fail", "failed_login", "logon_failure", "auth_failure", "login_failed", "failure", "failed", "signin_failure"],
    "file_read": ["file_read", "file_access", "file_open", "read", "download", "file_download"],
    "admin_action": ["admin_action", "admin", "admin_access", "admin_page", "administrative_action"],
    "priv_change": ["priv_change", "privilege_change", "privilege_escalation", "role_change", "group_add", "permission_change"],
    "outbound_transfer": ["outbound_transfer", "outbound", "upload", "egress", "transfer", "data_transfer", "network_out"],
}
ALIAS = {a: t for t, al in _TYPE_ALIASES.items() for a in al}

_TRUE = {"1", "true", "t", "yes", "y", "vpn", "on"}
_TS_FORMATS = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S",
               "%Y-%m-%d %H:%M"]


class RejectedRecord(ValueError):
    pass


def parse_ts(v) -> datetime:
    if isinstance(v, datetime):
        dt = v
    elif isinstance(v, (int, float)) or (isinstance(v, str) and re.fullmatch(r"\s*\d+(\.\d+)?\s*", v)):
        x = float(v)
        if x > 1e11:
            x /= 1000.0
        return datetime.fromtimestamp(x, tz=timezone.utc).replace(tzinfo=None, microsecond=0)
    elif isinstance(v, str) and v.strip():
        s = v.strip()
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            for f in _TS_FORMATS:
                try:
                    dt = datetime.strptime(s, f)
                    break
                except ValueError:
                    continue
            else:
                raise RejectedRecord("unparseable timestamp")
    else:
        raise RejectedRecord("missing timestamp")
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.replace(microsecond=0)


def _bool(v) -> bool:
    return str(v).strip().lower() in _TRUE


def _num(v) -> int:
    try:
        return max(0, int(float(v)))
    except (TypeError, ValueError):
        return 0


def _s(v) -> str:
    return "" if v is None else str(v).strip()


def _detect_source(r: dict) -> str:
    if "outcome" in r and "account" in r:
        return "auth"
    if "path" in r and "uid" in r:
        return "file"
    if "operation" in r and "actor" in r:
        return "priv"
    if "dst_host" in r and "username" in r:
        return "net"
    if {k.lower() for k in r} & {"event_type", "timestamp", "type", "event", "user", "username", "action"}:
        return "generic"
    raise RejectedRecord("unrecognised record layout")


def _from_native(r: dict, src: str) -> dict:
    if src == "auth":
        et = "login_success" if _s(r.get("outcome")).upper().startswith("S") else "login_failure"
        return dict(timestamp=r.get("ts"), user=r.get("account"), event_type=et, src_ip=r.get("client_ip"),
                    device=r.get("host"), geo=r.get("country"), resource="", bytes=0,
                    via_vpn=_bool(r.get("via_vpn")), session_id=r.get("session"))
    if src == "file":
        return dict(timestamp=r.get("time"), user=r.get("uid"), event_type="file_read", src_ip=r.get("client"),
                    device=r.get("workstation"), geo=r.get("geo"), resource=r.get("path"),
                    bytes=_num(r.get("size_bytes")), via_vpn=_bool(r.get("vpn")), session_id=r.get("sess"))
    if src == "priv":
        et = "admin_action" if _s(r.get("operation")).upper().startswith("ADMIN") else "priv_change"
        return dict(timestamp=r.get("@timestamp"), user=r.get("actor"), event_type=et, src_ip=r.get("src"),
                    device=r.get("machine"), geo=r.get("cc"), resource=r.get("target"), bytes=0,
                    via_vpn=_bool(r.get("vpn_flag")), session_id=r.get("sid"))
    if src == "net":
        return dict(timestamp=r.get("event_time"), user=r.get("username"), event_type="outbound_transfer",
                    src_ip=r.get("src_addr"), device=r.get("device_name"), geo=r.get("geoip"),
                    resource=r.get("dst_host"), bytes=_num(r.get("bytes_out")),
                    via_vpn=_s(r.get("tunnel")).lower() == "vpn", session_id=r.get("session_ref"))
    # generic / already-normalised, tolerant of common column synonyms
    low = {k.lower().strip(): v for k, v in r.items()}
    g = lambda *ks: next((low[k] for k in ks if k in low and low[k] not in (None, "")), "")  # noqa: E731
    et_raw = _s(g("event_type", "type", "event", "action")).lower().replace(" ", "_").replace("-", "_")
    outcome = _s(g("outcome", "status", "result", "success")).lower()
    if et_raw in ("login", "logon", "authentication", "auth", "signin") and outcome:
        et_raw = "login_success" if outcome in ("success", "ok", "true", "1", "succeeded", "allowed") else "login_failure"
    et = ALIAS.get(et_raw)
    if not et:
        raise RejectedRecord(f"unknown or ambiguous event_type '{et_raw or '(empty)'}' (a bare login needs an outcome/status column)")
    return dict(timestamp=g("timestamp", "time", "ts", "datetime", "@timestamp"), user=g("user", "username", "account", "uid", "actor"),
                event_type=et, src_ip=g("src_ip", "ip", "source_ip", "client_ip"), device=g("device", "host", "hostname", "workstation"),
                geo=g("geo", "country", "country_code"), resource=g("resource", "path", "target", "destination", "dst_host"),
                bytes=_num(g("bytes", "size", "bytes_out", "size_bytes")), via_vpn=_bool(g("via_vpn", "vpn")),
                session_id=g("session_id", "session", "sid"), event_id=g("event_id", "rid", "id"))


def normalise(records: list[dict]) -> tuple[list[dict], dict]:
    events: list[dict] = []
    rejected: Counter = Counter()
    by_source: Counter = Counter()
    seen_ids: set = set()
    seen_sig: set = set()
    dups = 0
    repaired: Counter = Counter()
    for idx, r in enumerate(records, 1):
        try:
            if not isinstance(r, dict):
                raise RejectedRecord("not an object")
            src = _detect_source(r)
            n = _from_native(r, src)
            ts = parse_ts(n["timestamp"])
            user = _s(n["user"]).lower()
            if not user:
                raise RejectedRecord("missing user")
            et = n["event_type"]
            eid = r.get("rid", n.get("event_id"))
            try:
                eid = int(eid)
            except (TypeError, ValueError):
                eid = None
            if eid is not None:
                if eid in seen_ids:
                    dups += 1
                    continue
                seen_ids.add(eid)
            ev = {
                "event_id": eid, "timestamp": ts, "user": user, "event_type": et,
                "src_ip": _s(n["src_ip"]), "device": _s(n["device"]), "geo": _s(n["geo"]).upper(),
                "resource": _s(n["resource"]), "bytes": _num(n["bytes"]), "via_vpn": bool(n["via_vpn"]),
                "session_id": _s(n["session_id"]), "source": SOURCE_OF[et],
            }
            if eid is None:
                sig = (ts, user, et, ev["src_ip"], ev["resource"], ev["device"])
                if sig in seen_sig:
                    dups += 1
                    continue
                seen_sig.add(sig)
            for k in ("src_ip", "device", "geo"):
                if not ev[k]:
                    repaired[f"empty {k} left blank"] += 1
            events.append(ev)
            by_source[src if src != "generic" else ev["source"]] += 1
        except RejectedRecord as exc:
            rejected[str(exc)] += 1
        except Exception as exc:  # defensive: never let one bad row kill the run
            rejected[f"error: {type(exc).__name__}"] += 1
    # assign ids to records that had none, avoiding collisions
    nxt = max([e["event_id"] for e in events if e["event_id"] is not None] or [0]) + 1
    events.sort(key=lambda e: (e["timestamp"], e["event_id"] if e["event_id"] is not None else 10 ** 12))
    for e in events:
        if e["event_id"] is None:
            e["event_id"] = nxt
            nxt += 1
    report = {
        "records_in": len(records), "records_ok": len(events), "records_rejected": sum(rejected.values()),
        "duplicates_removed": dups, "rejected_reasons": dict(rejected), "repairs": dict(repaired),
        "by_source": dict(by_source),
        "schema": [{"field": f, "meaning": m} for f, m in COMMON_SCHEMA],
        "field_maps": SOURCE_FIELD_MAP,
    }
    return events, report


def parse_upload(text: str, fmt: str = "auto") -> list[dict]:
    """Parse a pasted/uploaded CSV, JSON array or JSON-lines document into raw records."""
    text = (text or "").strip()
    if not text:
        raise ValueError("The log input is empty.")
    if fmt == "auto":
        fmt = "json" if text[0] in "[{" else "csv"
    if fmt == "json":
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                data = data.get("events") or data.get("records") or [data]
            if not isinstance(data, list):
                raise ValueError("JSON must be an array of event objects.")
            return data
        except json.JSONDecodeError:
            rows = []
            for i, line in enumerate(text.splitlines(), 1):
                if line.strip():
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError as exc:
                        raise ValueError(f"Invalid JSON on line {i}: {exc.msg}") from exc
            return rows
    sample = text[:2048]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    return list(csv.DictReader(io.StringIO(text), dialect=dialect))

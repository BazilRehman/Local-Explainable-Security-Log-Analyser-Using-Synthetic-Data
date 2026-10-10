"""Flask application: REST API + offline single-page UI."""
from __future__ import annotations

import csv
import io
import json
import threading
import uuid
from collections import OrderedDict
from datetime import date, datetime

from flask import Flask, Response, jsonify, request, send_from_directory

from . import experiments
from .config import param_specs
from .generator import to_raw
from .knowledge import STAGES, docs_payload
from .normaliser import parse_upload
from .pipeline import run_custom, run_synthetic

MAX_RUNS = 12
RUNS: "OrderedDict[str, dict]" = OrderedDict()
LOCK = threading.Lock()


def _default(o):
    if isinstance(o, (datetime, date)):
        return o.isoformat(sep=" ") if isinstance(o, datetime) else o.isoformat()
    if isinstance(o, (set, frozenset)):
        return sorted(o)
    if isinstance(o, tuple):
        return list(o)
    try:
        import numpy as np
        if isinstance(o, np.generic):
            return o.item()
    except ImportError:
        pass
    raise TypeError(f"not serialisable: {type(o)}")


def create_app() -> Flask:
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    app.json.default = _default
    app.json.sort_keys = False

    def store(summary, data):
        rid = uuid.uuid4().hex[:10]
        summary["run_id"] = rid
        with LOCK:
            RUNS[rid] = {"summary": summary, "data": data}
            while len(RUNS) > MAX_RUNS:
                RUNS.popitem(last=False)
        return rid

    def get_run(rid):
        with LOCK:
            r = RUNS.get(rid)
        if r is None:
            raise KeyError("run not found (it may have expired); please run the analysis again")
        return r

    @app.errorhandler(Exception)
    def on_error(exc):
        code = 404 if isinstance(exc, KeyError) else 400 if isinstance(exc, ValueError) else 500
        if code == 500:
            app.logger.exception(exc)
        return jsonify({"error": str(exc.args[0] if isinstance(exc, KeyError) else exc)}), code

    @app.get("/")
    def index():
        return send_from_directory(app.static_folder, "index.html")

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "runs_in_memory": len(RUNS)})

    @app.get("/api/schema")
    def schema():
        return jsonify({"params": param_specs(), "docs": docs_payload(),
                        "stage_names": {str(k): v["name"] for k, v in STAGES.items()}})

    @app.post("/api/run")
    def api_run():
        body = request.get_json(silent=True) or {}
        summary, data = run_synthetic(body.get("config") or {})
        store(summary, data)
        return jsonify(summary)

    @app.post("/api/custom")
    def api_custom():
        body = request.get_json(silent=True) or {}
        records = parse_upload(body.get("data", ""), body.get("format", "auto"))
        summary, data = run_custom(records, body.get("config") or {}, float(body.get("baseline_fraction", 0.4)))
        store(summary, data)
        return jsonify(summary)

    @app.post("/api/experiment")
    def api_experiment():
        body = request.get_json(silent=True) or {}
        return jsonify(experiments.run_experiment(body.get("config") or {}, body.get("runs", 10)))

    @app.post("/api/robustness")
    def api_robustness():
        body = request.get_json(silent=True) or {}
        return jsonify(experiments.run_robustness(body.get("config") or {}, body.get("variable", "drop_rate"), body.get("runs", 3)))

    # ------------------------------------------------------------------ logs
    def _rows(run, args):
        d = run["data"]
        events = d["events"]
        user, etype = (args.get("user") or "").lower().strip(), args.get("type") or ""
        q, flag, period = (args.get("q") or "").lower().strip(), args.get("flag") or "all", args.get("period") or "all"
        eval_start = datetime.fromisoformat(run["summary"]["dataset"]["eval_start"]) if isinstance(run["summary"]["dataset"]["eval_start"], str) else run["summary"]["dataset"]["eval_start"]
        out = []
        for e in events:
            if user and user not in e["user"]:
                continue
            if etype and e["event_type"] != etype:
                continue
            fl = d["flags"].get(e["event_id"], set())
            gt = d["gt_map"].get(e["event_id"])
            if flag == "attack" and not (gt and gt["label"] == "attack"):
                continue
            if flag == "control" and not (gt and gt["label"] != "attack"):
                continue
            if flag in ("A", "B", "C") and flag not in fl:
                continue
            if flag == "any" and not fl:
                continue
            if flag == "none" and fl:
                continue
            if period == "baseline" and e["timestamp"] >= eval_start:
                continue
            if period == "eval" and e["timestamp"] < eval_start:
                continue
            if q and q not in " ".join(str(v).lower() for v in e.values()):
                continue
            out.append(e)
        return out

    def _row(e, d, view):
        r = {"event_id": e["event_id"], "flagged_by": sorted(d["flags"].get(e["event_id"], [])),
             "ground_truth": d["gt_map"].get(e["event_id"])}
        if view == "raw":
            raw = d["rawmap"].get(e["event_id"])
            r["raw"] = json.dumps(raw, default=_default) if raw is not None else ""
            r["timestamp"], r["user"], r["event_type"] = e["timestamp"], e["user"], e["event_type"]
            r["source"] = e["source"]
        else:
            r.update(e)
        return r

    def _ensure_rawmap(d):
        if "rawmap" not in d:
            m = {}
            for i, r in enumerate(d["raw"]):
                m[r.get("rid", i + 1) if isinstance(r, dict) else i + 1] = r
            d["rawmap"] = m
        return d

    @app.get("/api/run/<rid>/logs")
    def logs(rid):
        run = get_run(rid)
        d = _ensure_rawmap(run["data"])
        rows = _rows(run, request.args)
        page, size = max(1, int(request.args.get("page", 1))), min(200, max(10, int(request.args.get("page_size", 50))))
        view = request.args.get("view", "normalised")
        total = len(rows)
        sl = rows[(page - 1) * size: page * size]
        return jsonify({"total": total, "page": page, "page_size": size, "pages": max(1, -(-total // size)),
                        "rows": [_row(e, d, view) for e in sl]})

    @app.get("/api/run/<rid>/event/<int:eid>")
    def event_detail(rid, eid):
        run = get_run(rid)
        d = _ensure_rawmap(run["data"])
        e = d["ev_by_id"].get(eid)
        if not e:
            raise KeyError("event not found")
        why = {"A": [{"alert_id": a["alert_id"], "rule": f"{a['rule']} {a['rule_name']}", "reason": a["reason"]}
                     for a in d["alerts_a"] if eid in a["evidence_ids"]][:10],
               "B": [{"alert_id": a["alert_id"], "score": a["score"], "top_features": a["top_features"]}
                     for a in d["alerts_b"] if eid in a["evidence_ids"]][:5],
               "C": [{"incident_id": i["incident_id"], "score": i["score"],
                      "stages": [{"id": s["id"], "name": s["name"], "reasons": s["reasons"]} for s in i["stages"]
                                 if eid in set(s["evidence_all"])]}
                     for i in d["inc_c"] if eid in i["evidence_ids"]][:5]}
        return jsonify({"event": e, "ground_truth": d["gt_map"].get(eid), "raw": d["rawmap"].get(eid), "detections": why})

    @app.get("/api/run/<rid>/export")
    def export(rid):
        run = get_run(rid)
        d = _ensure_rawmap(run["data"])
        fmt = request.args.get("fmt", "csv")
        if fmt == "report":
            return Response(json.dumps(run["summary"], default=_default, indent=2), mimetype="application/json",
                            headers={"Content-Disposition": f"attachment; filename=report_{rid}.json"})
        if fmt == "raw":
            body = "\n".join(json.dumps(r, default=_default) for r in d["raw"])
            return Response(body, mimetype="application/x-ndjson", headers={"Content-Disposition": f"attachment; filename=raw_logs_{rid}.jsonl"})
        rows = _rows(run, request.args)
        buf = io.StringIO()
        cols = ["event_id", "timestamp", "user", "event_type", "src_ip", "device", "geo", "resource", "bytes", "via_vpn",
                "session_id", "source", "ground_truth_chain", "ground_truth_scenario", "flagged_by"]
        w = csv.writer(buf)
        w.writerow(cols)
        for e in rows:
            gt = d["gt_map"].get(e["event_id"]) or {}
            w.writerow([e["event_id"], e["timestamp"].isoformat(sep=" "), e["user"], e["event_type"], e["src_ip"], e["device"],
                        e["geo"], e["resource"], e["bytes"], int(e["via_vpn"]), e["session_id"], e["source"],
                        gt.get("chain_id", ""), gt.get("scenario", ""), "".join(sorted(d["flags"].get(e["event_id"], [])))])
        return Response(buf.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename=logs_{rid}.csv"})

    return app

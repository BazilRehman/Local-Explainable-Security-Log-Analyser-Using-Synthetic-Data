"""Run with:  python -m unittest discover -s tests -v"""
import unittest
from datetime import datetime, timedelta

from xmslc.config import Config, build_config
from xmslc.detectors.correlator import run_correlator
from xmslc.detectors.profiles import build_profiles
from xmslc.generator import Generator, to_raw
from xmslc.normaliser import normalise, parse_upload
from xmslc.pipeline import run_custom, run_synthetic

SMALL = {"n_users": 12, "days": 5, "baseline_days": 2, "n_credential_stuffing": 2, "n_stolen_session": 2,
         "n_insider": 2, "n_slow_exfil": 1, "n_benign_travel": 2}


def ev(i, t, user, et, ip="10.20.1.1", dev="WS-1", geo="AE", res="", b=0, vpn=False):
    return {"event_id": i, "timestamp": t, "user": user, "event_type": et, "src_ip": ip, "device": dev, "geo": geo,
            "resource": res, "bytes": b, "via_vpn": vpn, "session_id": "s", "source": "auth"}


class Determinism(unittest.TestCase):
    def test_same_seed_same_result(self):
        a, _ = run_synthetic({**SMALL, "seed": 7})
        b, _ = run_synthetic({**SMALL, "seed": 7})
        self.assertEqual(a["dataset"]["events"], b["dataset"]["events"])
        self.assertEqual(a["metrics"]["C"]["alerts"], b["metrics"]["C"]["alerts"])

    def test_different_seed_differs(self):
        a, _ = run_synthetic({**SMALL, "seed": 1})
        b, _ = run_synthetic({**SMALL, "seed": 2})
        self.assertNotEqual(a["dataset"]["events"], b["dataset"]["events"])


class Normaliser(unittest.TestCase):
    def test_roundtrip_all_four_sources(self):
        cfg = build_config(SMALL)
        events, _, _ = Generator(cfg).generate()
        norm, rep = normalise([to_raw(e) for e in events])
        self.assertEqual(len(norm), len(events))
        self.assertEqual(rep["records_rejected"], 0)
        self.assertEqual({e["event_id"] for e in norm}, {e["event_id"] for e in events})
        by = {e["event_id"]: e for e in events}
        for n in norm[:300]:
            o = by[n["event_id"]]
            for k in ("user", "event_type", "src_ip", "device", "geo", "resource", "bytes", "via_vpn", "timestamp"):
                self.assertEqual(n[k], o[k], k)
        self.assertEqual(set(rep["by_source"]), {"auth", "file", "priv", "net"})

    def test_bad_records_are_reported_not_fatal(self):
        norm, rep = normalise([{"timestamp": "garbage", "user": "a", "event_type": "login_success"},
                               {"timestamp": "2026-03-01 10:00:00", "user": "", "event_type": "login_success"},
                               {"timestamp": "2026-03-01 10:00:00", "user": "a", "event_type": "teleport"},
                               {"timestamp": "2026-03-01 10:00:00", "user": "a", "event_type": "failed_login"}])
        self.assertEqual(len(norm), 1)
        self.assertEqual(norm[0]["event_type"], "login_failure")
        self.assertEqual(rep["records_rejected"], 3)

    def test_epoch_and_csv_parsing(self):
        rows = parse_upload("timestamp,user,event_type\n1772409600,bob,login\n", "csv")
        norm, rep = normalise(rows)
        self.assertEqual(rep["records_ok"], 0)  # bare 'login' without outcome is ambiguous -> rejected, not guessed
        rows = parse_upload("timestamp,user,event_type\n1772409600,bob,login_success\n", "auto")
        norm, _ = normalise(rows)
        self.assertEqual(norm[0]["timestamp"], datetime(2026, 3, 2, 0, 0, 0))

    def test_empty_input_raises(self):
        with self.assertRaises(ValueError):
            parse_upload("   ")


class Correlator(unittest.TestCase):
    def setUp(self):
        self.cfg = Config()
        self.t0 = datetime(2026, 3, 2)
        self.base = []
        i = 0
        for d in range(3):                      # three baseline days of ordinary activity for user 'amy'
            for h in (8, 9, 10, 11, 12, 13, 14, 15, 16):
                i += 1
                self.base.append(ev(i, self.t0 + timedelta(days=d, hours=h), "amy", "login_success" if h == 8 else "file_read"))
        self.eval_start = self.t0 + timedelta(days=3)

    def _run(self, events):
        events = sorted(self.base + events, key=lambda e: e["timestamp"])
        profiles, org = build_profiles(events, self.eval_start)
        return run_correlator(events, profiles, org, self.eval_start, self.cfg, {e["event_id"]: e for e in events})

    def test_attack_chain_raises_one_explained_incident(self):
        t = self.eval_start + timedelta(hours=3)
        evs, i = [], 1000
        for k in range(7):
            i += 1; evs.append(ev(i, t + timedelta(seconds=6 * k), "amy", "login_failure", "203.0.113.9", "unknown-1", "RU"))
        i += 1; evs.append(ev(i, t + timedelta(seconds=60), "amy", "login_success", "203.0.113.9", "unknown-1", "RU"))
        i += 1; evs.append(ev(i, t + timedelta(seconds=240), "amy", "admin_action", "203.0.113.9", "unknown-1", "RU", "/admin/x"))
        incs, _ = self._run(evs)
        self.assertEqual(len(incs), 1)
        inc = incs[0]
        self.assertGreaterEqual(inc["score"], self.cfg.alert_threshold)
        self.assertGreaterEqual(inc["n_stages"], 3)
        self.assertEqual(sum(b["points"] for b in inc["score_breakdown"]), inc["raw_score"])
        self.assertTrue(all(s["reasons"] for s in inc["stages"]))

    def test_benign_vpn_traveller_is_suppressed_not_alerted(self):
        t = self.eval_start + timedelta(hours=2)
        evs = [ev(2000, t, "amy", "login_success", "82.1.1.1", "LT-9", "GB", vpn=True)]
        for k in range(5):
            evs.append(ev(2001 + k, t + timedelta(minutes=2 + k), "amy", "file_read", "82.1.1.1", "LT-9", "GB", vpn=True))
        incs, sup = self._run(evs)
        self.assertEqual(incs, [])
        self.assertTrue(any(s["user"] == "amy" and "VPN" in s["reason"] for s in sup))

    def test_single_loud_signal_never_alerts(self):
        t = self.eval_start + timedelta(hours=4)
        incs, _ = self._run([ev(3000 + k, t + timedelta(seconds=k * 5), "amy", "login_failure", "1.2.3.4", "x", "RU") for k in range(30)])
        self.assertEqual(incs, [])


class Metrics(unittest.TestCase):
    def test_metric_ranges_and_consistency(self):
        s, _ = run_synthetic({**SMALL, "seed": 3})
        for k in "ABC":
            m = s["metrics"][k]
            for key in ("recall", "precision", "f1", "fpr"):
                self.assertTrue(0.0 <= m[key] <= 1.0, (k, key, m[key]))
            self.assertEqual(m["detected_chains"] + m["missed_chains"], m["attack_chains"])
            self.assertEqual(m["tp_alerts"] + m["fp_alerts"], m["alerts"])

    def test_no_attacks_gives_zero_recall_and_no_crash(self):
        s, _ = run_synthetic({**SMALL, "n_credential_stuffing": 0, "n_stolen_session": 0, "n_insider": 0, "n_slow_exfil": 0, "n_benign_travel": 0})
        self.assertEqual(s["metrics"]["C"]["attack_chains"], 0)

    def test_baseline_never_contains_attacks(self):
        cfg = build_config({**SMALL, "seed": 5})
        events, chains, _ = Generator(cfg).generate()
        eval_start = datetime(2026, 3, 2) + timedelta(days=cfg.baseline_days)
        self.assertTrue(all(c["start"] >= eval_start for c in chains))


class Custom(unittest.TestCase):
    def test_custom_pipeline(self):
        lines = ["timestamp,user,event_type,src_ip,device,geo,resource,bytes"]
        for d in range(1, 4):
            lines.append(f"2026-03-0{d} 08:30:00,bob,login_success,10.20.1.1,WS-1,AE,,0")
            for i in range(9):
                lines.append(f"2026-03-0{d} 09:{10 + i}:00,bob,file_read,10.20.1.1,WS-1,AE,/share/f{i}.xlsx,1000")
        lines.append("2026-03-05 03:00:00,bob,login_failure,1.2.3.4,x,RU,,0")
        s, _ = run_custom(parse_upload("\n".join(lines)), {}, 0.4)
        self.assertTrue(s["custom"])
        self.assertIsNone(s["metrics"])
        self.assertGreater(s["dataset"]["events"], 20)


if __name__ == "__main__":
    unittest.main()

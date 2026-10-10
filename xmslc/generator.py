"""Threat-model-driven synthetic security-log generator.

Everything is fictional: users, hosts, IP addresses (RFC 5737 documentation ranges for
attackers) and organisations.  Every attack event is recorded in a ground-truth "chain"
so detectors can later be scored against a known answer key.
"""
from __future__ import annotations

import calendar
import math
import random
from datetime import datetime, timedelta

from .config import Config

EPOCH = datetime(2026, 3, 2)          # Monday 00:00 UTC - fixed so runs are reproducible
INTERNAL_PREFIX = "10.20."

SOURCE_OF = {
    "login_success": "auth", "login_failure": "auth", "file_read": "file",
    "admin_action": "priv", "priv_change": "priv", "outbound_transfer": "net",
}

FIRST = ["amira", "omar", "sara", "yusuf", "layla", "khalid", "noor", "hassan", "mariam", "tariq", "dina",
         "faisal", "rania", "zayed", "huda", "bilal", "salma", "ibrahim", "aisha", "kareem", "lina",
         "rashid", "maya", "adel", "farah", "nabil", "jana", "samir", "hala", "waleed"]
LAST = ["alhashmi", "khan", "mansoor", "farouk", "haddad", "nasser", "rahman", "saleh", "qureshi", "darwish",
        "ansari", "bakr", "tamimi", "siddiqui", "ghanem", "zaman", "hijazi", "malik", "sabry", "yousef",
        "kazmi", "othman", "barakat", "shaikh", "habib"]
DEPTS = {"Finance": "/share/finance", "HR": "/share/hr", "Engineering": "/share/eng",
         "Sales": "/share/sales", "Legal": "/share/legal"}
SENSITIVE = ["/share/hr/payroll", "/share/finance/treasury", "/share/legal/privileged", "/share/eng/source"]
KINDS = ["report", "invoice", "contract", "budget", "minutes", "design", "forecast", "policy"]
EXTS = ["xlsx", "docx", "pdf", "pptx"]
ADMIN_PAGES = ["/admin/user-management", "/admin/group-policy", "/admin/audit-settings", "/admin/mfa-config"]
KNOWN_DESTS = ["mail.corp.local", "files.corp.local", "sharepoint.partner.com", "crm.corp.local", "git.corp.local"]
BACKUP_DEST = "backup.corp.local"
EXFIL_DESTS = ["mega-share.example", "paste-drop.example", "files-xfer.example", "203.0.113.77"]
ATTACK_GEOS = ["RU", "CN", "BR", "NG", "VN", "RO"]
TRAVEL_GEOS = ["GB", "DE", "SA", "IN", "FR", "US"]

SCENARIO_LABEL = {
    "credential_stuffing": "attack", "stolen_session": "attack",
    "insider_misuse": "attack", "slow_exfil": "attack", "benign_travel": "benign_control",
}


def poisson(rng: random.Random, lam: float) -> int:
    if lam <= 0:
        return 0
    limit, k, p = math.exp(-lam), 0, 1.0
    while True:
        k += 1
        p *= rng.random()
        if p <= limit:
            return k - 1


class Generator:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.rng = random.Random(cfg.seed)
        self.events: list[dict] = []
        self.chains: list[dict] = []
        self.users: list[dict] = []
        self._eid = 0
        self._sid = 0

    # ----------------------------------------------------------------- helpers
    def _day(self, d: int) -> datetime:
        return EPOCH + timedelta(days=d)

    def _new_session(self) -> str:
        self._sid += 1
        return f"S{self._sid:06d}"

    def _ev(self, ts, user, etype, ip, device, geo, resource="", nbytes=0, vpn=False, session="") -> int:
        self._eid += 1
        self.events.append({
            "event_id": self._eid, "timestamp": ts.replace(microsecond=0), "user": user,
            "event_type": etype, "src_ip": ip, "device": device, "geo": geo, "resource": resource,
            "bytes": int(nbytes), "via_vpn": bool(vpn), "session_id": session, "source": SOURCE_OF[etype],
        })
        return self._eid

    def _doc(self, base: str) -> str:
        r = self.rng
        return f"{base}/{r.choice(KINDS)}_{r.randint(1, 999):03d}.{r.choice(EXTS)}"

    def _ext_ip(self) -> str:
        r = self.rng
        return f"{r.choice(['203.0.113', '198.51.100', '192.0.2'])}.{r.randint(2, 250)}"

    def _isp_ip(self) -> str:
        r = self.rng
        return f"{r.choice([82, 85, 94, 176])}.{r.randint(1, 254)}.{r.randint(1, 254)}.{r.randint(1, 254)}"

    # ------------------------------------------------------------------- users
    def _make_users(self) -> None:
        r, cfg = self.rng, self.cfg
        n_admin = max(0, round(cfg.n_users * cfg.admin_fraction))
        seen: set[str] = set()
        for i in range(cfg.n_users):
            while True:
                name = f"{r.choice(FIRST)}.{r.choice(LAST)}"
                if name not in seen:
                    seen.add(name)
                    break
            is_admin = i < n_admin
            dept = "IT" if is_admin else r.choice(list(DEPTS))
            base = "/share/it" if is_admin else DEPTS[dept]
            sfx = f"{i + 1:03d}"
            self.users.append({
                "user": name, "dept": dept, "role": "admin" if is_admin else "staff",
                "home_ip": f"10.20.{r.randint(1, 200)}.{r.randint(10, 250)}",
                "devices": [f"WS-{sfx}", f"LT-{sfx}"],
                "vpn_ips": [self._isp_ip(), self._isp_ip()],
                "work_start": r.uniform(7.2, 9.3), "work_len": r.uniform(8, 9.5),
                "file_rate": r.uniform(12, 35), "out_rate": r.uniform(0.8, 3.0),
                "dests": r.sample(KNOWN_DESTS, 3), "base": base,
            })
        self.users.append({
            "user": "svc.backup", "dept": "IT", "role": "service", "home_ip": "10.20.250.5",
            "devices": ["BKP-SRV-01"], "vpn_ips": [], "work_start": 1.9, "work_len": 1,
            "file_rate": 0, "out_rate": 0, "dests": [BACKUP_DEST], "base": "/backup",
        })
        r.shuffle(self.users)

    # -------------------------------------------------------------- normal days
    def _files(self, t0, count, u, ip, dev, geo, vpn, sess, sensitive=False, max_span_s=None):
        """Emit ``count`` file reads in short bursts; returns ids."""
        r = self.rng
        ids, remaining = [], count
        while remaining > 0:
            burst = min(remaining, r.randint(1, 8))
            t = t0 + timedelta(seconds=r.uniform(0, max_span_s if max_span_s else 3600 * 7))
            for _ in range(burst):
                t += timedelta(seconds=r.uniform(1, 25))
                res = self._doc(r.choice(SENSITIVE) if sensitive else u["base"])
                ids.append(self._ev(t, u["user"], "file_read", ip, dev, geo, res, r.lognormvariate(11.7, 1.0), vpn, sess))
            remaining -= burst
        return ids

    def _normal_day(self, u: dict, day: int) -> None:
        r, n = self.rng, self.cfg.noise_level
        d0 = self._day(day)
        user = u["user"]
        if u["role"] == "service":
            self._backup_day(u, d0)
            return
        vpn_day = r.random() < 0.03 + 0.08 * n
        ip = r.choice(u["vpn_ips"]) if vpn_day else u["home_ip"]
        dev = u["devices"][1] if vpn_day else u["devices"][0]
        login_t = d0 + timedelta(hours=min(max(u["work_start"] + r.gauss(0, 0.35), 5), 21))
        sess = self._new_session()
        # password typos (benign failed logins), occasionally a lock-out-like burst
        x, nf = r.random(), 0
        if x < 0.005 + 0.015 * n:
            nf = r.randint(5, 6)
        elif x < 0.03 + 0.04 * n:
            nf = r.randint(3, 4)
        elif x < 0.08 + 0.12 * n:
            nf = r.randint(1, 2)
        t = login_t - timedelta(seconds=nf * 20)
        for _ in range(nf):
            t += timedelta(seconds=r.uniform(6, 22))
            self._ev(t, user, "login_failure", ip, dev, "AE", vpn=vpn_day, session=sess)
        self._ev(login_t, user, "login_success", ip, dev, "AE", vpn=vpn_day, session=sess)
        # routine work
        self._files(login_t, poisson(r, u["file_rate"]), u, ip, dev, "AE", vpn_day, sess,
                    max_span_s=u["work_len"] * 3600)
        for _ in range(poisson(r, u["out_rate"])):
            tt = login_t + timedelta(seconds=r.uniform(600, u["work_len"] * 3600))
            self._ev(tt, user, "outbound_transfer", ip, dev, "AE", r.choice(u["dests"]),
                     r.lognormvariate(12.4, 1.0), vpn_day, sess)
        if u["role"] == "admin":
            for _ in range(poisson(r, 3)):
                tt = login_t + timedelta(seconds=r.uniform(300, u["work_len"] * 3600))
                self._ev(tt, user, "admin_action", ip, dev, "AE", r.choice(ADMIN_PAGES), 0, vpn_day, sess)
            if r.random() < 0.15:
                tt = login_t + timedelta(seconds=r.uniform(1800, 20000))
                self._ev(tt, user, "priv_change", ip, dev, "AE", "grant:helpdesk-operators", 0, vpn_day, sess)
        # benign irregularities (the realistic noise that single-event rules choke on)
        if r.random() < 0.03 + 0.06 * n:           # late-night work over VPN on the laptop
            lt = d0 + timedelta(hours=r.uniform(21, 23.8))
            s2, vip = self._new_session(), r.choice(u["vpn_ips"])
            self._ev(lt, user, "login_success", vip, u["devices"][1], "AE", vpn=True, session=s2)
            self._files(lt, r.randint(5, 25), u, vip, u["devices"][1], "AE", True, s2, max_span_s=3000)
        if r.random() < 0.015 + 0.04 * n:          # archive operation: large but legitimate burst
            self._files(login_t + timedelta(hours=r.uniform(1, 6)), r.randint(110, 190), u, ip, dev, "AE",
                        vpn_day, sess, max_span_s=r.uniform(300, 520))
        if r.random() < 0.015 + 0.03 * n:          # new but legitimate vendor
            tt = login_t + timedelta(seconds=r.uniform(3600, 20000))
            self._ev(tt, user, "outbound_transfer", ip, dev, "AE", f"newvendor-{r.randint(1, 99)}.example.com",
                     r.uniform(1e6, 4e6), vpn_day, sess)

    def _backup_day(self, u: dict, d0: datetime) -> None:
        r = self.rng
        ip, dev, sess = u["home_ip"], u["devices"][0], self._new_session()
        t = d0 + timedelta(hours=1, minutes=58)
        self._ev(t, u["user"], "login_success", ip, dev, "AE", session=sess)
        t += timedelta(minutes=2)
        for i in range(r.randint(200, 300)):
            t += timedelta(seconds=r.uniform(1.5, 3.5))
            self._ev(t, u["user"], "file_read", ip, dev, "AE", f"/backup/vol{r.randint(1, 4)}/blk_{i:04d}",
                     r.uniform(5e5, 3e6), False, sess)
        self._ev(t + timedelta(minutes=2), u["user"], "outbound_transfer", ip, dev, "AE", BACKUP_DEST,
                 r.uniform(8e8, 1.2e9), False, sess)

    # ---------------------------------------------------------------- scenarios
    def _inject(self, scenario: str, u: dict, day: int) -> None:
        r, cfg = self.rng, self.cfg
        d0 = self._day(day)
        user = u["user"]
        spread = 1 + cfg.stealth * r.uniform(0, 4)
        skip = lambda: r.random() < cfg.stealth * 0.5          # noqa: E731 - attacker omits a step
        ids: list[int] = []
        planned: list[str] = []
        sess = self._new_session()
        offhours = lambda p: r.uniform(0, 6) if r.random() < p else r.uniform(20, 24)  # noqa: E731

        if scenario == "credential_stuffing":
            t = d0 + timedelta(hours=offhours(0.55) if r.random() < 0.7 else r.uniform(8, 18))
            ip, geo, dev = self._ext_ip(), r.choice(ATTACK_GEOS), f"unknown-{r.getrandbits(24):06x}"
            gap = spread * (1 + cfg.stealth * r.uniform(0, 6))
            for _ in range(r.randint(6, 15)):
                t += timedelta(seconds=r.uniform(2, 20) * gap)
                ids.append(self._ev(t, user, "login_failure", ip, dev, geo, session=sess))
            planned.append("S1")
            t += timedelta(seconds=r.uniform(3, 25) * gap)
            ids.append(self._ev(t, user, "login_success", ip, dev, geo, session=sess))
            planned += ["S2", "S3"]
            if r.random() < 0.8 and not skip():
                t += timedelta(seconds=r.uniform(60, 240) * spread)
                ids += self._files(t, r.randint(15, 50), u, ip, dev, geo, False, sess, True, 400 * spread)
            if r.random() < 0.35 and not skip():
                t = self.events[-1]["timestamp"] + timedelta(seconds=r.uniform(60, 240) * spread)
                ids.append(self._ev(t, user, "outbound_transfer", ip, dev, geo, r.choice(EXFIL_DESTS),
                                    r.uniform(2e7, 2e8), False, sess))
                planned.append("S6")
            desc = "Automated password guessing from an external IP, followed by a successful login on an unknown device."

        elif scenario == "stolen_session":
            t = d0 + timedelta(hours=offhours(0.5) if r.random() < 0.7 else r.uniform(8, 18))
            ip, geo, dev = self._ext_ip(), r.choice(ATTACK_GEOS), f"unknown-{r.getrandbits(24):06x}"
            ids.append(self._ev(t, user, "login_success", ip, dev, geo, vpn=False, session=sess))
            planned += ["S2", "S3"]
            t += timedelta(seconds=r.uniform(30, 180) * spread)
            if r.random() < 0.9 and not skip():
                for _ in range(r.randint(1, 3)):
                    t += timedelta(seconds=r.uniform(20, 90) * spread)
                    ids.append(self._ev(t, user, "admin_action", ip, dev, geo, r.choice(ADMIN_PAGES), 0, False, sess))
                if r.random() < 0.3:
                    t += timedelta(seconds=30)
                    ids.append(self._ev(t, user, "priv_change", ip, dev, geo, "grant:mailbox-full-access", 0, False, sess))
                planned.append("S4")
            if not skip():
                ids += self._files(t, r.randint(70, 220), u, ip, dev, geo, False, sess, True, r.uniform(180, 480) * spread)
                planned.append("S5")
            if r.random() < 0.5 and not skip():
                t = max(self.events[-1]["timestamp"], t) + timedelta(seconds=r.uniform(60, 200) * spread)
                ids.append(self._ev(t, user, "outbound_transfer", ip, dev, geo, r.choice(EXFIL_DESTS),
                                    r.uniform(2e7, 3e8), False, sess))
                planned.append("S6")
            desc = "A valid session token is replayed from a new IP and device (no failed logins), then used for privileged and bulk access."

        elif scenario == "insider_misuse":
            hour = r.uniform(8, 17) if r.random() < 0.5 else r.uniform(19, 23.5)
            t = d0 + timedelta(hours=hour)
            ip, dev = u["home_ip"], u["devices"][0]
            ids.append(self._ev(t, user, "login_success", ip, dev, "AE", session=sess))
            t += timedelta(minutes=r.uniform(1, 6) * spread)
            if r.random() < 0.8 and not skip():
                ids.append(self._ev(t, user, "priv_change", ip, dev, "AE", "grant:ReadAll-Sensitive", 0, False, sess))
                planned.append("S4")
                t += timedelta(seconds=r.uniform(30, 120))
            n_files = r.randint(150, 400)
            ids += self._files(t, n_files, u, ip, dev, "AE", False, sess, True, r.uniform(240, 540) * spread)
            planned.append("S5")
            if r.random() < 0.95 and not skip():
                t = self.events[-1]["timestamp"] + timedelta(seconds=r.uniform(60, 300) * spread)
                ids.append(self._ev(t, user, "outbound_transfer", ip, dev, "AE", r.choice(EXFIL_DESTS),
                                    r.uniform(5e7, 5e8), False, sess))
                planned.append("S6")
            desc = "A legitimate user on their own device escalates privileges, reads sensitive files in bulk and sends data to an external destination."

        elif scenario == "slow_exfil":
            # Off-model attack: a legitimate user leaks data in small batches spaced well beyond
            # every burst window, so it never forms a multi-stage chain.
            t = d0 + timedelta(hours=r.uniform(9, 15))
            ip, dev = u["home_ip"], u["devices"][0]
            ids.append(self._ev(t, user, "login_success", ip, dev, "AE", session=sess))
            dest = f"cloud-sync-{r.randint(1, 9)}.example.net"
            for _ in range(r.randint(3, 5)):
                t += timedelta(minutes=r.uniform(25, 45))
                ids += self._files(t, r.randint(20, 45), u, ip, dev, "AE", False, sess, True, 240)
                t += timedelta(minutes=r.uniform(3, 6))
                ids.append(self._ev(t, user, "outbound_transfer", ip, dev, "AE", dest, r.uniform(2.5e6, 4.5e6), False, sess))
            planned = ["S6"]
            desc = "A legitimate user leaks data in small, spaced-out batches to a new cloud destination, deliberately staying below every burst threshold (outside the correlator's stage model)."

        else:  # benign_travel - the control case that must NOT be flagged
            t = d0 + timedelta(hours=r.uniform(1.5, 5.5) if r.random() < 0.6 else r.uniform(22, 23.8))
            ip, geo = self._isp_ip(), r.choice(TRAVEL_GEOS)
            vpn, dev = r.random() < 0.7, u["devices"][1]
            if r.random() < 0.5:
                for _ in range(r.randint(1, 2)):
                    t += timedelta(seconds=r.uniform(8, 25))
                    ids.append(self._ev(t, user, "login_failure", ip, dev, geo, vpn=vpn, session=sess))
            t += timedelta(seconds=r.uniform(8, 25))
            ids.append(self._ev(t, user, "login_success", ip, dev, geo, vpn=vpn, session=sess))
            ids += self._files(t, r.randint(10, 30), u, ip, dev, geo, vpn, sess, False, 1500)
            for _ in range(r.randint(1, 2)):
                tt = t + timedelta(seconds=r.uniform(300, 1800))
                ids.append(self._ev(tt, user, "outbound_transfer", ip, dev, geo, r.choice(u["dests"]),
                                    r.lognormvariate(12.4, 0.8), vpn, sess))
            planned = []
            desc = "A business traveller logs in late from a new country (usually over VPN) and performs ordinary work."

        idset = set(ids)
        times = [e["timestamp"] for e in self.events if e["event_id"] in idset]
        self.chains.append({
            "scenario": scenario, "label": SCENARIO_LABEL[scenario], "user": user, "event_ids": ids,
            "start": min(times), "end": max(times), "planned_stages": planned, "description": desc,
        })

    # --------------------------------------------------------------------- run
    def generate(self):
        cfg, r = self.cfg, self.rng
        self._make_users()
        for u in self.users:
            for d in range(cfg.days):
                self._normal_day(u, d)
        victims = [u for u in self.users if u["role"] != "service"]
        used: set[tuple[str, int]] = set()
        plan = ([("credential_stuffing", cfg.n_credential_stuffing), ("stolen_session", cfg.n_stolen_session),
                 ("insider_misuse", cfg.n_insider), ("slow_exfil", cfg.n_slow_exfil),
                ("benign_travel", cfg.n_benign_travel)])
        for scen, count in plan:
            for _ in range(count):
                for _try in range(200):
                    u, d = r.choice(victims), r.randint(cfg.baseline_days, cfg.days - 1)
                    if (u["user"], d) not in used:
                        used.add((u["user"], d))
                        self._inject(scen, u, d)
                        break
        # renumber in chronological order so ids read naturally
        order = sorted(self.events, key=lambda e: (e["timestamp"], e["event_id"]))
        remap = {e["event_id"]: i + 1 for i, e in enumerate(order)}
        for e in order:
            e["event_id"] = remap[e["event_id"]]
        for c in self.chains:
            c["event_ids"] = sorted(remap[i] for i in c["event_ids"])
        self.chains.sort(key=lambda c: c["start"])
        for i, c in enumerate(self.chains, 1):
            c["chain_id"] = f"GT-{i:02d}"
        return order, self.chains, self.users


def _epoch(ts: datetime) -> int:
    return calendar.timegm(ts.timetuple())


def to_raw(e: dict) -> dict:
    """Render one event in the native format of its (fictional) log source."""
    iso = e["timestamp"].strftime("%Y-%m-%dT%H:%M:%SZ")
    src = e["source"]
    if src == "auth":
        return {"rid": e["event_id"], "ts": iso, "account": e["user"],
                "outcome": "SUCCESS" if e["event_type"] == "login_success" else "FAILURE",
                "client_ip": e["src_ip"], "host": e["device"], "country": e["geo"],
                "via_vpn": int(e["via_vpn"]), "session": e["session_id"]}
    if src == "file":
        return {"rid": e["event_id"], "time": iso, "uid": e["user"], "action": "READ", "path": e["resource"],
                "size_bytes": e["bytes"], "client": e["src_ip"], "workstation": e["device"], "geo": e["geo"],
                "vpn": bool(e["via_vpn"]), "sess": e["session_id"]}
    if src == "priv":
        return {"rid": e["event_id"], "@timestamp": iso, "actor": e["user"],
                "operation": "ADMIN_ACTION" if e["event_type"] == "admin_action" else "PRIV_CHANGE",
                "target": e["resource"], "src": e["src_ip"], "machine": e["device"], "cc": e["geo"],
                "vpn_flag": "Y" if e["via_vpn"] else "N", "sid": e["session_id"]}
    return {"rid": e["event_id"], "event_time": _epoch(e["timestamp"]), "username": e["user"],
            "dst_host": e["resource"], "bytes_out": e["bytes"], "src_addr": e["src_ip"],
            "device_name": e["device"], "geoip": e["geo"], "tunnel": "vpn" if e["via_vpn"] else "direct",
            "session_ref": e["session_id"]}

"""Run configuration and parameter schema.

Every tunable value of the framework lives in ``Config``.  ``PARAM_SPECS`` carries the
human-readable documentation that the web UI renders next to each input, so the form,
the validation and the methodology chapter are all generated from one source of truth.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict, fields


@dataclass
class Config:
    # --- synthetic data generator -------------------------------------------------
    seed: int = 42
    n_users: int = 30
    days: int = 7
    baseline_days: int = 3
    n_credential_stuffing: int = 4
    n_stolen_session: int = 4
    n_insider: int = 4
    n_slow_exfil: int = 3
    n_benign_travel: int = 5
    noise_level: float = 0.5
    stealth: float = 0.4
    drop_rate: float = 0.0
    admin_fraction: float = 0.1
    # --- detector A: independent rule-based alerting -------------------------------
    rule_fail_threshold: int = 5
    rule_fail_window_min: int = 10
    rule_bulk_files: int = 100
    rule_bulk_window_min: int = 10
    rule_bytes_mb: float = 5.0
    business_start: int = 7
    business_end: int = 19
    # --- detector B: Isolation Forest ---------------------------------------------
    if_window_min: int = 30
    if_contamination: float = 0.02
    if_trees: int = 100
    # --- detector C: context-aware multi-stage correlation -------------------------
    chain_window_min: int = 60
    s1_fail_threshold: int = 5
    s1_window_min: int = 10
    s2_fail_min: int = 3
    s2_window_min: int = 15
    bulk_min_files: int = 100
    bulk_baseline_factor: float = 1.5
    burst_window_min: int = 10
    bytes_min_mb: float = 5.0
    bytes_baseline_factor: float = 3.0
    w1: float = 10.0
    w2: float = 20.0
    w3: float = 15.0
    w4: float = 20.0
    w5: float = 20.0
    w6: float = 25.0
    order_bonus: float = 5.0
    velocity_bonus: float = 5.0
    velocity_window_min: int = 10
    vpn_discount: float = 0.5
    alert_threshold: float = 50.0
    min_stages: int = 3

    def to_dict(self) -> dict:
        return asdict(self)


# (key, group, label, min, max, step, help, effect)
_G = {
    "gen": "Synthetic data generator",
    "A": "Detector A - independent rules (baseline)",
    "B": "Detector B - Isolation Forest (baseline)",
    "C": "Detector C - multi-stage correlation (proposed)",
}

_SPECS = [
    ("seed", "gen", "Random seed", 0, 999999, 1,
     "Seeds the pseudo-random generator so a run is exactly reproducible.",
     "Same seed + same settings = identical logs and identical results. Change it to draw a different synthetic organisation."),
    ("n_users", "gen", "Number of users", 5, 200, 1,
     "How many employee accounts exist (plus one backup service account).",
     "More users means more background noise and a harder needle-in-a-haystack problem."),
    ("days", "gen", "Days of logs", 3, 30, 1,
     "Length of the simulated log period in days.",
     "Longer periods give the detectors more data but also more benign anomalies that can trigger false alarms."),
    ("baseline_days", "gen", "Baseline (learning) days", 1, 29, 1,
     "The first N days are assumed attack-free and are used to learn each user's normal behaviour (known IPs, devices, hours, volumes). Detection and evaluation only happen after this period.",
     "A longer baseline gives more accurate profiles; it must be smaller than the total number of days."),
    ("n_credential_stuffing", "gen", "Attack: credential stuffing", 0, 20, 1,
     "Number of injected chains: many failed logins from an external IP, then a successful login from a new device, then optional data access.",
     "Tests whether the detector links failed-then-successful authentication into one incident."),
    ("n_stolen_session", "gen", "Attack: stolen session", 0, 20, 1,
     "Number of injected chains: a valid session replayed from a new IP/device with no failed logins, followed by privileged and bulk activity.",
     "Tests detection when the attacker never triggers a failed-login rule."),
    ("n_insider", "gen", "Attack: insider misuse", 0, 20, 1,
     "Number of injected chains: a legitimate login from the user's own device followed by privilege abuse, bulk file reads and an external transfer.",
     "Tests detection when identity and device look completely normal; only behaviour is abnormal."),
    ("n_slow_exfil", "gen", "Attack: low-and-slow exfiltration (off-model)", 0, 20, 1,
     "Number of injected chains that deliberately do NOT follow the six modelled stages: a legitimate user leaks data in small, spaced-out batches to a new cloud destination, staying below every burst threshold.",
     "An honest stress test: it shows what the correlator gives up (recall on attacks outside its model) in exchange for fewer false positives."),
    ("n_benign_travel", "gen", "Control: benign travel/VPN", 0, 20, 1,
     "Number of harmless but unusual events: a business traveller logging in late from a new country over VPN.",
     "These must NOT be flagged. They measure false-positive behaviour on realistic unusual-but-legitimate activity."),
    ("noise_level", "gen", "Background noise level", 0.0, 1.0, 0.05,
     "Frequency of benign irregularities: password typos, VPN days, late work, archive operations, new vendors.",
     "Higher noise makes single-event alerting fire more often (more false positives) and stresses every detector."),
    ("stealth", "gen", "Attacker stealth", 0.0, 1.0, 0.05,
     "How careful the attacker is: slower activity, skipped steps, stretched time gaps.",
     "Higher stealth lowers recall for everybody because evidence becomes weaker and more spread out."),
    ("drop_rate", "gen", "Missing-log rate", 0.0, 0.6, 0.05,
     "Fraction of raw log records randomly dropped before analysis (simulates collection gaps).",
     "Used for the robustness experiment: how gracefully does each detector degrade with incomplete data?"),
    ("admin_fraction", "gen", "Admin account fraction", 0.0, 0.5, 0.01,
     "Share of users who perform routine administrative actions.",
     "Admin accounts make privilege-based evidence weaker, because admin activity is normal for them."),

    ("rule_fail_threshold", "A", "R1: failed logins threshold", 2, 50, 1,
     "Raise an alert when a user has at least this many failed logins inside the window.",
     "Lower = catches more guessing but also more typos."),
    ("rule_fail_window_min", "A", "R1: window (min)", 1, 120, 1,
     "Length of the failed-login counting window.", "Longer window catches slow attacks but increases false alarms."),
    ("rule_bulk_files", "A", "R6: bulk file reads", 10, 1000, 5,
     "Alert when a user reads at least this many files inside the window.",
     "Static for everyone - the nightly backup job and archive operations trigger it."),
    ("rule_bulk_window_min", "A", "R6: window (min)", 1, 120, 1,
     "Length of the bulk-read counting window.", ""),
    ("rule_bytes_mb", "A", "R7: outbound size (MB)", 0.5, 2000, 0.5,
     "Alert on any outbound transfer larger than this, or to a destination not on the approved list.",
     "Static size limit; large legitimate transfers (backups) will alert."),
    ("business_start", "A", "R2: business hours start", 0, 23, 1,
     "Logins before this hour are 'off-hours'.", ""),
    ("business_end", "A", "R2: business hours end", 1, 24, 1,
     "Logins after this hour are 'off-hours'.", ""),

    ("if_window_min", "B", "Scoring window (min)", 5, 120, 5,
     "Events of one user are aggregated into fixed time buckets of this length; each bucket is one feature vector.",
     "Shorter windows react faster but see less context."),
    ("if_contamination", "B", "Expected anomaly share", 0.001, 0.3, 0.001,
     "Fraction of baseline buckets the model is allowed to treat as anomalous; sets the alert threshold.",
     "Lower = fewer alerts and fewer false positives, but more missed attacks."),
    ("if_trees", "B", "Number of trees", 20, 500, 10,
     "Size of the Isolation Forest ensemble.", "More trees give more stable scores."),

    ("chain_window_min", "C", "Chain window (min)", 5, 480, 5,
     "Maximum gap between two consecutive stage events for them to belong to the same attack chain. If exceeded, the chain restarts.",
     "Longer windows catch slow attackers but allow unrelated events to be linked."),
    ("s1_fail_threshold", "C", "S1: failed logins", 2, 50, 1,
     "Failed logins needed within the S1 window to enter stage 1 (credential guessing).", ""),
    ("s1_window_min", "C", "S1: window (min)", 1, 120, 1, "Counting window for stage 1.", ""),
    ("s2_fail_min", "C", "S2: failures before success", 1, 20, 1,
     "A success after at least this many recent failures enters stage 2 (credential compromise).", ""),
    ("s2_window_min", "C", "S2: window (min)", 1, 120, 1, "How far back failures count for stage 2.", ""),
    ("bulk_min_files", "C", "S5: minimum bulk reads", 10, 1000, 5,
     "Floor for the bulk-access threshold. The effective threshold is max(this, factor x the user's own baseline burst).",
     ""),
    ("bulk_baseline_factor", "C", "S5: baseline factor", 1.0, 10.0, 0.1,
     "Multiplier on the user's normal peak burst of file reads.",
     "Personalised threshold: a backup account with large normal bursts is not flagged."),
    ("burst_window_min", "C", "S5: burst window (min)", 1, 60, 1, "Window used to measure file-read bursts.", ""),
    ("bytes_min_mb", "C", "S6: minimum transfer (MB)", 0.5, 2000, 0.5,
     "Floor for the unusual-transfer size threshold.", ""),
    ("bytes_baseline_factor", "C", "S6: baseline factor", 1.0, 20.0, 0.5,
     "Multiplier on the user's largest normal transfer.", ""),
    ("w1", "C", "Weight S1 credential guessing", 0, 50, 1, "Points added when stage 1 is observed.", ""),
    ("w2", "C", "Weight S2 credential compromise", 0, 50, 1, "Points added when stage 2 is observed.", ""),
    ("w3", "C", "Weight S3 anomalous context", 0, 50, 1, "Points added when stage 3 is observed.", ""),
    ("w4", "C", "Weight S4 privilege abuse", 0, 50, 1, "Points added when stage 4 is observed.", ""),
    ("w5", "C", "Weight S5 data collection", 0, 50, 1, "Points added when stage 5 is observed.", ""),
    ("w6", "C", "Weight S6 exfiltration", 0, 50, 1, "Points added when stage 6 is observed.", ""),
    ("order_bonus", "C", "Order bonus per transition", 0, 20, 1,
     "Extra points for every pair of consecutive stages that occur in kill-chain order (S1 -> S2 -> ... -> S6).",
     "Rewards realistic attack progression."),
    ("velocity_bonus", "C", "Velocity bonus", 0, 20, 1,
     "Extra points when three or more stages occur within the velocity window.", "Rewards fast, automated attacks."),
    ("velocity_window_min", "C", "Velocity window (min)", 1, 120, 1, "Window for the velocity bonus.", ""),
    ("vpn_discount", "C", "VPN discount factor", 0.0, 1.0, 0.05,
     "Multiplier applied to context stages (S2/S3) that came through the corporate VPN with no failed-login history.",
     "1.0 = ignore VPN information; 0.0 = completely ignore VPN-originated context."),
    ("alert_threshold", "C", "Alert threshold (0-100)", 10, 100, 1,
     "An incident is raised when the chain score reaches this value.",
     "Lower = more sensitive; higher = fewer, higher-confidence incidents."),
    ("min_stages", "C", "Minimum distinct stages", 1, 6, 1,
     "An incident also requires at least this many different stages, so one loud signal is never enough.",
     "Core idea of the framework: combine several weak signals."),
]


def param_specs() -> list[dict]:
    defaults = Config().to_dict()
    out = []
    for key, g, label, lo, hi, step, help_, effect in _SPECS:
        out.append({
            "key": key, "group": g, "group_label": _G[g], "label": label, "min": lo, "max": hi,
            "step": step, "default": defaults[key], "help": help_, "effect": effect,
            "kind": "int" if isinstance(defaults[key], int) else "float",
        })
    return out


_SPEC_BY_KEY = {s[0]: s for s in _SPECS}


def build_config(overrides: dict | None = None) -> Config:
    """Create a validated Config: unknown keys ignored, values cast and clamped."""
    cfg = Config()
    for f in fields(Config):
        if overrides and f.name in overrides and overrides[f.name] not in (None, ""):
            spec = _SPEC_BY_KEY.get(f.name)
            try:
                v = type(getattr(cfg, f.name))(float(overrides[f.name]))
            except (TypeError, ValueError):
                continue
            if spec:
                v = min(max(v, spec[3]), spec[4])
                v = type(getattr(cfg, f.name))(v)
            setattr(cfg, f.name, v)
    cfg.baseline_days = max(1, min(cfg.baseline_days, cfg.days - 1))
    if cfg.business_end <= cfg.business_start:
        cfg.business_end = min(24, cfg.business_start + 1)
    return cfg

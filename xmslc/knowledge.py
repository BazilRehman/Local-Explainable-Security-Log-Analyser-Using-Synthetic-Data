"""Documentation content shared by the engine (explanations) and the UI (methodology tab)."""

STAGES = {
    1: {
        "id": "S1", "name": "Credential guessing", "short": "Guessing",
        "signal": "A burst of failed logins for one account within a short window.",
        "why": "Password guessing and credential stuffing generate many authentication failures before a guess succeeds.",
        "logic": "count(login_failure within S1 window) >= S1 threshold",
        "mitre": [("T1110", "Brute Force"), ("T1110.004", "Credential Stuffing")],
        "actions": [("Containment", "Temporarily lock the account and block the offending source IP at the perimeter."),
                    ("Hardening", "Enforce multi-factor authentication and rate-limiting on the login endpoint.")],
    },
    2: {
        "id": "S2", "name": "Credential compromise", "short": "Compromise",
        "signal": "A successful login right after several failures, or from an IP never seen for this user.",
        "why": "A success following guessing - or from an unfamiliar network - suggests a credential or session is now in attacker hands.",
        "logic": "login_success AND (failures in S2 window >= S2 minimum OR source IP not in baseline)",
        "mitre": [("T1078", "Valid Accounts"), ("T1550.004", "Web Session Cookie")],
        "actions": [("Containment", "Force a password reset and revoke every active session and token for the account."),
                    ("Investigation", "Confirm with the user whether they authenticated from that IP address.")],
    },
    3: {
        "id": "S3", "name": "Anomalous context", "short": "Context",
        "signal": "Login from a device, country or hour that does not match the user's baseline.",
        "why": "Attackers rarely replicate the victim's device, location and working hours.",
        "logic": "login_success AND (device not in baseline OR country not in baseline OR hour outside learned working range)",
        "mitre": [("T1078", "Valid Accounts")],
        "actions": [("Investigation", "Check device inventory and geo-velocity: could the user physically be there?"),
                    ("Hardening", "Require step-up authentication for logins from unrecognised devices.")],
    },
    4: {
        "id": "S4", "name": "Privilege abuse", "short": "Privilege",
        "signal": "Administrative actions or privilege changes by an account with no routine admin activity.",
        "why": "Escalation lets an attacker widen access, persist and disable defences.",
        "logic": "admin_action/priv_change AND user has no admin activity in baseline (priv_change also flags when the user never changed privileges)",
        "mitre": [("T1098", "Account Manipulation"), ("T1548", "Abuse Elevation Control Mechanism")],
        "actions": [("Containment", "Revert unauthorised privilege grants and suspend the elevated role."),
                    ("Investigation", "Review the admin audit log for every change made during the session.")],
    },
    5: {
        "id": "S5", "name": "Data collection", "short": "Collection",
        "signal": "A burst of file reads far above the user's own normal peak.",
        "why": "Before exfiltration, attackers and malicious insiders gather large amounts of data.",
        "logic": "count(file_read within burst window) >= max(S5 minimum, factor x user's baseline peak burst)",
        "mitre": [("T1039", "Data from Network Shared Drive"), ("T1005", "Data from Local System")],
        "actions": [("Containment", "Restrict the account's access to sensitive shares and snapshot the affected folders."),
                    ("Investigation", "Establish which files were read and classify their sensitivity.")],
    },
    6: {
        "id": "S6", "name": "Exfiltration", "short": "Exfiltration",
        "signal": "An outbound transfer to a destination never seen before, or far larger than any previous transfer.",
        "why": "This is the point at which data actually leaves the organisation.",
        "logic": "outbound_transfer AND (destination not in baseline OR bytes > max(S6 minimum, factor x user's largest baseline transfer))",
        "mitre": [("T1048", "Exfiltration Over Alternative Protocol"), ("T1567", "Exfiltration Over Web Service")],
        "actions": [("Containment", "Block the destination at the egress firewall/proxy and preserve network logs."),
                    ("Investigation", "Estimate the volume and sensitivity of the data transferred; assess breach-notification duties.")],
    },
}

RULES = [
    {"id": "R1", "name": "Failed-login threshold", "logic": "At least N failed logins for one user inside a window (default 5 in 10 min); 10-minute cool-down.",
     "rationale": "Classic brute-force signature.", "weakness": "Fires on lock-out bursts caused by honest typos; blind to slow attacks.", "severity": "medium"},
    {"id": "R2", "name": "Off-hours login", "logic": "A successful login outside business hours (default 07:00-19:00).",
     "rationale": "Attackers often operate outside the victim's working day.", "weakness": "Every legitimate late worker triggers it; ignores personal schedules.", "severity": "low"},
    {"id": "R3", "name": "Non-corporate source IP", "logic": "A successful login from outside the corporate address range (10.20.0.0/16) that did not come through the VPN.",
     "rationale": "Direct logins from the internet are unexpected for staff.", "weakness": "Blind to attackers that use a VPN; flags home working without VPN.", "severity": "medium"},
    {"id": "R4", "name": "Foreign country login", "logic": "A successful login from a country other than the organisation's home country (AE).",
     "rationale": "Simple geo-fencing.", "weakness": "Business travellers trigger it; overlaps with R3.", "severity": "medium"},
    {"id": "R5", "name": "Admin action by non-admin", "logic": "An admin action or privilege change by a user with no administrative activity in the baseline directory.",
     "rationale": "Privilege use outside role.", "weakness": "Each admin event alerts independently; no link to how the session began.", "severity": "high"},
    {"id": "R6", "name": "Bulk file access", "logic": "At least N file reads inside a window (default 100 in 10 min); 10-minute cool-down.",
     "rationale": "Mass data collection.", "weakness": "Static threshold: the nightly backup job and archive operations fire it every time.", "severity": "medium"},
    {"id": "R7", "name": "Large / unapproved outbound transfer", "logic": "An outbound transfer over N MB (default 5) or to a destination not on the approved list.",
     "rationale": "Data exfiltration.", "weakness": "Backups exceed the size limit; any new vendor is 'unapproved'.", "severity": "high"},
]

IF_FEATURES = [
    ("n_fail", "Number of failed logins in the window", "Guessing activity"),
    ("n_success", "Number of successful logins", "Session volume"),
    ("n_files", "Number of file reads", "Data collection volume"),
    ("n_admin", "Number of admin actions and privilege changes", "Privileged activity"),
    ("n_out", "Number of outbound transfers", "Egress activity"),
    ("log_bytes_out", "log10(1 + bytes sent outbound)", "Egress size"),
    ("n_distinct_ips", "Distinct source IPs seen", "Multiple origins"),
    ("new_ip_logins", "Successful logins from an IP not in the user's baseline", "Location novelty"),
    ("new_device_logins", "Successful logins from a device not in the user's baseline", "Device novelty"),
    ("offhours_logins", "Successful logins outside the user's learned hours", "Time novelty"),
    ("new_dest", "Outbound transfers to a destination not in the baseline", "Destination novelty"),
    ("hour_sin", "sin of the window's hour-of-day", "Time of day (cyclic encoding)"),
    ("hour_cos", "cos of the window's hour-of-day", "Time of day (cyclic encoding)"),
]

METRICS = [
    {"key": "recall", "name": "Recall (attack detection rate)", "formula": "detected attack chains / total attack chains",
     "meaning": "Of the real attacks that were injected, how many did the detector notice? A chain counts as detected when at least one alert overlaps it in time for the same user.",
     "good": "Higher is better; 1.0 means no attack was missed."},
    {"key": "precision", "name": "Investigation precision", "formula": "detected attack chains / (detected attack chains + false-positive alerts)",
     "meaning": "Each false alert costs an analyst one wasted investigation; each real attack is investigated once however many alerts it produced. This measures how much analyst effort produced real findings.",
     "good": "Higher is better; low values mean analysts drown in noise (alert fatigue)."},
    {"key": "f1", "name": "F1-score", "formula": "2 x precision x recall / (precision + recall)",
     "meaning": "Harmonic mean of precision and recall: a detector cannot score well by being only sensitive or only quiet.",
     "good": "Higher is better; balances catching attacks against raising false alarms."},
    {"key": "fpr", "name": "False-positive rate (benign user-days)", "formula": "benign user-days with at least one false alert / all benign user-days",
     "meaning": "How often an innocent user-day is flagged. This is the operational burden on a SOC and the key figure for small organisations.",
     "good": "Lower is better."},
    {"key": "mttd_min", "name": "Mean time to detection (minutes)", "formula": "mean(first alert time - first attack event time) over detected chains",
     "meaning": "How quickly the attack is noticed after it begins. Shorter is better because damage grows with time.",
     "good": "Lower is better. Batch detectors cannot alert before their scoring window closes."},
    {"key": "alerts", "name": "Alert volume", "formula": "total alerts (incidents for detector C)",
     "meaning": "How many items an analyst must triage in the evaluation period.", "good": "Lower is better, provided recall is not lost."},
    {"key": "alerts_per_attack", "name": "Alerts per detected attack", "formula": "alerts overlapping attack chains / detected attack chains",
     "meaning": "How fragmented a single attack appears. 1.0 means the attack is presented as one consolidated incident.",
     "good": "Closer to 1 is better (alert consolidation)."},
    {"key": "fidelity", "name": "Explanation fidelity (evidence F1)", "formula": "F1 of (evidence events cited by the alert vs. true attack events), averaged over detected chains",
     "meaning": "Does the alert point at the events that really form the attack? Precision penalises irrelevant evidence; recall penalises missing evidence. It measures localisation only - whether the cited events are the right ones - not whether the alert gives understandable reasons.",
     "good": "Higher is better. A window-based detector can score well when attack events dominate its window, so also judge the qualitative explanation (stage, rule, counter-evidence, ATT&CK mapping) that only detector C provides."},
    {"key": "control_alerts", "name": "Benign-control alerts", "formula": "alerts overlapping benign travel/VPN cases",
     "meaning": "Alerts raised on harmless but unusual behaviour. A mature detector must tolerate these.", "good": "Lower is better; ideally 0."},
]

SCENARIOS = [
    {"id": "credential_stuffing", "name": "Credential stuffing", "difficulty": "Basic", "label": "Attack",
     "chain": "many failed logins -> success from new device -> optional file access / exfiltration",
     "tests": "Can the detector connect failed and successful authentication into one incident?"},
    {"id": "stolen_session", "name": "Stolen session / account takeover", "difficulty": "Medium", "label": "Attack",
     "chain": "valid login from new IP/device (no failures) -> admin actions -> bulk file reads -> exfiltration",
     "tests": "Can the detector spot an attacker who never triggers a failed-login rule?"},
    {"id": "insider_misuse", "name": "Insider-like misuse", "difficulty": "Medium", "label": "Attack",
     "chain": "normal login from own device -> privilege grant -> bulk sensitive reads -> external transfer",
     "tests": "Can behaviour alone expose an attack when identity, device and location are all normal?"},
    {"id": "slow_exfil", "name": "Low-and-slow exfiltration (off-model)", "difficulty": "Hard", "label": "Attack",
     "chain": "normal login -> small file batches spaced 25-45 min apart -> small transfers to a new cloud destination",
     "tests": "Deliberately outside the six modelled stages: shows what multi-stage correlation gives up in return for fewer false positives."},
    {"id": "benign_travel", "name": "Benign travel / VPN", "difficulty": "Control", "label": "Benign control",
     "chain": "late login from a new country (usually VPN), maybe a typo, then ordinary work",
     "tests": "Does the detector avoid flagging unusual-but-legitimate activity?"},
]

STATS = [
    {"name": "Paired t-test", "use": "Compares the per-seed scores of two detectors run on identical synthetic organisations. Pairing removes seed-to-seed variation.",
     "read": "p < 0.05 (Bonferroni-adjusted for the number of comparisons) suggests the difference is unlikely to be chance. Assumes roughly normal differences."},
    {"name": "Wilcoxon signed-rank test", "use": "Non-parametric alternative to the paired t-test; makes no normality assumption.",
     "read": "Agreement between t-test and Wilcoxon strengthens the conclusion. With very few runs the smallest attainable p-value is limited."},
    {"name": "Cohen's d (paired)", "use": "Effect size: mean difference divided by the standard deviation of the differences.",
     "read": "|d| ~0.2 small, ~0.5 medium, >= 0.8 large. Significance says 'is there a difference'; effect size says 'does it matter'."},
    {"name": "95% confidence interval", "use": "Range of mean scores expected if the experiment were repeated (Student-t based).",
     "read": "Non-overlapping intervals between detectors indicate a robust gap."},
]

LIMITATIONS = [
    "Circularity risk: three of the four attack scenarios are generated from the same six-stage model that detector C recognises, so part of C's advantage reflects shared assumptions. The low-and-slow scenario is deliberately off-model to expose this; any claim about C should be read together with its recall on that scenario.",
    "All data is synthetic. Detector performance depends on how realistic the documented behavioural model is; it is not evidence of performance on a real network.",
    "The correlation engine only recognises the six modelled stages; novel attack types that do not follow them will be missed (Isolation Forest partly covers unknown behaviour).",
    "Weights, thresholds and windows are expert-set design parameters. They are exposed in the UI so their influence can be studied, but they are not learned from data.",
    "Profiles are learned from a short baseline period that is assumed to be attack-free. In practice the baseline may contain compromised activity, and new users have no profile (cold start).",
    "Adversarial evasion: an attacker who knows the thresholds can slow down or split activity (the stealth parameter models this crudely).",
    "Ground-truth matching is time-and-user based; very overlapping benign activity can be matched to an attack chain.",
    "This is a research prototype, not a production SIEM. It must never be pointed at real systems or personal data without a separate ethics and security review.",
]

ETHICS = ("No human participants, personal data, university data or live systems are involved. All identities, hosts, organisations and "
          "events are fictional; attacker addresses use RFC 5737 documentation ranges. The prototype runs entirely offline and performs "
          "no scanning, no credential attacks and no malware execution.")

GLOSSARY = [
    ("Account takeover (ATO)", "Unauthorised control of a legitimate user account, via stolen/guessed credentials or hijacked sessions."),
    ("Alert fatigue", "Loss of analyst attention and trust caused by an overwhelming volume of mostly false or low-value alerts."),
    ("SIEM", "Security Information and Event Management: collects logs and raises alerts."),
    ("SOC", "Security Operations Centre: the team that monitors and responds to alerts."),
    ("Isolation Forest", "Unsupervised anomaly detector that isolates unusual points with random trees; unusual points need fewer splits."),
    ("Explainability", "The degree to which a system can show which evidence and reasoning produced its decision."),
    ("Finite-state correlation", "Tracking an account through ordered stages (S1-S6) and scoring the progression."),
    ("Sliding time window", "Only events within a fixed time span of one another can be linked into a chain."),
    ("Baseline", "Per-user behavioural profile learned from the attack-free learning period."),
    ("Kill chain", "Ordered sequence of attacker steps from initial access to objective."),
    ("MITRE ATT&CK", "Public knowledge base of adversary tactics and techniques used here to label each stage."),
    ("False positive / false negative", "A benign case flagged / a real attack missed."),
    ("Cold start", "A user without enough baseline history; novelty checks are relaxed for them."),
]

PIPELINE = [
    ("1  Generate", "Seeded generator creates normal behaviour, benign noise and labelled attack chains in four native log formats."),
    ("2  Normalise", "Heterogeneous records are converted to one schema; invalid and duplicate records are reported."),
    ("3  Profile", "Per-user baselines (IPs, devices, hours, volumes) are learned from the attack-free learning period only."),
    ("4  Detect", "The same events are analysed by A (rules), B (Isolation Forest) and C (multi-stage correlation)."),
    ("5  Explain", "Detector C attaches stage evidence, a score breakdown, ATT&CK mapping and response actions to every incident."),
    ("6  Evaluate", "Alerts are scored against the hidden ground-truth chains: recall, precision, F1, FPR, MTTD, fidelity."),
]


def classify_chain(stage_ids: set, novel_ip: bool, known_device: bool) -> str:
    if 1 in stage_ids and 2 in stage_ids:
        return "Credential stuffing / brute force followed by account use"
    if 2 in stage_ids and (4 in stage_ids or 5 in stage_ids or 6 in stage_ids):
        return "Account takeover with stolen credentials or a replayed session"
    if (5 in stage_ids or 6 in stage_ids) and 2 not in stage_ids and known_device:
        return "Insider-style data collection and exfiltration"
    return "Multi-stage suspicious activity"


def docs_payload() -> dict:
    return {
        "stages": [{"n": k, **{kk: vv for kk, vv in v.items() if kk != "actions"},
                    "mitre": [{"id": a, "name": b} for a, b in v["mitre"]]} for k, v in STAGES.items()],
        "rules": RULES, "if_features": [{"name": a, "meaning": b, "captures": c} for a, b, c in IF_FEATURES],
        "metrics": METRICS, "scenarios": SCENARIOS, "stats": STATS, "limitations": LIMITATIONS,
        "ethics": ETHICS, "glossary": [{"term": a, "meaning": b} for a, b in GLOSSARY],
        "pipeline": [{"step": a, "text": b} for a, b in PIPELINE],
    }

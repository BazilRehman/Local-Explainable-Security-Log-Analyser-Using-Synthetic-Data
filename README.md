# XMSLC Workbench - Explainable Multi-Stage Log Correlation

MSc Cybersecurity research prototype (CST4990, Middlesex University Dubai).
*Design and Evaluation of an Explainable Multi-Stage Log-Correlation Framework for Detecting Simulated Account Takeover Using Synthetic Security Logs.*

A fully offline Python application that (1) generates labelled synthetic security logs, (2) normalises four log formats into one schema,
(3) learns per-user baselines, (4) runs three detectors on identical data and (5) evaluates them against the hidden ground truth,
with a web workbench that explains every result.

| Detector | Method |
|---|---|
| **A** | Independent single-event rules R1-R7 (conventional SIEM-style baseline) |
| **B** | Isolation Forest over per-user time-window features (black-box anomaly baseline) |
| **C** | **Proposed:** per-user finite-state correlation of six attack stages (S1-S6) with a scored, evidence-backed, explainable incident |

## Run

```bash
pip install -r requirements.txt
python run.py            # http://127.0.0.1:5000   (use --port to change)
python -m unittest discover -s tests -v
```

No internet access is needed at run time: the UI uses no CDN, fonts or external scripts.

## What you can do in the UI

1. **Configure & Run** - every generator and detector parameter is an input (with plain-English help), plus presets.
2. **Executive Summary** - auto-written findings, all evaluation criteria with formulas/definitions, per-scenario detection, per-chain outcome and miss reasons, data-quality report.
3. **Incident Investigation** - stage ladder, score breakdown, timeline, per-stage evidence and rule, benign counter-evidence, MITRE ATT&CK mapping, response actions, suppressed (non-alerted) chains.
4. **Detector Comparison** - how each detector works; how one attack looks to A, B and C.
5. **Log Explorer** - filter/search normalised or raw records; click an event to see why each detector flagged it; CSV/JSONL export.
6. **Statistical Experiments** - multi-seed runs, 95% CIs, paired t-test + Wilcoxon (Bonferroni), Cohen's d, robustness sweeps (missing logs, noise, stealth).
7. **Analyse Your Own Logs** - paste/upload CSV or JSON and get the same explained analysis.
8. **Methodology & Criteria** - the full specification, limitations and ethics.

## Layout

```
run.py                    entry point
xmslc/config.py           parameters + schema (the UI form is generated from it)
xmslc/generator.py        synthetic organisation, noise, labelled attack scenarios, raw formats
xmslc/normaliser.py       4 source formats / CSV / JSON -> common schema + quality report
xmslc/detectors/          profiles.py (baselines), rules.py (A), iforest.py (B), correlator.py (C)
xmslc/evaluation.py       matching alerts to ground truth, metrics
xmslc/experiments.py      multi-seed statistics, robustness sweeps
xmslc/knowledge.py        stage/rule/metric definitions shown in the UI
xmslc/server.py           Flask REST API
xmslc/static/             single-page UI (vanilla JS, inline SVG charts)
tests/                    unit tests
```

## Scientific caveats (also shown in the UI)

* All data is synthetic; results compare methods under documented assumptions and do not predict real-world performance.
* Three of four attack scenarios are generated from the same six-stage model that detector C recognises (circularity). The **low-and-slow exfiltration** scenario is deliberately off-model to expose what C gives up in recall for its low false-positive rate.
* Fidelity measures *where* evidence points, not the quality of reasons; the qualitative explanation is a separate contribution of C.
* Weights and thresholds are expert-set, exposed as parameters, not learned.

## Ethics

No human participants, personal data, university data or live systems. All identities, hosts and events are fictional; attacker IPs use RFC 5737 documentation ranges. Runs offline; performs no scanning, credential attacks or malware execution.

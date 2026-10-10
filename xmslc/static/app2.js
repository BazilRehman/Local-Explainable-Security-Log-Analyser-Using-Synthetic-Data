/* XMSLC workbench - experiments, custom-log analysis, methodology reference. */
"use strict";
const pfmt = p => p == null ? "n/a" : p < 0.001 ? "<0.001" : p.toFixed(3);
const MLAB = {recall: "Recall", precision: "Precision", f1: "F1-score", fpr: "False-positive rate", mttd_min: "Mean time to detection (min)", alerts: "Alert volume", fidelity: "Explanation fidelity"};
const SWEEP_DOC = {
  drop_rate: ["Missing logs", "Fraction of raw records randomly lost (collection gaps)", "Do detectors degrade gracefully when evidence is missing?"],
  noise_level: ["Background noise", "Frequency of benign irregularities (typos, VPN days, late work, archives)", "Does more benign noise create false positives?"],
  stealth: ["Attacker stealth", "How careful the attacker is: slower, fewer steps", "How quickly does detection fall as attackers hide?"],
};

/* -------------------------------------------------------------- experiments */
function renderExperiments() {
  $("#tab-experiments").innerHTML = `
  <div class="page-head"><div><div class="crumb">Step 6 of 8</div><h2>Statistical experiments</h2>
    <p>A single run can be lucky. These experiments repeat the whole pipeline over many different random seeds (different synthetic organisations and attacks), then test whether the differences between detectors are statistically meaningful and how they hold up under stress.</p></div></div>
  <div class="card"><h3>E1-E3 · Multi-seed comparison with significance testing</h3>
    <p class="sub">Uses the settings from "Configure &amp; Run" as the base; run <i>i</i> uses seed + <i>i</i>. Every detector sees identical data in each run, so the tests are <b>paired</b>.</p>
    <div class="filters"><div><label>Number of runs (3-30)</label><input type="number" id="expRuns" min="3" max="30" value="10" style="width:100px"></div>
      <button class="btn primary" id="expGo">Run multi-seed experiment</button><span class="help" id="expStat"></span></div><div id="expOut"></div></div>
  <div class="card"><h3>E5 · Robustness sweeps</h3>
    <p class="sub">Vary one stress factor at a time and watch each detector's F1-score. Each point averages several runs.</p>
    <div class="filters"><div><label>Runs per level (2-8)</label><input type="number" id="robRuns" min="2" max="8" value="3" style="width:100px"></div>
      <button class="btn primary" id="robGo">Run robustness sweeps</button><span class="help" id="robStat"></span></div>
    <div class="progress"><div id="robBar"></div></div><div id="robOut"></div></div>
  <div class="card flat"><h3>How to read the statistics</h3>${S.schema ? statsDocs() : ""}</div>`;
  $("#expGo").onclick = runExperiment; $("#robGo").onclick = runRobustness;
}
function statsDocs() {
  return S.schema.docs.stats.map(s => `<div class="defn"><h4>${esc(s.name)}</h4><p>${esc(s.use)}</p><p class="help"><b>Reading it:</b> ${esc(s.read)}</p></div>`).join("");
}

async function runExperiment() {
  const b = $("#expGo"), runs = +$("#expRuns").value || 10;
  b.disabled = true; b.innerHTML = `<span class="spin"></span> Running ${runs} pipelines...`; $("#expStat").textContent = "";
  const t0 = performance.now();
  try {
    const d = await api("/api/experiment", {config: S.cfg, runs});
    const sm = d.summary, ci = (k, m) => sm[k][m] && sm[k][m].ci95;
    $("#expStat").textContent = `Completed ${d.n_runs} runs in ${((performance.now() - t0) / 1000).toFixed(1)} s (seeds ${d.seeds[0]}-${d.seeds[d.seeds.length - 1]}).`;
    const rowsM = ["recall", "precision", "f1", "fpr", "mttd_min", "alerts", "fidelity"];
    $("#expOut").innerHTML = `
    <h4>Mean performance over ${d.n_runs} runs (error bars = 95% confidence interval)</h4>
    <div class="grid g2"><div>${legend(["A", "B", "C"].map(k => ({name: DNAME[k], color: COL[k]})))}
      ${barChart({cats: ["Recall", "Precision", "F1-score", "FPR"], series: ["A", "B", "C"].map(k => ({name: DNAME[k], color: COL[k], values: ["recall", "precision", "f1", "fpr"].map(m => sm[k][m].mean), err: ["recall", "precision", "f1", "fpr"].map(m => ci(k, m))})), fmtv: v => (v * 100).toFixed(0) + "%"})}</div>
      <div>${legend([{name: "Alerts per run (mean)", color: "#7aa2f7"}])}${barChart({cats: ["A rules", "B IF", "C corr."], max: Math.max(1, ...["A", "B", "C"].map(k => sm[k].alerts.mean)) * 1.15, fmtv: v => v.toFixed(0), series: [{name: "alerts", color: "#7aa2f7", values: ["A", "B", "C"].map(k => sm[k].alerts.mean), err: ["A", "B", "C"].map(k => ci(k, "alerts"))}]})}</div></div>
    <div class="tw" style="margin-top:12px"><table class="data"><thead><tr><th>Criterion</th>${["A", "B", "C"].map(k => `<th class="num">${DNAME[k]}</th>`).join("")}</tr></thead><tbody>
      ${rowsM.map(m => `<tr><td><b>${MLAB[m]}</b></td>${["A", "B", "C"].map(k => { const a = sm[k][m]; return `<td class="num">${a ? `${fmt(a.mean, m)} <span class="help">± ${fmt(a.sd, m)}</span><div class="help">95% CI ${a.ci95 ? fmt(a.ci95[0], m) + " - " + fmt(a.ci95[1], m) : "n/a"}</div>` : "n/a"}</td>`; }).join("")}</tr>`).join("")}</tbody></table></div>
    <h4 style="margin-top:22px">Detection rate by scenario (pooled over all runs)</h4>
    <div class="tw"><table class="data"><thead><tr><th>Scenario</th>${["A", "B", "C"].map(k => `<th class="num">${DNAME[k]}</th>`).join("")}</tr></thead><tbody>
      ${Object.keys(d.by_scenario.C).map(sc => { const ctl = sc === "benign_travel"; return `<tr><td>${esc(scenName(sc))}${ctl ? ` <span class="chip ctl">control: lower is better</span>` : ""}</td>${["A", "B", "C"].map(k => { const v = d.by_scenario[k][sc], r = v.rate, good = ctl ? 1 - r : r; return `<td class="num" style="color:${good >= .8 ? "#7ee2a1" : good >= .5 ? "#f3d36b" : "#ff9a9a"};font-weight:700">${pct(r)}<div class="help">${v.detected} / ${v.total}</div></td>`; }).join("")}</tr>`; }).join("")}</tbody></table></div>
    <h4 style="margin-top:22px">Paired significance tests: detector C versus each baseline</h4>
    <div class="tw"><table class="data"><thead><tr><th>Comparison</th><th>Criterion</th><th class="num">Mean difference (C - other)</th><th class="num">t</th><th class="num">p (t-test, Bonferroni)</th><th class="num">p (Wilcoxon)</th><th class="num">Cohen's d</th><th>Conclusion</th></tr></thead><tbody>
      ${d.comparisons.map(c => `<tr><td><b>${c.pair}</b></td><td>${MLAB[c.metric]}${c.lower_is_better ? ' <span class="help">(lower is better)</span>' : ""}</td><td class="num">${c.mean_diff == null ? "n/a" : c.mean_diff.toFixed(3)}</td><td class="num">${c.t == null ? "-" : c.t}</td><td class="num">${pfmt(c.p_t_adj)}</td><td class="num">${pfmt(c.p_w)}</td><td class="num">${c.cohen_dz == null ? "-" : c.cohen_dz}</td>
      <td>${c.significant ? `<span class="chip ${c.direction === "C better" ? "tp" : "fp"}">${esc(c.direction)} · significant</span>` : `<span class="chip ev">${esc(c.direction || "n/a")} · not significant</span>`}</td></tr>`).join("")}</tbody></table></div>
    <div class="callout"><b>Reading this table.</b> The mean difference is C minus the baseline for each run, so a negative value is good for "lower is better" criteria. p-values are multiplied by ${d.bonferroni_tests} (Bonferroni) because ${d.bonferroni_tests} tests were run; significance means adjusted p &lt; 0.05. Cohen's d describes how large the effect is (≥0.8 is large). If a result is "C worse" and significant, that is a genuine trade-off to discuss - for example lower recall on attacks that fall outside the stage model.</div>
    <div class="callout warn"><b>Validity note.</b> Most attack scenarios are generated from the same six-stage model that detector C recognises, so C's strength on them is partly by construction. The off-model low-and-slow scenario is the honest counterweight; weigh the two together.</div>`;
  } catch (e) { toast(e.message); }
  finally { b.disabled = false; b.textContent = "Run multi-seed experiment"; }
}

async function runRobustness() {
  const b = $("#robGo"), runs = +$("#robRuns").value || 3, vars = ["drop_rate", "noise_level", "stealth"];
  b.disabled = true; b.innerHTML = `<span class="spin"></span> Running...`; $("#robOut").innerHTML = ""; $("#robBar").style.width = "0";
  const res = {};
  try {
    for (let i = 0; i < vars.length; i++) {
      $("#robStat").textContent = `Sweep ${i + 1} of ${vars.length}: ${SWEEP_DOC[vars[i]][0]}...`;
      res[vars[i]] = await api("/api/robustness", {config: S.cfg, variable: vars[i], runs});
      $("#robBar").style.width = ((i + 1) / vars.length * 100) + "%";
    }
    $("#robStat").textContent = "Done.";
    $("#robOut").innerHTML = `<div class="grid g3">${vars.map(v => { const r = res[v]; return `<div><h4>${SWEEP_DOC[v][0]}</h4><div class="help">${SWEEP_DOC[v][1]}</div>${legend(["A", "B", "C"].map(k => ({name: "Detector " + k, color: COL[k]})))}
      ${lineChart({xs: r.rows.map(x => x.level), xlabel: SWEEP_DOC[v][0] + " level", series: ["A", "B", "C"].map(k => ({name: "Detector " + k + " F1", color: COL[k], values: r.rows.map(x => x[k].f1)}))})}
      <div class="explain"><b>Question:</b> ${SWEEP_DOC[v][2]}<br>F1 at lowest → highest level: ${["A", "B", "C"].map(k => `<span class="chip ${k}">${k}</span> ${pct(r.rows[0][k].f1)} → ${pct(r.rows[r.rows.length - 1][k].f1)}`).join(" &nbsp; ")}</div></div>`; }).join("")}</div>
      <div class="callout">A flat line means the detector is robust to that stress; a falling line shows where it breaks. Compare the <em>slope</em> as well as the starting level: a detector that begins high but collapses is less trustworthy than one that degrades gently.</div>`;
  } catch (e) { toast(e.message); }
  finally { b.disabled = false; b.textContent = "Run robustness sweeps"; }
}

/* ------------------------------------------------------------ custom logs */
function sampleCsv() {
  const L = ["timestamp,user,event_type,src_ip,device,geo,resource,bytes,via_vpn"];
  const pad = n => String(n).padStart(2, "0"), ts = (d, h, m, s) => `2026-03-0${d} ${pad(h)}:${pad(m)}:${pad(s)}`;
  for (const u of [["alice", "10.20.5.10", "WS-ALICE"], ["bob", "10.20.7.22", "WS-BOB"]]) {
    for (let d = 1; d <= 3; d++) {
      L.push(`${ts(d, 8, 30, 0)},${u[0]},login_success,${u[1]},${u[2]},AE,,0,false`);
      for (let i = 0; i < 9; i++) L.push(`${ts(d, 9 + (i >> 1), 10 + i * 4, 5 + i)},${u[0]},file_read,${u[1]},${u[2]},AE,/share/${u[0]}/doc_${d}${i}.xlsx,120000,false`);
      L.push(`${ts(d, 15, 0, 0)},${u[0]},outbound_transfer,${u[1]},${u[2]},AE,mail.corp.local,250000,false`);
    }
  }
  L.push(`${ts(4, 8, 31, 0)},alice,login_success,10.20.5.10,WS-ALICE,AE,,0,false`);       // normal day for alice
  for (let i = 0; i < 7; i++) L.push(`${ts(5, 3, 10, i * 6)},alice,login_failure,203.0.113.9,unknown-9f3a,RU,,0,false`);
  L.push(`${ts(5, 3, 11, 5)},alice,login_success,203.0.113.9,unknown-9f3a,RU,,0,false`);
  L.push(`${ts(5, 3, 14, 0)},alice,admin_action,203.0.113.9,unknown-9f3a,RU,/admin/user-management,0,false`);
  for (let i = 0; i < 160; i++) L.push(`${ts(5, 3, 16 + (i >> 5), (i * 2) % 60)},alice,file_read,203.0.113.9,unknown-9f3a,RU,/share/finance/treasury/file_${i}.xlsx,900000,false`);
  L.push(`${ts(5, 3, 24, 0)},alice,outbound_transfer,203.0.113.9,unknown-9f3a,RU,mega-share.example,150000000,false`);
  L.push(`${ts(5, 2, 20, 0)},bob,login_success,82.14.9.77,LT-BOB,GB,,0,true`);                 // benign traveller
  for (let i = 0; i < 12; i++) L.push(`${ts(5, 2, 21 + (i >> 2), i * 5)},bob,file_read,82.14.9.77,LT-BOB,GB,/share/bob/doc_${i}.xlsx,100000,true`);
  return L.join("\n");
}
const CUSTOM = {res: null};
function renderCustom() {
  $("#tab-custom").innerHTML = `
  <div class="page-head"><div><div class="crumb">Step 7 of 8</div><h2>Analyse your own logs</h2>
    <p>Paste or upload any security log as CSV or JSON. It is normalised, the first part is used to learn baselines, and the remainder is analysed by all three detectors with full explanations. No ground truth exists for your own data, so no accuracy metrics are produced - instead you get the alerts and their reasoning.</p></div></div>
  <div class="grid g2"><div class="card"><h3>Input</h3>
    <div class="filters"><div><label>Format</label><select id="cFmt"><option value="auto">Auto-detect</option><option value="csv">CSV</option><option value="json">JSON / JSON-lines</option></select></div>
      <div><label>Baseline share of timeline</label><input type="range" id="cBase" min="0.1" max="0.9" step="0.05" value="0.4" style="width:150px"><span class="help" id="cBaseV">40%</span></div></div>
    <textarea id="cData" rows="13" placeholder="timestamp,user,event_type,src_ip,device,geo,resource,bytes,via_vpn&#10;2026-03-01 08:30:00,alice,login_success,10.20.5.10,WS-ALICE,AE,,0,false&#10;..."></textarea>
    <div class="filters" style="margin-top:10px"><input type="file" id="cFile" accept=".csv,.json,.jsonl,.txt,.log"><button class="btn" id="cSample">Load sample (attack + benign traveller)</button><button class="btn primary" id="cGo">Analyse logs</button></div>
    <div class="help">Detector settings (windows, weights, threshold) come from the "Configure &amp; Run" tab.</div></div>
  <div class="card"><h3>Accepted format</h3><p class="sub">Required: <code>timestamp</code>, <code>user</code>, <code>event_type</code>. Optional: <code>src_ip</code>, <code>device</code>, <code>geo</code>, <code>resource</code>, <code>bytes</code>, <code>via_vpn</code>, <code>session_id</code>.</p>
    <p class="help"><b>event_type</b> values (synonyms such as <code>failed_login</code>, <code>download</code>, <code>privilege_escalation</code>, <code>upload</code> are mapped automatically): <span class="mono-s">login_success, login_failure, file_read, admin_action, priv_change, outbound_transfer</span>.<br>
    Timestamps may be ISO-8601, <code>YYYY-MM-DD HH:MM:SS</code>, or epoch seconds/milliseconds (UTC).<br>The native formats of the four generated sources (auth, file, privilege, network) are also recognised.</p>
    <div class="callout warn"><b>Use only logs you are authorised to analyse.</b> This is a research prototype; do not upload production or personal data.</div></div></div>
  <div id="cOut"></div>`;
  $("#cBase").oninput = e => $("#cBaseV").textContent = Math.round(e.target.value * 100) + "%";
  $("#cSample").onclick = () => { $("#cData").value = sampleCsv(); $("#cFmt").value = "csv"; };
  $("#cFile").onchange = e => { const f = e.target.files[0]; if (!f) return; const r = new FileReader(); r.onload = () => $("#cData").value = r.result; r.readAsText(f); };
  $("#cGo").onclick = runCustom;
}
async function runCustom() {
  const b = $("#cGo"); b.disabled = true; b.innerHTML = `<span class="spin"></span> Analysing...`;
  try {
    const d = await api("/api/custom", {data: $("#cData").value, format: $("#cFmt").value, baseline_fraction: +$("#cBase").value, config: S.cfg});
    CUSTOM.res = d; drawCustom(d);
  } catch (e) { toast(e.message); $("#cOut").innerHTML = `<div class="callout warn"><b>Could not analyse:</b> ${esc(e.message)}</div>`; }
  finally { b.disabled = false; b.textContent = "Analyse logs"; }
}
function drawCustom(d) {
  const q = d.quality, D = d.dataset, C = d.detectors.C, A = d.detectors.A, B = d.detectors.B;
  const prev = S.run; S.run = d;   // incidentHTML reads S.run.config; restore afterwards
  const html = C.incidents.length ? C.incidents.slice().sort((a, b) => b.score - a.score).map(i => `<details class="grp" open><summary><span class="tag C">C</span>${esc(i.incident_id)} · ${esc(i.user)} · score ${i.score} · ${esc(i.severity.toUpperCase())}</summary><div>${incidentHTML(i, false)}</div></details>`).join("")
    : `<div class="empty"><b>No multi-stage incidents</b>No account combined enough correlated stages to cross the threshold of ${d.config.alert_threshold}. See the suppressed chains below and the single-event alerts of detectors A and B.</div>`;
  S.run = prev;
  $("#cOut").innerHTML = `<div class="grid g4" style="margin-bottom:16px">
      <div class="kpi"><div class="lab">Records parsed</div><div class="val">${q.records_ok.toLocaleString()}</div><p class="sub">${q.records_in.toLocaleString()} in · ${q.records_rejected} rejected · ${q.duplicates_removed} duplicates</p></div>
      <div class="kpi A"><div class="lab">A: rule alerts</div><div class="val">${A.total}</div><p class="sub">Single-event alerts after the baseline period.</p></div>
      <div class="kpi B"><div class="lab">B: IF alerts</div><div class="val">${B.total}</div><p class="sub">Unusual time windows.</p></div>
      <div class="kpi C"><div class="lab">C: incidents</div><div class="val">${C.total}</div><p class="sub">Correlated, explained incidents.</p></div></div>
    <div class="callout">Baseline learned from <b>${D.baseline_events.toLocaleString()}</b> events before <b>${tstr(D.eval_start)}</b>; <b>${D.eval_events.toLocaleString()}</b> events analysed. ${D.cold_start_users ? `${D.cold_start_users} user(s) had too little baseline history (cold start), so novelty checks are relaxed for them.` : ""}
      ${Object.keys(q.rejected_reasons).length ? `<br><b>Rejected records:</b> ${Object.entries(q.rejected_reasons).map(([k, v]) => `${esc(k)} (${v})`).join("; ")}` : ""}</div>
    <h3>Detector C incidents</h3>${html}
    ${C.suppressed.length ? `<div class="card"><h3>Suppressed chains (not escalated)</h3><div class="tw"><table class="data"><thead><tr><th>User</th><th>Window</th><th class="num">Score</th><th>Stages</th><th>Why not escalated</th></tr></thead><tbody>${C.suppressed.map(s => `<tr><td class="mono-s">${esc(s.user)}</td><td class="mono-s">${tstr(s.start)} → ${tshort(s.end)}</td><td class="num">${s.score}</td><td>${esc(s.stages.join(" + "))}</td><td class="help">${esc(s.reason)}</td></tr>`).join("")}</tbody></table></div></div>` : ""}
    <div class="grid g2"><div class="card"><h3><span class="tag A">A</span> Rule alerts</h3><div class="tw" style="max-height:340px"><table class="data"><thead><tr><th>Time</th><th>User</th><th>Rule</th><th>Reason</th></tr></thead><tbody>${A.alerts.map(a => `<tr><td class="mono-s">${tstr(a.time)}</td><td class="mono-s">${esc(a.user)}</td><td>${a.rule}</td><td class="help">${esc(a.reason)}</td></tr>`).join("") || `<tr><td colspan="4" class="help">None.</td></tr>`}</tbody></table></div></div>
    <div class="card"><h3><span class="tag B">B</span> Isolation Forest windows</h3><div class="tw" style="max-height:340px"><table class="data"><thead><tr><th>Window</th><th>User</th><th class="num">Score</th><th>Largest deviations</th></tr></thead><tbody>${B.alerts.map(a => `<tr><td class="mono-s">${tstr(a.window_start).slice(5, 16)}</td><td class="mono-s">${esc(a.user)}</td><td class="num">${a.score}</td><td class="help">${a.top_features.map(f => f.feature + " z=" + f.robust_z).join(", ")}</td></tr>`).join("") || `<tr><td colspan="4" class="help">None${B.info && B.info.trained_on ? "" : " (not enough baseline windows to train the model)"}.</td></tr>`}</tbody></table></div></div></div>`;
  // allow drill-down links ("open in log explorer") from custom incidents
  $("#cOut").onclick = e => { const b = e.target.closest("[data-logs]"); if (b) { S.run = d; S.logs.f = {user: b.dataset.logs, flag: "C"}; S.logs.page = 1; renderLogsShell(); show("logs"); loadLogs(); } };
}

/* -------------------------------------------------------------- methodology */
function renderMethod() {
  const D = S.schema.docs, cfg = S.run ? S.run.config : S.cfg;
  const w = [cfg.w1, cfg.w2, cfg.w3, cfg.w4, cfg.w5, cfg.w6];
  $("#tab-method").innerHTML = `
  <div class="page-head"><div><div class="crumb">Step 8 of 8</div><h2>Methodology &amp; criteria</h2>
    <p>The complete specification of what the system does, written so that every number on the other screens can be traced back to a definition here.</p></div></div>
  <div class="card"><h3>Research question</h3><div class="callout"><i>To what extent does a context-aware explainable log-correlation framework improve the detection of simulated multi-stage account-takeover activity - in terms of detection accuracy, false-positive rate, time to detection, alert reduction and explanation fidelity - compared with independent rule-based alerting and an unsupervised anomaly-detection baseline operating on synthetic security logs?</i></div></div>
  <div class="card"><h3>1 · Pipeline</h3><div class="pipe">${D.pipeline.map(s => `<div class="pstep done"><b>${esc(s.step)}</b><p>${esc(s.text)}</p></div>`).join("")}</div></div>
  <div class="card"><h3>2 · Threat model: the scenarios that are simulated</h3><p class="sub">Each scenario is injected after the baseline period with a ground-truth label. Attacker addresses use documentation-only IP ranges.</p>
    <div class="tw"><table class="data"><thead><tr><th>Scenario</th><th>Difficulty</th><th>Label</th><th>Event chain</th><th>What it tests</th></tr></thead><tbody>${D.scenarios.map(s => `<tr><td><b>${esc(s.name)}</b></td><td>${s.difficulty}</td><td><span class="chip ${s.label === "Attack" ? "gt" : "ctl"}">${s.label}</span></td><td class="help">${esc(s.chain)}</td><td class="help">${esc(s.tests)}</td></tr>`).join("")}</tbody></table></div>
    <div class="explain">Background activity also includes password typos, VPN days, late-night work, archive operations, new vendors and a nightly backup service account - the benign irregularities that make single-event rules noisy.</div></div>
  <div class="card"><h3>3 · Normalisation</h3><p>Four native log formats (authentication, file server, privilege management, network gateway) with different field names, timestamp formats (ISO-8601 vs. epoch) and boolean conventions are mapped to one schema. Invalid timestamps, missing users and unknown event types are rejected and counted; exact duplicates are removed. The full mapping table is on the Executive Summary after a run.</p></div>
  <div class="card"><h3>4 · Baseline learning</h3><p>Everything before the evaluation start is treated as attack-free. Per user the system learns: known source IPs, devices and countries; the working-hours range (1st-99th percentile of activity ±1 h); whether the user routinely performs admin actions; the largest 10-minute burst of file reads; the largest outbound transfer; and approved destinations (organisation-wide). Users with fewer than 8 baseline events are marked <b>cold-start</b> and receive relaxed novelty checks. Ground-truth labels are never used.</p></div>
  <div class="card"><h3><span class="tag A">A</span> 5 · Detector A - independent rules</h3><div class="tw"><table class="data"><thead><tr><th>Rule</th><th>Logic</th><th>Rationale</th><th>Weakness</th></tr></thead><tbody>${D.rules.map(r => `<tr><td><b>${r.id}</b> ${esc(r.name)}</td><td class="help">${esc(r.logic)}</td><td class="help">${esc(r.rationale)}</td><td class="help">${esc(r.weakness)}</td></tr>`).join("")}</tbody></table></div></div>
  <div class="card"><h3><span class="tag B">B</span> 6 · Detector B - Isolation Forest</h3><p>Events are grouped into per-user windows of ${cfg.if_window_min} minutes. Each window becomes a 13-dimensional vector. The model is trained on baseline windows only and flags later windows that are easy to isolate with random trees. Contamination (${cfg.if_contamination}) sets the threshold.</p>
    <div class="tw"><table class="data"><thead><tr><th>Feature</th><th>Definition</th><th>Captures</th></tr></thead><tbody>${D.if_features.map(f => `<tr><td><code>${f.name}</code></td><td class="help">${esc(f.meaning)}</td><td class="help">${esc(f.captures)}</td></tr>`).join("")}</tbody></table></div></div>
  <div class="card"><h3><span class="tag C">C</span> 7 · Detector C - multi-stage correlation</h3>
    <p>A per-user finite-state tracker observes the six stages below. Stages link only if the gap between consecutive stage events is at most the <b>chain window</b> (${cfg.chain_window_min} min); a longer gap restarts the chain.</p>
    <div class="tw"><table class="data"><thead><tr><th>Stage</th><th>Signal</th><th>Formal rule</th><th class="num">Weight</th><th>MITRE ATT&amp;CK</th></tr></thead><tbody>${D.stages.map((s, i) => `<tr><td><b>${s.id}</b> ${esc(s.name)}<div class="help">${esc(s.why)}</div></td><td class="help">${esc(s.signal)}</td><td class="mono-s" style="min-width:260px">${esc(s.logic)}</td><td class="num"><b>${w[i]}</b></td><td>${s.mitre.map(m => `<span class="chip mitre">${m.id}</span>`).join(" ")}<div class="help">${s.mitre.map(m => esc(m.name)).join("; ")}</div></td></tr>`).join("")}</tbody></table></div>
    <h4 style="margin-top:18px">Scoring formula</h4>
    <div class="defn"><span class="f">score = min(100, Σ stage weights × VPN-discount + order bonus + velocity bonus)</span>
      <p><b>Stage weight</b> - points for each distinct stage observed (current weights ${w.join(" / ")}). <b>VPN discount</b> - S2/S3 reached through the corporate VPN with no failed-login history are multiplied by ${cfg.vpn_discount}. <b>Order bonus</b> - ${cfg.order_bonus} points per consecutive pair of stages that occur in kill-chain order (at most 5 pairs counted). <b>Velocity bonus</b> - ${cfg.velocity_bonus} points when 3 or more stages fall within ${cfg.velocity_window_min} minutes.</p></div>
    <div class="defn"><span class="f">raise incident when score ≥ ${cfg.alert_threshold} AND distinct stages ≥ ${cfg.min_stages}</span>
      <p>Requiring several stages is the central design idea: no single loud signal can raise an incident, which is what suppresses false positives such as a late VPN login or a nightly backup.</p></div>
    <div class="defn"><h4>What explanations contain</h4><p>For every incident: the stage progression, the exact rule and evidence events behind each stage, a point-by-point score breakdown, a grouped event timeline, benign counter-evidence, ATT&amp;CK technique mapping, recommended containment/investigation/hardening actions, and - when ground truth exists - an evidence-fidelity check. Chains that fell short are listed as <b>suppressed</b> with the reason.</p></div></div>
  <div class="card"><h3>8 · Evaluation criteria</h3>${D.metrics.map(m => `<div class="defn"><h4>${esc(m.name)}</h4><span class="f">${esc(m.formula)}</span><p>${esc(m.meaning)}</p><p class="help"><b>Good value:</b> ${esc(m.good)}</p></div>`).join("")}
    <div class="defn"><h4>How an alert is matched to an attack</h4><p>An alert matches a ground-truth chain when it belongs to the same user and its evidence events overlap the chain's time span (±60 s). A chain is <i>detected</i> if at least one alert matches it; alerts matching no attack chain are <i>false positives</i> (including alerts on the benign control cases).</p></div></div>
  <div class="card"><h3>9 · Statistical analysis</h3>${statsDocs()}</div>
  <div class="card"><h3>10 · Limitations &amp; threats to validity</h3><ul style="margin:0 0 0 18px;padding:0">${D.limitations.map(l => `<li style="margin:6px 0">${esc(l)}</li>`).join("")}</ul></div>
  <div class="card"><h3>11 · Ethics</h3><p>${esc(D.ethics)}</p></div>
  <div class="card"><h3>12 · Glossary</h3><div class="grid g2">${D.glossary.map(g => `<div class="defn"><h4>${esc(g.term)}</h4><p class="help">${esc(g.meaning)}</p></div>`).join("")}</div></div>
  <div class="card flat"><h3>Key references</h3><ul class="help" style="margin:0 0 0 18px;padding:0;line-height:1.7">
    <li>Kent, K. and Souppaya, M. (2006) <i>Guide to Computer Security Log Management</i>, NIST SP 800-92.</li>
    <li>Liu, F.T., Ting, K.M. and Zhou, Z.-H. (2008) Isolation Forest. <i>IEEE ICDM</i>, pp. 413-422.</li>
    <li>Chandola, V., Banerjee, A. and Kumar, V. (2009) Anomaly detection: a survey. <i>ACM Computing Surveys</i>, 41(3).</li>
    <li>Sommer, R. and Paxson, V. (2010) Outside the closed world: on using machine learning for network intrusion detection. <i>IEEE S&amp;P</i>.</li>
    <li>Strom, B.E. et al. (2018) <i>MITRE ATT&amp;CK: Design and Philosophy</i>. The MITRE Corporation.</li>
    <li>Sharafaldin, I., Lashkari, A.H. and Ghorbani, A.A. (2018) Toward generating a new intrusion detection dataset (CIC-IDS2017). <i>ICISSP</i>.</li>
    <li>Lundberg, S.M. and Lee, S.-I. (2017) A unified approach to interpreting model predictions. <i>NeurIPS</i>; Ribeiro, M.T. et al. (2016) "Why should I trust you?" <i>KDD</i>.</li></ul></div>`;
}

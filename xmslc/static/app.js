/* XMSLC workbench - core: state, configure/run, summary, incidents, comparison, log explorer. */
"use strict";
const S = {schema: null, cfg: {}, run: null, sel: null, logs: {page: 1, view: "normalised", f: {}}, busy: false};

async function api(path, body) {
  const opt = body === undefined ? {} : {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)};
  const r = await fetch(path, opt);
  let j = {};
  try { j = await r.json(); } catch (e) { /* non-JSON error body */ }
  if (!r.ok) throw new Error(j.error || `Request failed (${r.status})`);
  return j;
}
function toast(msg, ok) {
  const t = $("#toast");
  t.textContent = msg; t.className = "toast" + (ok ? " ok" : ""); t.style.display = "block";
  clearTimeout(toast.h); toast.h = setTimeout(() => t.style.display = "none", ok ? 2500 : 7000);
}
function show(tab) {
  $$(".tab").forEach(t => t.classList.toggle("active", t.id === "tab-" + tab));
  $$(".nav").forEach(n => n.classList.toggle("active", n.dataset.tab === tab));
  window.scrollTo({top: 0});
  if (tab === "logs" && S.run) loadLogs();
}
$("#nav").addEventListener("click", e => { const b = e.target.closest(".nav"); if (b) show(b.dataset.tab); });

const PRESETS = [
  ["Thesis default", {}, "Balanced organisation of 30 users, 7 days, moderate noise and stealth."],
  ["Quick demo", {n_users: 12, days: 5, baseline_days: 2, n_credential_stuffing: 2, n_stolen_session: 2, n_insider: 2, n_slow_exfil: 1, n_benign_travel: 2}, "Small and fast; good for a first look."],
  ["Stealthy attacker", {stealth: 0.85}, "Attackers slow down and skip steps - stresses recall."],
  ["Noisy network", {noise_level: 1.0, n_users: 60}, "Lots of benign irregularities - stresses false positives."],
  ["Incomplete logs", {drop_rate: 0.3}, "30% of raw records are lost before analysis."],
  ["Attack-heavy", {n_credential_stuffing: 8, n_stolen_session: 8, n_insider: 8, n_slow_exfil: 6, n_benign_travel: 6, n_users: 50}, "Many attacks; shows consolidation and ranking."],
];

/* ---------------------------------------------------------------- configure */
function renderConfig() {
  const groups = {};
  S.schema.params.forEach(p => (groups[p.group] = groups[p.group] || {label: p.group_label, items: []}).items.push(p));
  const tag = {gen: "G", A: "A", B: "B", C: "C"};
  const paramHTML = p => `<div class="param" id="row_${p.key}">
      <div class="top"><label for="n_${p.key}">${esc(p.label)}</label><span class="def">default ${p.default}</span></div>
      <div class="ctrl"><input type="range" id="r_${p.key}" min="${p.min}" max="${p.max}" step="${p.step}" value="${S.cfg[p.key]}">
      <input type="number" id="n_${p.key}" min="${p.min}" max="${p.max}" step="${p.step}" value="${S.cfg[p.key]}"></div>
      <div class="h">${esc(p.help)}</div>${p.effect ? `<div class="e">${esc(p.effect)}</div>` : ""}</div>`;
  $("#tab-config").innerHTML = `
    <div class="page-head"><div><div class="crumb">Step 1 of 8</div><h2>Configure the experiment and generate the logs</h2>
      <p>Every value below is a live input. Press <b>Generate logs &amp; run analysis</b> and the backend will invent a fictional organisation, write its logs in four native formats, normalise them, learn each user's baseline, and run three detectors. Every setting explains itself underneath.</p></div>
      <button class="btn primary" id="runBtn"><span>Generate logs &amp; run analysis</span></button></div>
    <div class="card"><h3>Quick presets</h3><div class="preset-row" id="presets">${PRESETS.map((p, i) => `<button class="chipbtn" data-i="${i}" title="${esc(p[2])}">${esc(p[0])}</button>`).join("")}</div>
      <div class="help" id="presetHelp">Presets only change the inputs; you can still adjust any value afterwards.</div></div>
    ${Object.entries(groups).map(([g, v], gi) => `<details class="grp" ${gi < 1 ? "open" : ""}><summary><span class="tag ${tag[g]}">${g === "gen" ? "DATA" : g}</span>${esc(v.label)}</summary>
      <div><div class="params">${v.items.map(paramHTML).join("")}</div></div></details>`).join("")}
    <div class="card"><h3>What happens when you press run</h3><p class="sub">The pipeline below mirrors the workflow diagram in the dissertation. After a run, each step shows how long it took.</p>
      <div class="pipe" id="pipe">${S.schema.docs.pipeline.map((s, i) => `<div class="pstep" id="ps${i}"><span class="ms"></span><b>${esc(s.step)}</b><p>${esc(s.text)}</p></div>`).join("")}</div></div>`;
  S.schema.params.forEach(p => {
    const r = $("#r_" + p.key), n = $("#n_" + p.key);
    const set = v => { S.cfg[p.key] = p.kind === "int" ? Math.round(+v) : +v; r.value = n.value = S.cfg[p.key]; };
    r.addEventListener("input", () => set(r.value));
    n.addEventListener("change", () => set(Math.min(p.max, Math.max(p.min, +n.value || p.default))));
  });
  $("#presets").addEventListener("click", e => {
    const b = e.target.closest("[data-i]"); if (!b) return;
    const pr = PRESETS[+b.dataset.i];
    const keep = {seed: S.cfg.seed};
    S.cfg = {...defaults(), ...keep, ...pr[1]};
    renderConfig(); $("#presetHelp").innerHTML = `<b>${esc(pr[0])}:</b> ${esc(pr[2])}`;
  });
  $("#runBtn").addEventListener("click", runAnalysis);
  if (S.run) markPipe(S.run.steps);
}
function defaults() { const d = {}; S.schema.params.forEach(p => d[p.key] = p.default); return d; }

function markPipe(steps) {
  const ms = n => steps.filter(s => n.some(x => s.step.startsWith(x))).reduce((a, s) => a + s.ms, 0);
  const map = [["Generate"], ["Normalise"], ["Learn"], ["Detector"], ["Detector C"], ["Evaluate"]];
  [0, 1, 2, 3, 4, 5].forEach(i => {
    const el = $("#ps" + i); if (!el) return;
    el.className = "pstep done";
    $(".ms", el).textContent = i === 4 ? "in C" : ms(map[i]).toFixed(0) + " ms";
  });
}

async function runAnalysis() {
  if (S.busy) return;
  S.busy = true;
  const btn = $("#runBtn"); btn.disabled = true; btn.innerHTML = `<span class="spin"></span><span>Running pipeline...</span>`;
  let i = 0; const tick = setInterval(() => { $$(".pstep").forEach((e, k) => e.className = "pstep" + (k < i ? " done" : k === i ? " run" : "")); i = Math.min(i + 1, 5); }, 170);
  try {
    S.run = await api("/api/run", {config: S.cfg});
    S.sel = null; S.logs = {page: 1, view: "normalised", f: {}};
    clearInterval(tick); markPipe(S.run.steps);
    $("#runBadge").className = "badge live"; $("#runBadge").textContent = `Run ${S.run.run_id} · ${S.run.dataset.events.toLocaleString()} events`;
    $$(".nav").forEach(n => { if (["summary", "incidents", "compare", "logs"].includes(n.dataset.tab)) n.classList.add("has"); });
    renderSummary(); renderIncidents(); renderCompare(); renderLogsShell(); renderMethod();
    toast("Analysis complete - showing the executive summary.", true);
    show("summary");
  } catch (e) { clearInterval(tick); $$(".pstep").forEach(x => x.className = "pstep"); toast(e.message); }
  finally { S.busy = false; btn.disabled = false; btn.innerHTML = "<span>Generate logs &amp; run analysis</span>"; }
}

/* ------------------------------------------------------------------ summary */
const HIGHER = ["recall", "precision", "f1", "fidelity"], LOWER = ["fpr", "mttd_min", "alerts", "control_alerts", "alerts_per_attack"];
function bestOf(key, M) {
  const vals = ["A", "B", "C"].map(k => M[k][key]);
  const ok = vals.filter(v => v != null); if (!ok.length) return -1;
  const tgt = HIGHER.includes(key) ? Math.max(...ok) : Math.min(...ok);
  return vals.findIndex(v => v === tgt);
}
function metricSub(key, m) {
  switch (key) {
    case "recall": return `${m.detected_chains} of ${m.attack_chains} attacks`;
    case "precision": return `${m.detected_chains} found, ${m.fp_alerts} false alerts`;
    case "fpr": return `${m.fp_user_days} of ${m.benign_user_days} user-days`;
    case "alerts": return `${m.tp_alerts} on attacks, ${m.fp_alerts} false`;
    case "control_alerts": return `${m.control_flagged} of ${m.control_chains} control cases touched`;
    default: return "";
  }
}

function renderSummary() {
  const R = S.run, D = R.dataset, M = R.metrics, el = $("#tab-summary");
  const nAtk = M ? M.C.attack_chains : 0, nCtl = M ? M.C.control_chains : 0;
  const kpi = (cls, lab, val, sub) => `<div class="kpi ${cls}"><div class="lab">${lab}</div><div class="val">${val}</div><p class="sub">${sub}</p></div>`;
  const dayLabels = R.per_day.A.map((_, i) => "D" + (i + 1));
  const evalDay = Math.round((new Date(D.eval_start.replace(" ", "T")) - new Date(R.day0.replace(" ", "T"))) / 864e5);
  el.innerHTML = `
  <div class="page-head"><div><div class="crumb">Step 2 of 8</div><h2>Executive summary</h2>
    <p>What was generated, what each detector reported, and how the three methods compare against the hidden ground truth.</p></div>
    <div><button class="btn sm" id="expReport">Download full report (JSON)</button></div></div>

  <div class="card"><h3>Key findings <span class="tag G">auto-generated from this run</span></h3>
    <ul style="margin:6px 0 0 18px;padding:0">${R.findings.map(f => `<li style="margin:6px 0">${esc(f)}</li>`).join("")}</ul>
    <div class="callout warn"><b>Read with care:</b> everything here is computed on synthetic logs. The comparison is fair (all three detectors see identical events and the same baseline) but it is not a prediction of real-world performance - see Methodology &amp; Criteria for limitations.</div></div>

  <div class="grid g6" style="margin-bottom:18px">
    ${kpi("", "Events analysed", D.events.toLocaleString(), `${D.baseline_events.toLocaleString()} used to learn baselines, ${D.eval_events.toLocaleString()} analysed for threats.`)}
    ${kpi("", "Users", D.users, `${D.profiled_users} with a learned profile${D.cold_start_users ? `, ${D.cold_start_users} cold-start` : ""}.`)}
    ${kpi("", "Ground truth", nAtk + " + " + nCtl, `${nAtk} real attack chains and ${nCtl} benign look-alike (control) cases hidden in the data.`)}
    ${kpi("A", "A: rule alerts", R.detectors.A.total, "Independent single-event alerts an analyst would have to triage.")}
    ${kpi("B", "B: IF alerts", R.detectors.B.total, "Time windows flagged as statistically unusual.")}
    ${kpi("C", "C: incidents", R.detectors.C.total, "Correlated, scored, explained incidents (one per attack chain ideally).")}
  </div>

  ${M ? `
  <div class="grid g2">
    <div class="card"><h3>Detection quality</h3><p class="sub">Higher is better for all four bars except false-positive rate.</p>
      ${legend(["A", "B", "C"].map(k => ({name: DNAME[k], color: COL[k]})))}
      ${barChart({cats: ["Recall", "Precision", "F1-score", "False-positive rate"], series: ["A", "B", "C"].map(k => ({name: DNAME[k], color: COL[k], values: [M[k].recall, M[k].precision, M[k].f1, M[k].fpr]})), fmtv: v => (v * 100).toFixed(0) + "%"})}
      <div class="explain"><b>How to read:</b> <b>Recall</b> = share of real attacks noticed. <b>Precision</b> = share of analyst effort that found a real attack. <b>F1</b> balances both. <b>False-positive rate</b> = share of innocent user-days that raised a false alert (lower is better). A detector that alerts on everything has high recall but terrible precision and FPR.</div></div>
    <div class="card"><h3>Analyst workload</h3><p class="sub">Alerts raised in the evaluation period, split by whether they relate to a real attack.</p>
      ${legend([{name: "Alerts on real attacks", color: "#22c55e"}, {name: "False alerts", color: "#ef4444"}])}
      ${barChart({cats: ["A  rules", "B  Isolation Forest", "C  correlation"], max: Math.max(1, ...["A", "B", "C"].map(k => M[k].alerts)), fmtv: v => Math.round(v), series: [{name: "Alerts on attacks", color: "#22c55e", values: ["A", "B", "C"].map(k => M[k].tp_alerts)}, {name: "False alerts", color: "#ef4444", values: ["A", "B", "C"].map(k => M[k].fp_alerts)}]})}
      <div class="explain"><b>How to read:</b> This is alert fatigue made visible. Rules and anomaly windows fragment one attack into many alerts; the correlator's goal is one incident per attack with few false ones.</div></div>
  </div>

  <div class="card"><h3>Every evaluation criterion, explained</h3><p class="sub">The best value in each row is highlighted. Each row defines the criterion, shows the formula, and tells you how to interpret it.</p>
    <div class="tw"><table class="data"><thead><tr><th style="min-width:330px">Criterion - what it means</th><th>Formula</th><th class="num">A Rules</th><th class="num">B Isolation Forest</th><th class="num">C Correlation</th></tr></thead><tbody>
    ${S.schema.docs.metrics.map(d => { const b = bestOf(d.key, M); return `<tr><td><b>${esc(d.name)}</b><div class="help">${esc(d.meaning)}</div><div class="help"><em>${esc(d.good)}</em></div></td><td class="mono-s" style="min-width:210px">${esc(d.formula)}</td>
      ${["A", "B", "C"].map((k, i) => `<td class="num ${b === i ? "best" : ""}">${fmt(M[k][d.key], d.key)}<div class="help">${esc(metricSub(d.key, M[k]))}</div></td>`).join("")}</tr>`; }).join("")}
    </tbody></table></div></div>

  <div class="card"><h3>Detection by attack scenario</h3><p class="sub">Each cell shows chains detected / chains injected. For the benign control row, <b>lower is better</b> - flagging a harmless traveller is a false positive.</p>
    <div class="tw"><table class="data"><thead><tr><th>Scenario</th><th>Modelled chain</th><th class="num">A</th><th class="num">B</th><th class="num">C</th></tr></thead><tbody>
    ${S.schema.docs.scenarios.map(sc => { const tot = M.C.by_scenario[sc.id]; if (!tot || !tot.total) return ""; const ctl = sc.label !== "Attack";
      return `<tr><td><b>${esc(sc.name)}</b> <span class="chip ${ctl ? "ctl" : "gt"}">${esc(sc.label)}</span><div class="help">${esc(sc.tests)}</div></td><td class="help" style="min-width:240px">${esc(sc.chain)}</td>
      ${["A", "B", "C"].map(k => { const v = M[k].by_scenario[sc.id] || {detected: 0, total: 0}, r = v.total ? v.detected / v.total : 0, good = ctl ? 1 - r : r;
        return `<td class="num" style="color:${good >= .8 ? "#7ee2a1" : good >= .5 ? "#f3d36b" : "#ff9a9a"};font-weight:700">${v.detected} / ${v.total}</td>`; }).join("")}</tr>`; }).join("")}
    </tbody></table></div></div>

  <div class="card"><h3>Ground-truth attack chains and who caught them</h3><p class="sub">The hidden answer key. "Delay" is minutes between the first malicious event and the first alert. Misses by detector C are explained.</p>
    <div class="tw"><table class="data"><thead><tr><th>ID</th><th>Scenario</th><th>User</th><th>Start</th><th class="num">Events</th><th>Planned stages</th><th>A</th><th>B</th><th>C</th></tr></thead><tbody>
    ${R.chains.map(c => `<tr><td class="mono-s">${c.chain_id}</td><td>${esc(scenName(c.scenario))}<div class="help">${c.label === "attack" ? "attack" : "control (should NOT alert)"}</div></td><td class="mono-s">${esc(c.user)}</td><td class="mono-s">${tstr(c.start)}</td><td class="num">${c.n_events}</td><td class="mono-s">${c.planned_stages.join(" ") || "-"}</td>
      ${["A", "B", "C"].map(k => { const d = c.detected[k]; const ctl = c.label !== "attack";
        return `<td>${d.detected ? `<span class="chip ${ctl ? "fp" : "tp"}">${ctl ? "FLAGGED (FP)" : "CAUGHT"}</span><div class="help">${d.delay_min} min · ${d.n_alerts} alert${d.n_alerts > 1 ? "s" : ""}</div>` : `<span class="chip ${ctl ? "tp" : "fp"}">${ctl ? "QUIET (good)" : "MISSED"}</span>`}</td>`; }).join("")}</tr>
      ${c.miss_reason_c ? `<tr><td></td><td colspan="8" class="help"><b style="color:#ffb070">Why C missed ${c.chain_id}:</b> ${esc(c.miss_reason_c)}</td></tr>` : ""}`).join("")}
    </tbody></table></div></div>` : ""}

  <div class="grid g2">
    <div class="card"><h3>When do events happen?</h3><p class="sub">Events per hour of day. Red = events belonging to injected attacks; blue = normal activity.</p>${hourChart(R.hours)}
      <div class="explain"><b>Why it matters:</b> attacks cluster outside working hours, which is why single time-of-day rules fire - and why they also fire on every legitimate late worker.</div></div>
    <div class="card"><h3>Alerts per day</h3><p class="sub">Days D1-D${R.per_day.A.length}; the first ${evalDay} are the baseline learning period, so no alerts are raised then.</p>
      ${legend(["A", "B", "C"].map(k => ({name: DNAME[k], color: COL[k]})))}
      ${barChart({cats: dayLabels, max: Math.max(1, ...["A", "B", "C"].flatMap(k => R.per_day[k])), fmtv: v => Math.round(v), height: 200, series: ["A", "B", "C"].map(k => ({name: DNAME[k], color: COL[k], values: R.per_day[k]}))})}</div>
  </div>

  <div class="grid g2">
    <div class="card"><h3>Dataset composition</h3><p class="sub">Event types after normalisation (${D.events.toLocaleString()} events, ${D.attack_events} belonging to attacks).</p>
      <div class="tw"><table class="data"><thead><tr><th>Event type</th><th class="num">Count</th><th>Source log</th></tr></thead><tbody>
      ${Object.entries(D.types).sort((a, b) => b[1] - a[1]).map(([t, n]) => `<tr><td><span class="et ${t}">${t}</span></td><td class="num">${n.toLocaleString()}</td><td class="help">${{login_success: "auth", login_failure: "auth", file_read: "file server", admin_action: "privilege mgmt", priv_change: "privilege mgmt", outbound_transfer: "network gateway"}[t]}</td></tr>`).join("")}
      </tbody></table></div>
      <div class="explain">Period ${tstr(D.start).slice(0, 10)} to ${tstr(D.end).slice(0, 10)}. Baseline = before ${tstr(D.eval_start)}; detection runs after.</div></div>
    <div class="card"><h3>Normalisation &amp; data-quality report</h3><p class="sub">Four differently-formatted sources are mapped to one schema.</p>
      <div class="grid g3" style="margin-bottom:10px"><div class="kpi"><div class="lab">Records in</div><div class="val" style="font-size:22px">${R.quality.records_in.toLocaleString()}</div></div><div class="kpi"><div class="lab">Accepted</div><div class="val" style="font-size:22px">${R.quality.records_ok.toLocaleString()}</div></div><div class="kpi"><div class="lab">Rejected / dup</div><div class="val" style="font-size:22px">${R.quality.records_rejected + R.quality.duplicates_removed}</div></div></div>
      <div class="help">By source: ${Object.entries(R.quality.by_source).map(([k, v]) => `<b>${k}</b> ${v.toLocaleString()}`).join(" · ")}${R.config.drop_rate > 0 ? ` · <b style="color:#f3d36b">${(R.config.drop_rate * 100).toFixed(0)}% of records were deliberately dropped (robustness test)</b>` : ""}</div>
      <details style="margin-top:10px"><summary class="help" style="cursor:pointer">Show field mapping per source</summary>
      <div class="tw" style="margin-top:8px"><table class="data"><thead><tr><th>Common field</th>${["auth", "file", "priv", "net"].map(s => `<th>${s}</th>`).join("")}</tr></thead><tbody>
      ${R.quality.schema.map(f => `<tr><td><code>${f.field}</code><div class="help">${esc(f.meaning)}</div></td>${["auth", "file", "priv", "net"].map(s => `<td class="mono-s">${esc(R.quality.field_maps[s][f.field] || "-")}</td>`).join("")}</tr>`).join("")}
      </tbody></table></div></details></div>
  </div>
  <div class="card flat"><h3>Pipeline timings</h3><div class="help">${R.steps.map(s => `${esc(s.step)}: <b>${s.ms} ms</b>`).join(" &nbsp;·&nbsp; ")}</div></div>`;
  $("#expReport").onclick = () => location.href = `/api/run/${R.run_id}/export?fmt=report`;
}

/* ---------------------------------------------------------------- incidents */
function gtChip(inc) {
  if (!S.run.chains || !S.run.chains.length) return "";
  const hits = S.run.chains.filter(c => (inc.matched || []).includes(c.chain_id));
  if (!hits.length) return `<span class="chip fp">FALSE POSITIVE</span>`;
  return hits.some(c => c.label === "attack") ? `<span class="chip tp">TRUE POSITIVE</span>` : `<span class="chip fp">FALSE POSITIVE (benign control)</span>`;
}
function stageLadder(inc) {
  const names = S.schema.stage_names, by = {};
  inc.stages.forEach(s => by[s.sid] = s);
  return `<div class="ladder">${[1, 2, 3, 4, 5, 6].map(n => { const s = by[n];
    return `<div class="lstep ${s ? "on" : ""} ${s && s.discounted ? "disc" : ""}" title="${esc(s ? s.signal : names[n])}"><span class="n">S${n}</span><b>${esc(names[n])}</b><small>${s ? `+${s.points} pts · ${tshort(s.time)}` : "not observed"}</small></div>`; }).join("")}</div>`;
}
function incidentHTML(inc, gt) {
  const tlClass = t => t === "login_failure" ? "fail" : ["admin_action", "priv_change", "outbound_transfer"].includes(t) ? "warn" : "";
  const chains = gt ? S.run.chains.filter(c => (inc.matched || []).includes(c.chain_id)) : [];
  return `
  <div class="card"><div style="display:flex;gap:22px;align-items:center;flex-wrap:wrap">
    <div>${gauge(inc.score, inc.severity)}</div>
    <div style="flex:1;min-width:260px"><div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><h3 style="margin:0">${esc(inc.incident_id)} · ${esc(inc.user)}</h3>${sevChip(inc.severity)}${gt ? gtChip(inc) : ""}</div>
      <p style="margin:6px 0 0"><b>${esc(inc.assessment)}</b></p>
      <div class="help">Alert raised ${tstr(inc.time)} · first correlated signal ${tstr(inc.first_event_time)} · <b>${inc.time_to_alert_min} min</b> to alert · ${inc.n_stages} stages · ${inc.evidence_count} evidence events</div></div></div>
    <div class="callout"><b>Analyst narrative.</b> ${esc(inc.narrative)}</div></div>

  <div class="card"><h3>1 · Attack-stage progression</h3><p class="sub">The six stages of the modelled account-takeover kill chain. Lit stages were observed for this account within the chain window; amber = weight reduced because the session came through the corporate VPN.</p>${stageLadder(inc)}
    <div class="explain"><b>Why this is more than a list of alerts:</b> the detector is not counting alarms. It follows one account through ordered stages and only raises an incident when <b>${S.run.config.min_stages}+ different stages</b> accumulate a score of at least <b>${S.run.config.alert_threshold}</b>.</div></div>

  <div class="card"><h3>2 · How the risk score was calculated</h3><p class="sub">Every point is traceable. Final score = stage weights + order bonus + velocity bonus, capped at 100 (raw total ${inc.raw_score}).</p>
    ${stackedBar(inc.score_breakdown, inc.raw_score)}
    <div class="tw"><table class="data"><thead><tr><th>Component</th><th class="num">Points</th><th>Calculation</th></tr></thead><tbody>
      ${inc.score_breakdown.map(b => `<tr><td>${esc(b.term)}</td><td class="num"><b>${b.points}</b></td><td class="help">${esc(b.formula)}</td></tr>`).join("")}
      <tr><td><b>Total (capped at 100)</b></td><td class="num"><b>${inc.score}</b></td><td class="help">Alert threshold ${S.run.config.alert_threshold}; score when the alert fired: ${inc.score_at_alert}.</td></tr></tbody></table></div>
    <div class="explain"><b>Order bonus</b> rewards realistic attack progression (e.g. failed logins before a success, collection before exfiltration). <b>Velocity bonus</b> rewards fast, automated chains.</div></div>

  <div class="card"><h3>3 · Event timeline</h3><p class="sub">The evidence events that formed the chain, in order. Consecutive similar events are grouped.</p>
    <div class="tl">${inc.timeline.map(t => `<div class="it ${tlClass(t.type)}"><div class="t">${tstr(t.start)}${t.count > 1 ? " → " + tshort(t.end) : ""} ${t.stages.map(s => `<span class="chip mitre">S${s}</span>`).join(" ")}</div><div class="s"><span class="et ${t.type}">${t.type}</span> ${esc(t.summary)}</div></div>`).join("")}</div></div>

  <div class="card"><h3>4 · Why each stage fired</h3><p class="sub">For every stage: what the detector looks for, the exact rule, the evidence found in this account's logs, and the MITRE ATT&amp;CK techniques it maps to.</p>
    ${inc.stages.map(s => `<div class="stagecard ${s.discounted ? "disc" : ""}"><h4>${esc(s.id)} · ${esc(s.name)} <span class="chip ${s.discounted ? "medium" : "C"}">+${s.points} pts${s.discounted ? " (VPN discount)" : ""}</span><span class="help mono-s" style="margin-left:auto">${tstr(s.time)}</span></h4>
      <dl class="kv"><dt>What it detects</dt><dd>${esc(s.signal)}</dd><dt>Why it matters</dt><dd>${esc(s.why)}</dd><dt>Formal rule</dt><dd class="mono-s">${esc(s.logic)}</dd>
      <dt>Evidence in this log</dt><dd><ul style="margin:0 0 0 16px;padding:0">${s.reasons.map(r => `<li>${esc(r)}</li>`).join("")}</ul><span class="help">${s.evidence_count} supporting event(s)${s.evidence_sample.length ? " · e.g. ids " + s.evidence_sample.slice(0, 5).join(", ") : ""}</span></dd>
      <dt>ATT&amp;CK</dt><dd>${s.mitre.map(m => `<span class="chip mitre" title="${esc(m.name)}">${esc(m.id)} ${esc(m.name)}</span>`).join(" ")}</dd></dl></div>`).join("")}</div>

  <div class="grid g2"><div class="card"><h3>5 · What argues against compromise?</h3><p class="sub">Benign signals found for this account. A trustworthy explanation shows both sides.</p>
      ${inc.counter_evidence.length ? `<ul style="margin:0 0 0 18px;padding:0">${inc.counter_evidence.map(c => `<li style="margin:5px 0">${esc(c)}</li>`).join("")}</ul>` : `<div class="help">No benign signals were found - every observed signal points towards compromise.</div>`}</div>
    <div class="card"><h3>6 · Recommended response</h3><p class="sub">Ordered by urgency; each action is tied to the stage that justifies it.</p>
      ${inc.actions.map(a => `<div class="act"><div><span class="chip ${a.category === "Containment" ? "critical" : a.category === "Investigation" ? "medium" : "low"}">${a.category}</span></div><div>${esc(a.action)}<small>because ${esc(a.because)}</small></div></div>`).join("")}</div></div>
  ${gt ? `<div class="card"><h3>7 · Ground-truth check <span class="tag G">research evaluation only</span></h3>${chains.length ? chains.map(c => {
      const d = c.detected.C; return `<dl class="kv"><dt>Matched chain</dt><dd>${c.chain_id} - ${esc(scenName(c.scenario))} (${c.label === "attack" ? "real attack" : "benign control"}) on <span class="mono-s">${esc(c.user)}</span></dd>
      <dt>Planned stages</dt><dd class="mono-s">${c.planned_stages.join(" ") || "none (benign)"}</dd>
      <dt>Evidence fidelity</dt><dd>precision ${pct(d.evidence_precision)} · recall ${pct(d.evidence_recall)} · F1 ${pct(d.evidence_f1)} <span class="help">(share of cited events that really belong to the attack / share of attack events that were cited)</span></dd>
      <dt>Rules (A) saw</dt><dd>${c.detected.A.n_alerts} separate alerts</dd><dt>Isolation Forest (B) saw</dt><dd>${c.detected.B.n_alerts} flagged window(s)</dd></dl>`; }).join("<hr style='border:0;border-top:1px solid var(--line)'>") : `<div class="help">This incident does not overlap any injected chain: it is a <b>false positive</b>. Review its stages above to see which benign behaviours combined to look like an attack - this is the error analysis the dissertation should discuss.</div>`}</div>` : ""}
  <div><button class="btn sm" data-logs="${esc(inc.user)}">Open this user's evidence in the Log Explorer</button></div>`;
}

function renderIncidents() {
  const R = S.run, C = R.detectors.C, el = $("#tab-incidents");
  if (!C.incidents.length && !C.suppressed.length) {
    el.innerHTML = `<div class="page-head"><div><div class="crumb">Step 3 of 8</div><h2>Incident investigation</h2></div></div><div class="empty"><b>Detector C raised no incidents</b>No account accumulated enough correlated stages. Try lowering the alert threshold, or add attacks in the configuration.</div>`; return;
  }
  if (!S.sel && C.incidents.length) S.sel = C.incidents.slice().sort((a, b) => b.score - a.score)[0].incident_id;
  el.innerHTML = `<div class="page-head"><div><div class="crumb">Step 3 of 8</div><h2>Incident investigation</h2>
    <p>Detector C's output. Select an incident to see the stage-by-stage reasoning, score breakdown, benign counter-evidence, ATT&amp;CK mapping and recommended response.</p></div></div>
    <div class="split"><div><div class="tabs"><button class="on" data-l="inc">Incidents (${C.incidents.length})</button><button data-l="sup">Suppressed (${C.suppressed.length})</button></div>
      <div class="inc-list" id="incList"></div></div><div id="incDetail"></div></div>`;
  const draw = which => {
    $("#incList").innerHTML = which === "inc" ? C.incidents.slice().sort((a, b) => b.score - a.score).map(i => `<div class="inc ${i.incident_id === S.sel ? "sel" : ""}" data-id="${i.incident_id}"><div class="r1"><b>${esc(i.user)}</b><span class="score-pill" style="color:${{critical: "#ff8a8a", high: "#ffb070", medium: "#f3d36b", low: "#8fd3f8"}[i.severity]}">${i.score}</span></div>
        <div class="r2">${i.incident_id} · ${sevChip(i.severity)} ${R.chains.length ? gtChip(i) : ""}</div><div class="r2">${i.stage_ids.map(n => "S" + n).join(" → ")} · ${tstr(i.time).slice(5, 16)}</div></div>`).join("")
      : (C.suppressed.length ? C.suppressed.map(s => `<div class="inc" style="cursor:default"><div class="r1"><b>${esc(s.user)}</b><span class="score-pill" style="color:var(--dim)">${s.score}</span></div><div class="r2">${s.stages.join(" + ")}</div><div class="r2">${esc(s.reason)}</div>${(s.matched || []).length ? `<div class="r2"><span class="chip ctl">overlaps ${s.matched.join(", ")}</span></div>` : ""}</div>`).join("")
        : `<div class="help">No near-miss chains.</div>`);
  };
  draw("inc");
  $$(".tabs button", el).forEach(b => b.onclick = () => { $$(".tabs button", el).forEach(x => x.classList.toggle("on", x === b)); draw(b.dataset.l);
    if (b.dataset.l === "sup") $("#incDetail").innerHTML = `<div class="card"><h3>Suppressed chains</h3><p>These chains reached at least two stages but were <b>not</b> escalated. They explain why the detector stays quiet on benign-but-unusual behaviour (for example a traveller on VPN). Each shows its score and exactly why it fell short. This transparency about <em>non-alerts</em> is part of the explainability goal.</p></div>`;
    else showInc(S.sel); });
  el.onclick = e => {
    const c = e.target.closest(".inc[data-id]"); if (c) { S.sel = c.dataset.id; $$(".inc", el).forEach(x => x.classList.toggle("sel", x === c)); showInc(S.sel); }
    const b = e.target.closest("[data-logs]"); if (b) { S.logs.f = {user: b.dataset.logs, flag: "C"}; S.logs.page = 1; renderLogsShell(); show("logs"); }
  };
  if (C.incidents.length) showInc(S.sel);
}
function showInc(id) { const inc = S.run.detectors.C.incidents.find(i => i.incident_id === id); if (inc) $("#incDetail").innerHTML = incidentHTML(inc, true); }

/* --------------------------------------------------------------- comparison */
const DET_DOC = {
  A: ["Independent rule-based alerting", "Seven static rules (R1-R7) each inspect single events or one short counter. No memory between rules, no per-user baseline. This is how a basic SIEM works.",
    "Strength: simple, fast, catches loud attacks. Weakness: one attack becomes many unrelated alerts; static thresholds fire on backups, travel and late work.", "A"],
  B: ["Isolation Forest anomaly detection", "An unsupervised model trained on the baseline period scores 30-minute per-user windows described by 13 numeric features. Windows that are easy to isolate are flagged.",
    "Strength: no hand-written rules; can catch unusual behaviour. Weakness: it says <i>that</i> a window is odd but not <i>why</i>; the feature deviations shown are only a post-hoc approximation.", "B"],
  C: ["Multi-stage correlation (proposed)", "A per-user finite-state tracker follows six attack stages relative to the user's own baseline, links them within a sliding window, scores the chain and attaches evidence, ATT&CK mapping and response actions.",
    "Strength: consolidates many weak signals into one explained incident with few false positives. Weakness: only recognises modelled stages; deliberately slow or off-model attacks can slip through.", "C"],
};
function renderCompare() {
  const R = S.run, M = R.metrics, cfg = R.config, el = $("#tab-compare");
  const params = {
    A: [["Failed-login threshold", `${cfg.rule_fail_threshold} in ${cfg.rule_fail_window_min} min`], ["Bulk file reads", `${cfg.rule_bulk_files} in ${cfg.rule_bulk_window_min} min`], ["Outbound limit", cfg.rule_bytes_mb + " MB"], ["Business hours", `${cfg.business_start}:00-${cfg.business_end}:00`]],
    B: [["Window", cfg.if_window_min + " min"], ["Expected anomaly share", cfg.if_contamination], ["Trees", cfg.if_trees], ["Trained on", (R.detectors.B.info.trained_on || 0) + " baseline windows"]],
    C: [["Chain window", cfg.chain_window_min + " min"], ["Alert threshold", cfg.alert_threshold + " / 100"], ["Minimum stages", cfg.min_stages], ["Stage weights", [cfg.w1, cfg.w2, cfg.w3, cfg.w4, cfg.w5, cfg.w6].join(" / ")]],
  };
  const atk = R.chains.filter(c => c.label === "attack");
  el.innerHTML = `<div class="page-head"><div><div class="crumb">Step 4 of 8</div><h2>Detector comparison</h2>
    <p>The same events were given to three detectors. Here is how each one works, the parameters it ran with, what it reported for one chosen attack, and every alert it raised.</p></div></div>
    <div class="grid g3">${["A", "B", "C"].map(k => `<div class="card" style="border-top:3px solid ${COL[k]}"><h3><span class="tag ${k}">${k}</span>${esc(DET_DOC[k][0])}</h3><p>${DET_DOC[k][1]}</p><p class="help">${DET_DOC[k][2]}</p>
      <dl class="kv">${params[k].map(p => `<dt>${esc(p[0])}</dt><dd>${esc(p[1])}</dd>`).join("")}${M ? `<dt>Recall</dt><dd><b>${pct(M[k].recall)}</b> (${M[k].detected_chains}/${M[k].attack_chains})</dd><dt>Precision</dt><dd><b>${pct(M[k].precision)}</b></dd><dt>False-positive rate</dt><dd><b>${pct(M[k].fpr)}</b></dd><dt>Alerts</dt><dd><b>${M[k].alerts}</b></dd>` : ""}</dl></div>`).join("")}</div>

    ${atk.length ? `<div class="card"><h3>How one attack looks to each detector</h3><p class="sub">Pick an injected attack chain. This is the clearest demonstration of alert fatigue versus consolidation.</p>
      <div class="filters"><div><label>Attack chain</label><select id="cmpChain">${atk.map(c => `<option value="${c.chain_id}">${c.chain_id} · ${esc(scenName(c.scenario))} · ${esc(c.user)}</option>`).join("")}</select></div></div><div id="cmpOut"></div></div>` : ""}

    <div class="card"><h3><span class="tag A">A</span> Rule alerts by rule</h3><p class="sub">${R.detectors.A.total} alerts. Rules that fire constantly on benign activity are the main source of alert fatigue.</p>
      <div class="tw"><table class="data"><thead><tr><th>Rule</th><th>Logic</th><th class="num">Alerts</th><th>Known weakness</th></tr></thead><tbody>
      ${S.schema.docs.rules.map(r => `<tr><td><b>${r.id}</b> ${esc(r.name)}</td><td class="help" style="min-width:240px">${esc(r.logic)}</td><td class="num"><b>${R.detectors.A.by_rule[r.id] || 0}</b></td><td class="help">${esc(r.weakness)}</td></tr>`).join("")}</tbody></table></div></div>
    <div class="card"><h3>Alert lists</h3><div class="tabs" id="altabs"><button class="on" data-k="A">A · Rules (${R.detectors.A.total})</button><button data-k="B">B · Isolation Forest (${R.detectors.B.total})</button><button data-k="C">C · Incidents (${R.detectors.C.total})</button></div><div id="alertList"></div></div>`;
  const verdict = a => { if (!R.chains.length) return ""; const h = R.chains.filter(c => (a.matched || []).includes(c.chain_id)); return !h.length ? `<span class="chip fp">FP</span>` : h.some(c => c.label === "attack") ? `<span class="chip tp">TP ${h.find(c => c.label === "attack").chain_id}</span>` : `<span class="chip fp">FP (control)</span>`; };
  const drawList = k => {
    const D = R.detectors[k]; let rows = "";
    if (k === "A") rows = `<thead><tr><th>ID</th><th>Time</th><th>User</th><th>Rule</th><th>Sev</th><th>Why it fired</th><th>Verdict</th></tr></thead><tbody>${D.alerts.map(a => `<tr><td class="mono-s">${a.alert_id}</td><td class="mono-s">${tstr(a.time)}</td><td class="mono-s">${esc(a.user)}</td><td>${a.rule} <span class="help">${esc(a.rule_name)}</span></td><td>${sevChip(a.severity)}</td><td class="help">${esc(a.reason)}</td><td>${verdict(a)}</td></tr>`).join("")}</tbody>`;
    if (k === "B") rows = `<thead><tr><th>ID</th><th>Window</th><th>User</th><th class="num">Score</th><th class="num">Events</th><th>Largest deviations (post-hoc, robust z-score)</th><th>Verdict</th></tr></thead><tbody>${D.alerts.map(a => `<tr><td class="mono-s">${a.alert_id}</td><td class="mono-s">${tstr(a.window_start).slice(5, 16)}-${tshort(a.window_end).slice(0, 5)}</td><td class="mono-s">${esc(a.user)}</td><td class="num">${a.score}</td><td class="num">${a.n_events}</td><td class="help">${a.top_features.map(f => `<code>${f.feature}</code> = ${f.value} (median ${f.baseline_median}, z ${f.robust_z})`).join("<br>") || "no single feature stands out"}</td><td>${verdict(a)}</td></tr>`).join("")}</tbody>`;
    if (k === "C") rows = `<thead><tr><th>ID</th><th>Alert time</th><th>User</th><th class="num">Score</th><th>Stages</th><th>Assessment</th><th>Verdict</th></tr></thead><tbody>${D.incidents.map(a => `<tr class="click" data-inc="${a.incident_id}"><td class="mono-s">${a.incident_id}</td><td class="mono-s">${tstr(a.time)}</td><td class="mono-s">${esc(a.user)}</td><td class="num"><b>${a.score}</b></td><td class="mono-s">${a.stage_ids.map(n => "S" + n).join(" ")}</td><td class="help">${esc(a.assessment)}</td><td>${verdict(a)}</td></tr>`).join("")}</tbody>`;
    $("#alertList").innerHTML = (D.total > 400 && k !== "C" ? `<div class="help" style="margin-bottom:6px">Showing the first 400 of ${D.total} alerts.</div>` : "") + `<div class="tw" style="max-height:480px"><table class="data">${rows}</table></div>` + (k === "B" ? `<div class="callout">Isolation Forest provides only an anomaly score. The "largest deviations" column is computed afterwards by comparing each feature with the baseline median - it suggests what looked odd but is <b>not</b> the model's own reasoning. That is the explainability gap detector C closes.</div>` : "");
  };
  drawList("A");
  $("#altabs").onclick = e => { const b = e.target.closest("button"); if (!b) return; $$("#altabs button").forEach(x => x.classList.toggle("on", x === b)); drawList(b.dataset.k); };
  el.onclick = e => { const r = e.target.closest("tr[data-inc]"); if (r) { S.sel = r.dataset.inc; renderIncidents(); show("incidents"); } };
  const sel = $("#cmpChain");
  if (sel) { const draw = () => { const c = R.chains.find(x => x.chain_id === sel.value);
      const al = R.detectors.A.alerts.filter(a => (a.matched || []).includes(c.chain_id)), bl = R.detectors.B.alerts.filter(a => (a.matched || []).includes(c.chain_id)), cl = R.detectors.C.incidents.filter(a => (a.matched || []).includes(c.chain_id));
      $("#cmpOut").innerHTML = `<div class="callout"><b>${esc(scenName(c.scenario))}</b> on <span class="mono-s">${esc(c.user)}</span> at ${tstr(c.start)} - ${c.n_events} malicious events. ${esc(c.description)} Planned stages: <b>${c.planned_stages.join(", ") || "none"}</b>.</div>
        <div class="grid g3"><div class="card flat" style="border-top:3px solid ${COL.A}"><h4>A sees ${al.length} separate alert(s)</h4>${al.length ? al.slice(0, 12).map(a => `<div class="help" style="margin:5px 0"><span class="mono-s">${tshort(a.time)}</span> <b>${a.rule}</b> ${esc(a.reason)}</div>`).join("") : `<div class="help">Nothing raised.</div>`}${al.length > 12 ? `<div class="help">… and ${al.length - 12} more</div>` : ""}</div>
        <div class="card flat" style="border-top:3px solid ${COL.B}"><h4>B sees ${bl.length} window(s)</h4>${bl.length ? bl.map(a => `<div class="help" style="margin:5px 0"><span class="mono-s">${tshort(a.window_start).slice(0, 5)}-${tshort(a.window_end).slice(0, 5)}</span> anomaly score <b>${a.score}</b>, ${a.n_events} events; no reason given</div>`).join("") : `<div class="help">Nothing raised.</div>`}</div>
        <div class="card flat" style="border-top:3px solid ${COL.C}"><h4>C sees ${cl.length} incident(s)</h4>${cl.length ? cl.map(a => `<div class="help" style="margin:5px 0"><b>${a.incident_id}</b> score <b>${a.score}</b> · ${a.stage_ids.map(n => "S" + n).join(" → ")}<br>${esc(a.assessment)} <a href="#" data-goinc="${a.incident_id}">open explanation</a></div>`).join("") : `<div class="help">Missed: ${esc(c.miss_reason_c || "no incident raised")}</div>`}</div></div>`; };
    sel.onchange = draw; draw();
    $("#cmpOut").onclick = e => { const a = e.target.closest("[data-goinc]"); if (a) { e.preventDefault(); S.sel = a.dataset.goinc; renderIncidents(); show("incidents"); } };
  }
}

/* ------------------------------------------------------------ log explorer */
function renderLogsShell() {
  const f = S.logs.f, el = $("#tab-logs");
  if (!S.run) { el.innerHTML = `<div class="page-head"><div><div class="crumb">Step 5 of 8</div><h2>Log explorer</h2></div></div><div class="empty"><b>No logs yet</b>Run an analysis first.</div>`; return; }
  const types = ["login_success", "login_failure", "file_read", "admin_action", "priv_change", "outbound_transfer"];
  el.innerHTML = `<div class="page-head"><div><div class="crumb">Step 5 of 8</div><h2>Log explorer</h2>
    <p>Every generated event. Switch between the <b>normalised</b> schema and the <b>raw</b> native records, filter, and click a row to see exactly which detectors flagged it and why. Ground-truth labels are shown for research evaluation - detectors never see them.</p></div>
    <div style="display:flex;gap:8px;flex-wrap:wrap"><a class="btn sm" id="exCsv">Export CSV</a><a class="btn sm" id="exRaw">Export raw JSONL</a></div></div>
    <div class="card"><div class="filters">
      <div><label>View</label><select id="fView"><option value="normalised">Normalised schema</option><option value="raw">Raw source records</option></select></div>
      <div><label>User contains</label><input id="fUser" placeholder="e.g. sara" value="${esc(f.user || "")}"></div>
      <div><label>Event type</label><select id="fType"><option value="">all</option>${types.map(t => `<option ${f.type === t ? "selected" : ""}>${t}</option>`).join("")}</select></div>
      <div><label>Flag filter</label><select id="fFlag">${[["all", "All events"], ["attack", "Ground-truth attack events"], ["control", "Benign control events"], ["any", "Flagged by any detector"], ["A", "Flagged by A (rules)"], ["B", "Flagged by B (IF)"], ["C", "Evidence of C incidents"], ["none", "Not flagged by anyone"]].map(([v, l]) => `<option value="${v}" ${(f.flag || "all") === v ? "selected" : ""}>${l}</option>`).join("")}</select></div>
      <div><label>Period</label><select id="fPeriod"><option value="all">Whole log</option><option value="baseline">Baseline only</option><option value="eval">Evaluation only</option></select></div>
      <div><label>Search any field</label><input id="fQ" placeholder="ip, device, path..."></div>
      <button class="btn sm primary" id="fGo">Apply</button></div>
      <div id="logOut"></div></div>`;
  $("#fView").value = S.logs.view;
  const apply = () => { S.logs.f = {user: $("#fUser").value, type: $("#fType").value, flag: $("#fFlag").value, period: $("#fPeriod").value, q: $("#fQ").value}; S.logs.view = $("#fView").value; S.logs.page = 1; loadLogs(); };
  $("#fGo").onclick = apply; $("#fView").onchange = apply; ["fUser", "fQ"].forEach(i => $("#" + i).addEventListener("keydown", e => e.key === "Enter" && apply()));
  if (f.period) $("#fPeriod").value = f.period; if (f.q) $("#fQ").value = f.q;
  const qs = () => new URLSearchParams(Object.fromEntries(Object.entries(S.logs.f).filter(([, v]) => v))).toString();
  $("#exCsv").href = `/api/run/${S.run.run_id}/export?fmt=csv&${qs()}`; $("#exRaw").href = `/api/run/${S.run.run_id}/export?fmt=raw`;
}
async function loadLogs() {
  const out = $("#logOut"); if (!out || !S.run) return;
  const q = new URLSearchParams({...Object.fromEntries(Object.entries(S.logs.f).filter(([, v]) => v)), page: S.logs.page, page_size: 50, view: S.logs.view});
  out.innerHTML = `<div class="help">Loading...</div>`;
  try {
    const d = await api(`/api/run/${S.run.run_id}/logs?${q}`);
    const flagCell = r => `${r.ground_truth ? `<span class="chip ${r.ground_truth.label === "attack" ? "gt" : "ctl"}" title="${esc(r.ground_truth.scenario)}">${r.ground_truth.label === "attack" ? "ATTACK" : "CONTROL"} ${r.ground_truth.chain_id}</span> ` : ""}${r.flagged_by.map(detChip).join(" ")}`;
    const head = S.logs.view === "raw" ? `<tr><th>ID</th><th>Time</th><th>User</th><th>Source</th><th>Raw record (native format)</th><th>Flags</th></tr>` : `<tr><th>ID</th><th>Time (UTC)</th><th>User</th><th>Event</th><th>Source IP</th><th>Device</th><th>Geo</th><th>Resource</th><th class="num">Bytes</th><th>VPN</th><th>Flags</th></tr>`;
    const body = d.rows.map(r => S.logs.view === "raw"
      ? `<tr class="click" data-e="${r.event_id}"><td class="mono-s">${r.event_id}</td><td class="mono-s">${tstr(r.timestamp)}</td><td class="mono-s">${esc(r.user)}</td><td>${r.source}</td><td class="mono-s" style="word-break:break-all;min-width:380px">${esc(r.raw)}</td><td>${flagCell(r)}</td></tr>`
      : `<tr class="click" data-e="${r.event_id}"><td class="mono-s">${r.event_id}</td><td class="mono-s">${tstr(r.timestamp)}</td><td class="mono-s">${esc(r.user)}</td><td><span class="et ${r.event_type}">${r.event_type}</span></td><td class="mono-s">${esc(r.src_ip)}</td><td class="mono-s">${esc(r.device)}</td><td>${esc(r.geo)}</td><td class="mono-s" style="max-width:260px;overflow:hidden;text-overflow:ellipsis">${esc(r.resource)}</td><td class="num">${r.bytes ? bytesH(r.bytes) : ""}</td><td>${r.via_vpn ? "yes" : ""}</td><td>${flagCell(r)}</td></tr>`).join("");
    out.innerHTML = `<div class="help" style="margin-bottom:8px"><b>${d.total.toLocaleString()}</b> matching events · page ${d.page} of ${d.pages}</div><div class="tw" style="max-height:600px"><table class="data"><thead>${head}</thead><tbody>${body || `<tr><td colspan="11" class="help">No events match these filters.</td></tr>`}</tbody></table></div>
      <div class="pager"><button class="btn sm" id="pPrev" ${d.page <= 1 ? "disabled" : ""}>Prev</button><span>${d.page} / ${d.pages}</span><button class="btn sm" id="pNext" ${d.page >= d.pages ? "disabled" : ""}>Next</button></div>`;
    $("#pPrev").onclick = () => { S.logs.page--; loadLogs(); }; $("#pNext").onclick = () => { S.logs.page++; loadLogs(); };
    out.onclick = e => { const tr = e.target.closest("tr[data-e]"); if (tr) openEvent(tr.dataset.e); };
  } catch (e) { out.innerHTML = `<div class="callout warn">${esc(e.message)}</div>`; }
}
async function openEvent(id) {
  const d = await api(`/api/run/${S.run.run_id}/event/${id}`), e = d.event, dr = $("#drawer");
  const det = d.detections;
  dr.innerHTML = `<div style="display:flex;justify-content:space-between;align-items:center"><h3 style="margin:0">Event ${e.event_id}</h3><button class="btn sm" id="dClose">Close</button></div>
    <p class="help">${tstr(e.timestamp)} · <span class="et ${e.event_type}">${e.event_type}</span></p>
    ${d.ground_truth ? `<div class="callout ${d.ground_truth.label === "attack" ? "warn" : ""}"><b>Ground truth (hidden from detectors):</b> belongs to ${d.ground_truth.chain_id} - ${esc(scenName(d.ground_truth.scenario))} (${d.ground_truth.label === "attack" ? "real attack" : "benign control"}).</div>` : `<div class="help">Ground truth: ordinary background activity.</div>`}
    <h4>Normalised fields</h4><dl class="kv">${Object.entries(e).filter(([k]) => k !== "event_id").map(([k, v]) => `<dt>${k}</dt><dd class="mono-s">${esc(typeof v === "boolean" ? (v ? "true" : "false") : tstr(v) === v ? v : v)}</dd>`).join("")}</dl>
    <h4 style="margin-top:14px">Raw source record</h4><pre class="mono-s" style="white-space:pre-wrap;word-break:break-all;background:#0a1121;border:1px solid var(--line);border-radius:8px;padding:10px">${esc(JSON.stringify(d.raw, null, 1))}</pre>
    <h4 style="margin-top:14px">What the detectors said about this event</h4>
    <p><b>A - rules:</b></p>${det.A.length ? det.A.map(a => `<div class="help"><span class="chip A">${a.alert_id}</span> <b>${esc(a.rule)}</b> - ${esc(a.reason)}</div>`).join("") : `<div class="help">Not part of any rule alert.</div>`}
    <p style="margin-top:10px"><b>B - Isolation Forest:</b></p>${det.B.length ? det.B.map(a => `<div class="help"><span class="chip B">${a.alert_id}</span> window anomaly score ${a.score}; ${a.top_features.map(f => f.feature).join(", ")}</div>`).join("") : `<div class="help">Not in any flagged window.</div>`}
    <p style="margin-top:10px"><b>C - correlation:</b></p>${det.C.length ? det.C.map(i => `<div class="help"><span class="chip C">${i.incident_id}</span> score ${i.score}${i.stages.map(s => `<div style="margin:4px 0 0 8px"><b>${s.id} ${esc(s.name)}</b><ul style="margin:2px 0 0 16px;padding:0">${s.reasons.map(r => `<li>${esc(r)}</li>`).join("")}</ul></div>`).join("")}</div>`).join("") : `<div class="help">Not evidence in any incident.</div>`}`;
  dr.classList.add("open"); $("#dClose").onclick = () => dr.classList.remove("open");
}

/* --------------------------------------------------------------------- boot */
(async function boot() {
  try {
    S.schema = await api("/api/schema");
    S.cfg = defaults();
    renderConfig(); renderLogsShell();
    $("#tab-summary").innerHTML = $("#tab-incidents").innerHTML = $("#tab-compare").innerHTML = `<div class="empty"><b>Nothing to show yet</b>Go to <a href="#" onclick="show('config');return false">Configure &amp; Run</a> and press the run button.</div>`;
    if (window.renderExperiments) renderExperiments(); if (window.renderCustom) renderCustom(); if (window.renderMethod) renderMethod();
  } catch (e) { document.body.insertAdjacentHTML("beforeend", `<div class="toast" style="display:block">Could not reach the backend: ${esc(e.message)}</div>`); }
})();

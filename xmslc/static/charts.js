/* Shared helpers + dependency-free SVG charts (fully offline). */
"use strict";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
const COL = {A: "#f59e0b", B: "#a78bfa", C: "#2dd4bf"};
const DNAME = {A: "A  Independent rules", B: "B  Isolation Forest", C: "C  Multi-stage correlation"};
const pct = v => v == null ? "n/a" : (v * 100).toFixed(v >= .995 || v < .005 ? 0 : 1) + "%";
const num = (v, d = 2) => v == null ? "n/a" : (+v).toFixed(d);
const fmt = (v, k) => v == null ? "n/a" : (["recall", "precision", "f1", "fpr", "fidelity"].includes(k) ? pct(v) : k === "mttd_min" ? v.toFixed(1) + " min" : Number.isInteger(v) ? v : (+v).toFixed(1));
const tstr = s => (s || "").toString().replace("T", " ").slice(0, 19);
const tshort = s => tstr(s).slice(11, 19);
const dstr = s => tstr(s).slice(0, 10);
const bytesH = b => b >= 1e9 ? (b / 1e9).toFixed(2) + " GB" : b >= 1e6 ? (b / 1e6).toFixed(1) + " MB" : b >= 1e3 ? (b / 1e3).toFixed(0) + " KB" : b + " B";
const sevChip = s => `<span class="chip ${esc(s)}">${esc(String(s).toUpperCase())}</span>`;
const detChip = k => `<span class="chip ${k}">${k}</span>`;
const scenName = id => ({credential_stuffing: "Credential stuffing", stolen_session: "Stolen session", insider_misuse: "Insider misuse", slow_exfil: "Low-and-slow exfil", benign_travel: "Benign travel (control)"}[id] || id);

function legend(items) {
  return `<div class="legend">${items.map(i => `<span><i style="background:${i.color}"></i>${esc(i.name)}</span>`).join("")}</div>`;
}

function barChart({cats, series, max = 1, height = 230, fmtv = v => v.toFixed(2), unit = ""}) {
  const W = 680, H = height, pl = 42, pr = 8, pt = 16, pb = 38, iw = W - pl - pr, ih = H - pt - pb;
  const gw = iw / cats.length, bw = Math.min(40, (gw - 22) / series.length);
  let s = `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img">`;
  for (let i = 0; i <= 4; i++) {
    const y = pt + ih - ih * i / 4;
    s += `<line class="grid" x1="${pl}" x2="${W - pr}" y1="${y}" y2="${y}"/><text x="${pl - 6}" y="${y + 3}" text-anchor="end">${(max * i / 4).toFixed(max <= 1 ? 2 : 0)}${unit}</text>`;
  }
  s += `<line class="axis" x1="${pl}" x2="${W - pr}" y1="${pt + ih}" y2="${pt + ih}"/>`;
  cats.forEach((c, ci) => {
    const x0 = pl + gw * ci + (gw - bw * series.length) / 2;
    series.forEach((se, si) => {
      const v = se.values[ci] ?? 0, h = Math.max(0, Math.min(1, v / max)) * ih, x = x0 + si * bw, y = pt + ih - h;
      s += `<rect x="${x}" y="${y}" width="${bw - 3}" height="${h}" rx="3" fill="${se.color}" opacity=".92"><title>${esc(se.name)} - ${esc(c)}: ${fmtv(v)}</title></rect>`;
      s += `<text class="val" x="${x + (bw - 3) / 2}" y="${y - 4}" text-anchor="middle">${fmtv(v)}</text>`;
      if (se.err && se.err[ci]) {
        const [lo, hi] = se.err[ci], xm = x + (bw - 3) / 2, yl = pt + ih - Math.max(0, Math.min(1, lo / max)) * ih, yh = pt + ih - Math.max(0, Math.min(1, hi / max)) * ih;
        s += `<line x1="${xm}" x2="${xm}" y1="${yl}" y2="${yh}" stroke="#fff" stroke-width="1.4"/><line x1="${xm - 4}" x2="${xm + 4}" y1="${yh}" y2="${yh}" stroke="#fff"/><line x1="${xm - 4}" x2="${xm + 4}" y1="${yl}" y2="${yl}" stroke="#fff"/>`;
      }
    });
    s += `<text x="${pl + gw * ci + gw / 2}" y="${H - 14}" text-anchor="middle">${esc(c)}</text>`;
  });
  return s + "</svg>";
}

function lineChart({xs, series, xlabel = "", height = 210, max = 1}) {
  const W = 520, H = height, pl = 40, pr = 12, pt = 12, pb = 38, iw = W - pl - pr, ih = H - pt - pb;
  const X = i => pl + (xs.length === 1 ? iw / 2 : iw * i / (xs.length - 1)), Y = v => pt + ih - Math.max(0, Math.min(1, v / max)) * ih;
  let s = `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img">`;
  for (let i = 0; i <= 4; i++) {
    const y = pt + ih - ih * i / 4;
    s += `<line class="grid" x1="${pl}" x2="${W - pr}" y1="${y}" y2="${y}"/><text x="${pl - 6}" y="${y + 3}" text-anchor="end">${(max * i / 4).toFixed(2)}</text>`;
  }
  xs.forEach((x, i) => s += `<text x="${X(i)}" y="${H - 18}" text-anchor="middle">${esc(x)}</text>`);
  s += `<text x="${pl + iw / 2}" y="${H - 3}" text-anchor="middle">${esc(xlabel)}</text>`;
  series.forEach(se => {
    const pts = se.values.map((v, i) => `${X(i)},${Y(v)}`).join(" ");
    s += `<polyline points="${pts}" fill="none" stroke="${se.color}" stroke-width="2.4" stroke-linejoin="round"/>`;
    se.values.forEach((v, i) => s += `<circle cx="${X(i)}" cy="${Y(v)}" r="3.5" fill="${se.color}"><title>${esc(se.name)} @ ${esc(xs[i])}: ${v.toFixed(3)}</title></circle>`);
  });
  return s + "</svg>";
}

function hourChart(hours) {
  const W = 680, H = 190, pl = 40, pr = 8, pt = 10, pb = 28, iw = W - pl - pr, ih = H - pt - pb;
  const tot = hours.normal.map((v, i) => v + hours.attack[i]), mx = Math.max(1, ...tot), bw = iw / 24;
  let s = `<svg class="chart" viewBox="0 0 ${W} ${H}">`;
  for (let i = 0; i <= 3; i++) {
    const y = pt + ih - ih * i / 3;
    s += `<line class="grid" x1="${pl}" x2="${W - pr}" y1="${y}" y2="${y}"/><text x="${pl - 6}" y="${y + 3}" text-anchor="end">${Math.round(mx * i / 3)}</text>`;
  }
  for (let h = 0; h < 24; h++) {
    const hn = hours.normal[h] / mx * ih, ha = hours.attack[h] / mx * ih, x = pl + bw * h + 2;
    s += `<rect x="${x}" y="${pt + ih - hn}" width="${bw - 4}" height="${hn}" fill="#4a6fa5" rx="2"><title>${h}:00 normal events: ${hours.normal[h]}</title></rect>`;
    if (ha > 0) s += `<rect x="${x}" y="${pt + ih - hn - ha}" width="${bw - 4}" height="${ha}" fill="#ef4444" rx="2"><title>${h}:00 attack events: ${hours.attack[h]}</title></rect>`;
    if (h % 3 === 0) s += `<text x="${x + (bw - 4) / 2}" y="${H - 10}" text-anchor="middle">${String(h).padStart(2, "0")}h</text>`;
  }
  return s + "</svg>";
}

function gauge(score, severity) {
  const col = {critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#38bdf8"}[severity] || "#2dd4bf";
  const r = 54, cx = 70, cy = 66, a = Math.PI * Math.min(100, score) / 100;
  const ex = cx - r * Math.cos(a), ey = cy - r * Math.sin(a);
  return `<svg viewBox="0 0 140 84" width="150" role="img" aria-label="Risk score ${score} of 100">
    <path d="M${cx - r} ${cy} A${r} ${r} 0 0 1 ${cx + r} ${cy}" fill="none" stroke="#1d2b47" stroke-width="12" stroke-linecap="round"/>
    <path d="M${cx - r} ${cy} A${r} ${r} 0 0 1 ${ex.toFixed(2)} ${ey.toFixed(2)}" fill="none" stroke="${col}" stroke-width="12" stroke-linecap="round"/>
    <text x="${cx}" y="${cy - 6}" text-anchor="middle" font-size="26" font-weight="700" fill="#fff" font-family="ui-monospace,Consolas,monospace">${score}</text>
    <text x="${cx}" y="${cy + 12}" text-anchor="middle" font-size="9.5" fill="#93a1bb" letter-spacing="1.2">RISK / 100</text></svg>`;
}

function stackedBar(items, total) {
  const cols = {stage: "#2dd4bf", bonus: "#38bdf8"};
  let used = 0;
  const segs = items.filter(i => i.points > 0).map((i, k) => {
    const w = i.points / Math.max(total, 100) * 100; used += w;
    const c = i.kind === "bonus" ? (k % 2 ? "#7dd3fc" : "#38bdf8") : ["#2dd4bf", "#5eead4", "#14b8a6", "#99f6e4", "#0d9488", "#67e8f9"][k % 6];
    return `<div style="width:${w}%;background:${c}" title="${esc(i.term)}: ${i.points}">${w > 7 ? i.points : ""}</div>`;
  }).join("");
  return `<div class="bar-h">${segs}<div style="flex:1;background:#14203a;color:#6b7c9c">${used < 100 ? "" : ""}</div></div>`;
}

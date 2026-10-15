"use strict";

const Scan = (() => {
  const state = { findings: new Map(), jobs: new Map(), stats: null, sel: null, q: "", minSev: "", started: false };
  const SEV = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const SEVLABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
  const CONF = { certain: "Certain", firm: "Firm", tentative: "Tentative" };

  function activate() {
    if (state.started) return;
    state.started = true;
    connect();
    bind();
  }

  function connect() {
    const es = new EventSource("/api/scan/events");
    es.onmessage = e => ingest(JSON.parse(e.data));
  }

  function ingest(ev) {
    if (ev.cleared) { state.findings.clear(); state.sel = null; }
    for (const f of ev.findings || []) state.findings.set(f.id, f);
    for (const j of ev.jobs || []) state.jobs.set(j.id, j);
    if (ev.stats) state.stats = ev.stats;
    render();
  }

  function bind() {
    const q = $("#scan-q"), sevf = $("#scan-sevf");
    if (q) q.oninput = () => { state.q = q.value.toLowerCase(); renderList(); };
    if (sevf) sevf.onchange = () => { state.minSev = sevf.value; renderList(); };
    const pass = $("#scan-passive"); if (pass) pass.onclick = () => post("/api/scan/passive");
    const clear = $("#scan-clear"); if (clear) clear.onclick = () => post("/api/scan/clear");
    const stop = $("#scan-stop"); if (stop) stop.onclick = () => post("/api/scan/stop");
    const active = $("#scan-active"); if (active) active.onclick = openActive;
  }

  async function openActive() {
    const cfg = await (await fetch("/api/scan/config")).json();
    const hosts = (cfg.hosts || []).map(h => esc(h)).join("\n");
    const routes = (cfg.routes || []).map(r => `<option value="${esc(r.id)}">${esc(r.name)}</option>`).join("");
    const profiles = profileOptions(cfg.profiles);
    const cats = {};
    for (const c of cfg.checks || []) (cats[c.category] = cats[c.category] || []).push(c);
    const checkHTML = Object.keys(cats).map(cat => `
      <fieldset class="scancat"><legend>${esc(cat)}</legend>` +
      cats[cat].map(c => `<label class="scanck"><input type="checkbox" data-check="${esc(c.id)}" ${c.default ? "checked" : ""}> ${esc(c.name)}</label>`).join("") +
      `</fieldset>`).join("");
    const modal = $("#modal");
    modal.innerHTML = `<div class="overlay" data-backdrop><div class="modal wide">
      <header class="mh"><h2>Active scan</h2><button type="button" class="x" data-close title="Close (Esc)">✕</button></header>
      <div class="scanform">
        <div class="scanform-row">
          <label class="scanlbl">In-scope hosts <span class="muted">(one per line, * wildcards)</span>
            <textarea id="sc-include" class="mono" rows="4" placeholder="example.com&#10;*.example.com">${hosts}</textarea></label>
          <label class="scanlbl">Exclude
            <textarea id="sc-exclude" class="mono" rows="4" placeholder="logout&#10;*.google.com"></textarea></label>
        </div>
        <div class="scanform-row">
          <label class="scanlbl">Intensity
            <select id="sc-intensity">
              <option value="light">Light — fewer payloads</option>
              <option value="normal" selected>Normal</option>
              <option value="thorough">Thorough</option>
              <option value="insane">Insane — everything</option>
            </select></label>
          <label class="scanlbl">Route <select id="sc-route">${routes}</select></label>
          <label class="scanlbl">TLS <select id="sc-profile">${profiles}</select></label>
        </div>
        <div class="scanform-row">
          <label class="scanlbl">Max requests/sec <span class="muted">(0 = unlimited)</span><input id="sc-rate" type="number" min="0" value="0"></label>
          <label class="scanlbl">Concurrency <input id="sc-conc" type="number" min="1" max="64" value="10"></label>
          <label class="scanlbl">Request budget <input id="sc-budget" type="number" min="0" value="0" placeholder="auto"></label>
        </div>
        <div class="scanform-row toggles">
          <label class="scanck"><input type="checkbox" id="sc-discover" checked> Discover hidden paths & parameters</label>
          <label class="scanck"><input type="checkbox" id="sc-blind"> Blind / time-based checks</label>
        </div>
        <h3>Checks</h3>
        <div class="scanchecks">${checkHTML}</div>
        <div class="scanform-actions">
          <button type="button" class="tool" data-close>Cancel</button>
          <button type="button" id="sc-start" class="btn primary">Start scan ▸</button>
        </div>
      </div>
    </div></div>`;
    $("#sc-start").onclick = startActive;
  }

  async function startActive() {
    const val = s => ($(s) && $(s).value || "").trim();
    const lines = s => val(s).split(/[\r\n,]+/).map(x => x.trim()).filter(Boolean);
    const checks = [...document.querySelectorAll("[data-check]:checked")].map(c => c.dataset.check);
    const opts = {
      scope: { include: lines("#sc-include"), exclude: lines("#sc-exclude") },
      checks,
      intensity: val("#sc-intensity"),
      route: val("#sc-route"),
      profile: $("#sc-profile") && $("#sc-profile").value === "none" ? "" : val("#sc-profile"),
      rateLimit: +val("#sc-rate") || 0,
      concurrency: +val("#sc-conc") || 0,
      maxRequests: +val("#sc-budget") || 0,
      active: true,
      discover: $("#sc-discover").checked,
      blind: $("#sc-blind").checked,
    };
    if (!opts.scope.include.length) { toast("Add at least one in-scope host"); return; }
    const btn = $("#sc-start"); if (btn) { btn.disabled = true; btn.textContent = "Starting…"; }
    const res = await fetch("/api/scan/start", { method: "POST", headers: { "X-Sift": "1", "Content-Type": "application/json" }, body: JSON.stringify(opts) });
    const out = await res.json();
    const msg = res.headers.get("X-Toast");
    if (msg) toast(decodeURIComponent(msg.replace(/\+/g, " ")));
    if (!out.error) closeModal();
    else if (btn) { btn.disabled = false; btn.textContent = "Start scan ▸"; }
  }

  function sorted() {
    const list = [...state.findings.values()];
    list.sort((a, b) => {
      if (SEV[b.severity] !== SEV[a.severity]) return SEV[b.severity] - SEV[a.severity];
      return (b.last || 0) - (a.last || 0);
    });
    return list;
  }

  function visible(f) {
    if (state.minSev && SEV[f.severity] < SEV[state.minSev]) return false;
    if (state.q) {
      const hay = (f.title + " " + f.host + " " + (f.url || "") + " " + (f.param || "") + " " + f.type).toLowerCase();
      if (!hay.includes(state.q)) return false;
    }
    return true;
  }

  function render() { renderStats(); renderList(); renderJobs(); if (state.sel) renderDetail(state.sel); }

  function renderStats() {
    const el = $("#scan-stats"); if (!el || !state.stats) return;
    const s = state.stats, by = s.bySev || {};
    const chips = ["critical", "high", "medium", "low", "info"]
      .filter(k => by[k]).map(k => `<span class="sevchip ${k}">${by[k]} ${SEVLABEL[k]}</span>`).join("");
    el.innerHTML = chips || `<span class="muted">No findings</span>`;
  }

  function renderList() {
    const wrap = $("#scan-items"), empty = $("#scan-empty");
    if (!wrap) return;
    const list = sorted().filter(visible);
    if (empty) empty.hidden = state.findings.size > 0;
    wrap.innerHTML = list.map(f => `
      <button class="scanitem ${f.id === state.sel ? "on" : ""}" data-id="${esc(f.id)}">
        <span class="sevdot ${esc(f.severity)}"></span>
        <span class="scanitem-main">
          <span class="scanitem-title">${esc(f.title)}${f.count > 1 ? ` <span class="muted">×${f.count}</span>` : ""}</span>
          <span class="scanitem-sub">${esc(f.host)}${f.param ? " · " + esc(f.param) : ""}</span>
        </span>
        <span class="conf ${esc(f.confidence)}" title="Confidence">${CONF[f.confidence] || ""}</span>
      </button>`).join("");
    wrap.querySelectorAll(".scanitem").forEach(b => b.onclick = () => { state.sel = b.dataset.id; renderList(); renderDetail(b.dataset.id); });
  }

  function renderDetail(id) {
    const el = $("#scan-detail"); if (!el) return;
    const f = state.findings.get(id);
    if (!f) { el.innerHTML = `<p class="placeholder">Select a finding.</p>`; return; }
    const repro = (f.repro || []).map(r => `<li>${esc(r)}</li>`).join("");
    const ev = (f.evidence || []).map(e => `
      <div class="evidence">
        <div class="ev-label">${esc(e.label)}${e.flow ? ` <a href="#" data-flow="${e.flow}" class="ev-flow">view request #${e.flow}</a>` : ""}</div>
        ${e.detail ? `<div class="muted">${esc(e.detail)}</div>` : ""}
        ${e.snippet ? `<pre class="ev-snip">${esc(e.snippet)}</pre>` : ""}
      </div>`).join("");
    el.innerHTML = `
      <div class="finding">
        <div class="finding-head">
          <span class="sevtag ${esc(f.severity)}">${SEVLABEL[f.severity]}</span>
          <span class="conf ${esc(f.confidence)}">${CONF[f.confidence] || ""} confidence</span>
          ${f.cwe ? `<span class="cwe">${esc(f.cwe)}</span>` : ""}
          ${f.passive ? `<span class="tagbadge">passive</span>` : `<span class="tagbadge active">active</span>`}
        </div>
        <h2>${esc(f.title)}</h2>
        <div class="finding-loc mono">${f.method ? esc(f.method) + " " : ""}${esc(f.url || f.host)}</div>
        ${f.param ? `<div class="muted">Insertion point: <b>${esc(f.param)}</b> (${esc(f.where || "")})</div>` : ""}
        <p>${esc(f.detail)}</p>
        ${f.payload ? `<div class="finding-sec"><h3>Payload</h3><pre class="ev-snip">${esc(f.payload)}</pre></div>` : ""}
        ${ev ? `<div class="finding-sec"><h3>Evidence</h3>${ev}</div>` : ""}
        ${repro ? `<div class="finding-sec"><h3>Reproduction</h3><ol>${repro}</ol></div>` : ""}
        ${f.remediation ? `<div class="finding-sec"><h3>Remediation</h3><p>${esc(f.remediation)}</p></div>` : ""}
      </div>`;
    el.querySelectorAll(".ev-flow").forEach(a => a.onclick = e => {
      e.preventDefault();
      switchView("traffic");
      if (window.select) select(+a.dataset.flow);
    });
  }

  function renderJobs() {
    const el = $("#scan-jobs"); if (!el) return;
    const jobs = [...state.jobs.values()].filter(j => j.state === "running");
    const stop = $("#scan-stop"); if (stop) stop.hidden = jobs.length === 0;
    if (!jobs.length) { el.innerHTML = ""; return; }
    el.innerHTML = jobs.map(j => {
      const pct = j.queued ? Math.round(100 * (j.done || 0) / j.queued) : 0;
      return `<div class="scanjob"><span>${esc(j.kind)} · ${esc(j.target)}</span>
        <span class="jobbar"><span style="width:${pct}%"></span></span>
        <span class="muted">${j.done || 0}${j.queued ? "/" + j.queued : ""} · ${j.requests || 0} reqs</span></div>`;
    }).join("");
  }

  return { activate };
})();
window.Scan = Scan;

// Apps view: analyse an APK/IPA and show the report. All the heavy lifting (decompile,
// scan) happens in Go; this file uploads the file, shows live progress, and renders the
// report the server sends back as JSON. Shares globals ($, esc, post, toast, S) with app.js.
"use strict";

const Apps = (() => {
  let reports = [];      // list summaries
  let selected = 0;      // open report id
  let full = null;       // full report of the selected one
  let tools = {};
  let emu = {};        // emulator status
  let emuDevices = null; // cached device list
  let activated = false;
  let showManual = true; // the legend is shown by default
  try { showManual = localStorage.getItem("sift-manual") !== "0"; } catch {}

  const KINDS = {
    pinning: ["SSL Pinning", "Code that checks the server's certificate. These are the places that stop Sift (and any proxy) from reading HTTPS; see the HTTPS-decryption settings to pass pinned hosts through."],
    secret: ["Secrets", "API keys, tokens and passwords compiled into the app. Values are masked. Treat every one as exposed — anyone can extract these from the app."],
    auth: ["Auth & Captcha", "Login, register, OTP/2FA, OAuth, biometric, payment and captcha (reCAPTCHA, hCaptcha, Turnstile) touchpoints — where and how the app authenticates. Mapping only."],
    endpoint: ["Endpoints", "URLs and WebSocket addresses the app talks to. Hosts that also appear in captured traffic are linked."],
    deeplink: ["Deep links", "Custom URL schemes that open the app."],
    tracker: ["Trackers / SDKs", "Analytics and attribution SDKs bundled in the app."],
    cleartext: ["Cleartext", "Settings that allow plain, unencrypted HTTP."],
  };
  const SEV = { high: "sev-high", med: "sev-med", low: "sev-low", info: "sev-info" };

  function activate() {
    if (!activated) { activated = true; load(); connect(); wire(); }
    render();
  }

  async function load() {
    const data = await (await fetch("/api/apps/reports")).json();
    reports = data.reports || [];
    tools = data.tools || {};
    if (!selected && reports.length) selected = reports[0].id;
    if (selected) await loadReport(selected);
    try { emu = await (await fetch("/api/emulator/status")).json(); } catch {}
    render();
  }

  async function loadReport(id) {
    if (!id) { full = null; return; }
    try { full = await (await fetch(`/api/apps/reports/${id}`)).json(); }
    catch { full = null; }
  }

  function connect() {
    const es = new EventSource("/api/apps/events");
    es.onmessage = async e => {
      const msg = JSON.parse(e.data);
      if (msg.tools) tools = msg.tools;
      if (msg.emulator) { emu = msg.emulator; renderEmu(); }
      if (msg.reload) {
        const data = await (await fetch("/api/apps/reports")).json();
        reports = data.reports || [];
        tools = data.tools || tools;
        if (!reports.find(r => r.id === selected) && reports.length) selected = reports[0].id;
        if (selected) await loadReport(selected);
        if (S.view_mode === "apps") render();
      } else if (msg.tools && !tools.jadxReady) {
        renderTools();
      }
    };
  }

  function wire() {
    const pick = $("#app-file");
    $("#app-add").onclick = () => pick.click();
    pick.onchange = () => { if (pick.files[0]) upload(pick.files[0]); pick.value = ""; };
    const drop = $("#appmain");
    ["dragover", "dragenter"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add("dragging"); }));
    ["dragleave", "drop"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); if (ev === "drop" || e.target === drop) drop.classList.remove("dragging"); }));
    drop.addEventListener("drop", e => { const f = e.dataTransfer.files[0]; if (f) upload(f); });
  }

  async function upload(file) {
    const ok = /\.(apk|ipa|xapk|aab)$/i.test(file.name);
    if (!ok && !confirm(`"${file.name}" doesn't look like an app file. Analyse anyway?`)) return;
    const fd = new FormData();
    fd.append("file", file);
    const res = await post("/api/apps/analyse", fd, true);
    if (!res.ok) { toast("Couldn't analyse: " + (await res.text())); return; }
    const { id } = await res.json();
    selected = id;
    toast("Analysing " + file.name + "…");
    await load();
  }

  async function select(id) { selected = id; await loadReport(id); render(); }
  async function del(id) {
    await post(`/api/apps/reports/${id}/delete`);
    if (selected === id) { selected = 0; full = null; }
    await load();
  }

  // ---------------------------------------------------------------- render

  function render() {
    renderTools();
    renderList();
    renderReport();
  }

  function renderTools() {
    const el = $("#app-tools");
    if (!el) return;
    if (tools.jadxReady) { el.hidden = true; return; }
    el.hidden = false;
    if (tools.downloading) {
      el.className = "app-tools";
      el.innerHTML = `<div class="tool-dl">Downloading jadx… ${tools.percent}%<div class="bar"><i style="width:${tools.percent}%"></i></div></div>`;
    } else if (!tools.javaReady) {
      el.innerHTML = `<div class="tool-warn">Java isn't installed. Android analysis (jadx) needs a Java runtime. <a href="https://adoptium.net" target="_blank" rel="noopener">Get one</a>, then reopen. iOS (.ipa) analysis works without it.</div>`;
    } else {
      el.innerHTML = `<div class="tool-warn">Android analysis needs jadx (~40 MB, downloaded once). It downloads automatically when you open an APK.</div>`;
    }
  }

  function stateLabel(r) {
    return { queued: "Queued", "downloading-tool": "Getting jadx", decompiling: "Decompiling", scanning: "Scanning", done: "", error: "Failed" }[r.state] || r.state;
  }

  function renderList() {
    const el = $("#app-reports");
    if (!el) return;
    if (!reports.length) { el.innerHTML = `<p class="muted pad">No apps analysed yet.</p>`; return; }
    el.innerHTML = reports.map(r => {
      const busy = r.state !== "done" && r.state !== "error";
      const badge = r.state === "error" ? `<span class="rb err">Failed</span>`
        : busy ? `<span class="rb busy">${stateLabel(r)}</span>`
        : `<span class="rb">${total(r)} findings</span>`;
      return `<div class="rep${selected === r.id ? " on" : ""}" data-id="${r.id}">
        <div class="rep-top"><span class="kind ${r.kind}">${r.kind.toUpperCase()}</span><span class="rep-name" title="${esc(r.name)}">${esc(r.label || r.name)}</span>
        <button class="rep-x" data-del="${r.id}" title="Remove">✕</button></div>
        <div class="rep-sub">${esc(r.package || r.name)}</div>
        <div class="rep-foot">${badge}${busy ? `<span class="muted">${esc(r.progress || "")}</span>` : ""}</div>
      </div>`;
    }).join("");
    el.querySelectorAll(".rep").forEach(d => d.onclick = e => { if (!e.target.dataset.del) select(+d.dataset.id); });
    el.querySelectorAll("[data-del]").forEach(b => b.onclick = e => { e.stopPropagation(); del(+b.dataset.del); });
  }

  function total(r) { return Object.values(r.counts || {}).reduce((a, b) => a + b, 0); }

  function renderReport() {
    const drop = $("#appdrop"), box = $("#appreport");
    if (!selected || !full) { drop.hidden = false; box.hidden = true; return; }
    drop.hidden = true;
    box.hidden = false;
    const r = full;
    if (r.state === "error") {
      box.innerHTML = `<div class="rep-head"><h2>${esc(r.name)}</h2></div><div class="rp-body"><p class="bad">Analysis failed: ${esc(r.error || "unknown error")}</p></div>`;
      return;
    }
    if (r.state !== "done") {
      box.innerHTML = `<div class="rep-head"><h2>${esc(r.name)}</h2></div><div class="rp-body"><div class="working"><div class="spin"></div><p>${esc(r.progress || "Working…")}</p></div></div>`;
      return;
    }
    box.innerHTML = reportHTML(r);
    wireReport(box, r);
  }

  function idRow(label, val) { return val ? `<tr><th>${label}</th><td>${esc(String(val))}</td></tr>` : ""; }

  function reportHTML(r) {
    const groups = {};
    for (const f of r.findings || []) (groups[f.kind] ||= []).push(f);
    const order = ["pinning", "secret", "auth", "endpoint", "deeplink", "tracker", "cleartext"];

    const manual = showManual ? `<div class="manual">
      <div class="manual-head"><b>What Sift looks for</b><button id="manual-hide" class="link">Hide</button></div>
      <div class="manual-grid">${Object.entries(KINDS).map(([k, [t, d]]) =>
        `<div><span class="chip ${k}">${t}</span><span class="muted">${d}</span></div>`).join("")}</div>
      <p class="muted small">Static analysis only — Sift reads the app, it never runs it, logs in, submits forms or solves captchas.</p>
    </div>` : `<div class="manual-mini"><button id="manual-show" class="link">What do these mean?</button></div>`;

    const chips = order.filter(k => r.counts?.[k]).map(k =>
      `<span class="chip ${k}" data-jump="${k}">${KINDS[k]?.[0] || k} ${r.counts[k]}</span>`).join("");

    const idTable = `<table class="kv">
      ${idRow("Package", r.package)}${idRow("Version", r.version ? `${r.version} (build ${r.build || "?"})` : "")}
      ${idRow("Platform", r.platform)}${idRow("Min / Target SDK", r.minSdk ? `${r.minSdk} / ${r.targetSdk || "?"}` : r.minSdk)}
      ${idRow("Signing", r.signer)}${idRow("Cleartext HTTP", r.cleartext ? "⚠ allowed — " + (r.cleartextNote || "") : (r.cleartextNote || ""))}
      ${idRow("File", `${r.name} · ${fmtBytes(r.size)}`)}
    </table>`;

    const sections = order.filter(k => groups[k]).map(k => section(k, groups[k], r)).join("");
    const perms = (r.permissions || []).length ? `<details class="rp-sec"><summary>Permissions <i>${r.permissions.length}</i></summary><div class="chips2">${r.permissions.map(p => `<span class="perm">${esc(p)}</span>`).join("")}</div></details>` : "";
    const comps = (r.components || []).length ? `<details class="rp-sec"><summary>Components <i>${r.components.length}</i></summary><table class="kv">${r.components.map(c => `<tr><th>${c.type}</th><td>${esc(c.name)} ${c.exported ? '<span class="tag warn">exported</span>' : ""}</td></tr>`).join("")}</table></details>` : "";
    const links = (r.deepLinks || []).length ? `<details class="rp-sec" open><summary>Deep links <i>${r.deepLinks.length}</i></summary><div class="chips2">${r.deepLinks.map(d => `<span class="perm mono">${esc(d)}</span>`).join("")}</div></details>` : "";

    const emuBtn = r.kind === "apk" ? `<button id="emu-open" class="btn" title="Run this app in an Android emulator and capture its traffic">▶ Open in emulator</button>` : "";
    return `<div class="rep-head">
        <div><h2>${esc(r.label || r.name)}</h2><div class="muted mono">${esc(r.package || "")}</div></div>
        <span class="grow"></span>${emuBtn}<div class="sumchips">${chips}</div>
      </div>
      <div class="rp-body">
        <div id="emu-panel"></div>
        ${r.quickScan ? `<div class="note-bar">Findings are ready (scanned directly from the app — fast, and complete). The code viewer currently shows extracted strings; if this app is small enough, full decompiled Java is loading in the background and will replace it automatically.</div>` : ""}
        ${manual}
        <details class="rp-sec" open><summary>App details</summary>${idTable}</details>
        ${links}${perms}${comps}
        ${sections}
      </div>
      <div id="codeview" hidden></div>`;
  }

  function section(kind, items, r) {
    const [title] = KINDS[kind] || [kind];
    const hosts = trafficHosts();
    const rows = items.map((f, i) => {
      const linked = kind === "endpoint" && hostLinked(f.value, hosts);
      return `<tr class="fr" data-file="${esc(f.file)}" data-line="${f.line}">
        <td class="fc-sev"><span class="dot ${SEV[f.sev]}" title="${f.sev}"></span></td>
        <td class="fc-sub">${esc(f.subtype)}${linked ? ` <span class="xlink" data-host="${esc(linked)}" title="Seen in captured traffic — show it">● traffic</span>` : ""}</td>
        <td class="fc-val mono">${esc(f.value)}</td>
        <td class="fc-loc mono" title="Open ${esc(f.file)}:${f.line}">${esc(shortFile(f.file))}:${f.line}</td>
      </tr>`;
    }).join("");
    return `<details class="rp-sec" id="sec-${kind}" open><summary>${title} <i>${items.length}</i></summary>
      <table class="findings">${rows}</table></details>`;
  }

  function trafficHosts() {
    const set = new Set();
    for (const f of (typeof S !== "undefined" ? S.flows : [])) set.add(f.h);
    return set;
  }
  function hostLinked(url, hosts) {
    const h = hostFromURL(url);
    if (!h) return null;
    for (const t of hosts) if (t === h || t.endsWith("." + h) || h.endsWith("." + t)) return h;
    return null;
  }
  function hostFromURL(u) {
    const m = /^[a-z]+:\/\/([^\/:?#]+)/i.exec(u);
    return m ? m[1].toLowerCase() : "";
  }

  function wireReport(box, r) {
    box.querySelector("#manual-hide")?.addEventListener("click", () => { showManual = false; save(); renderReport(); });
    box.querySelector("#manual-show")?.addEventListener("click", () => { showManual = true; save(); renderReport(); });
    box.querySelector("#emu-open")?.addEventListener("click", () => openEmuPicker(r));
    box.querySelectorAll("[data-jump]").forEach(c => c.onclick = () => {
      const sec = box.querySelector("#sec-" + c.dataset.jump);
      if (sec) { sec.open = true; sec.scrollIntoView({ behavior: "smooth", block: "start" }); }
    });
    box.querySelectorAll(".fr").forEach(row => row.onclick = e => {
      if (e.target.dataset.host) { crossLink(e.target.dataset.host); return; }
      openCode(r.id, row.dataset.file, +row.dataset.line);
    });
    renderEmu(); // show the emulator panel state for this report
  }

  // ---------------------------------------------------------------- emulator

  async function openEmuPicker(r) {
    const panel = $("#emu-panel");
    if (!panel) return;
    if (!emuDevices) {
      panel.innerHTML = `<div class="emu-box">Loading devices…</div>`;
      emuDevices = await (await fetch("/api/emulator/devices")).json();
    }
    if (!emuDevices.available) {
      panel.innerHTML = `<div class="emu-box warn">No Android SDK found. Install Android Studio (with an emulator / AVD and the platform-tools) so Sift can launch the app, then reopen Sift.</div>`;
      return;
    }
    const avds = emuDevices.avds || [];
    const running = emuDevices.running || [];
    if (!avds.length && !running.length) {
      panel.innerHTML = `<div class="emu-box warn">No virtual devices found. Create one in Android Studio (Device Manager), then reopen.</div>`;
      return;
    }
    const opts = [...running.map(s => `<option value="${esc(s)}">${esc(s)} (running)</option>`),
                  ...avds.map(a => `<option value="${esc(a)}">${esc(a)}</option>`)].join("");
    const fridaOk = emuDevices.fridaPython;
    const unpinRow = `<label class="emu-check ${fridaOk ? "" : "off"}" ${fridaOk ? "" : `title="${esc(emuDevices.fridaReason || "")}"`}>
        <input type="checkbox" id="emu-unpin" ${fridaOk ? "" : "disabled"}>
        <span>Bypass SSL pinning (Frida) <span class="muted small">${fridaOk ? "— decrypts pinned apps like TikTok; needs a rooted AVD with frida-server" : "— needs <code>pip install frida-tools</code> on this PC"}</span></span>
      </label>`;
    panel.innerHTML = `<div class="emu-box">
      <div class="emu-row">
        <b>Run in emulator</b>
        <select id="emu-avd">${opts}</select>
        <button id="emu-launch" class="btn primary">Launch</button>
        <button id="emu-cancel" class="link">Cancel</button>
      </div>
      ${unpinRow}
      <div class="muted small">Sift boots the device, routes its traffic through the proxy, trusts its certificate, installs this app and opens it. Traffic appears in the Traffic tab, tagged with the app.</div>
    </div>`;
    panel.querySelector("#emu-cancel").onclick = () => { panel.innerHTML = ""; };
    panel.querySelector("#emu-launch").onclick = async () => {
      const avd = panel.querySelector("#emu-avd").value;
      const unpin = panel.querySelector("#emu-unpin")?.checked ? "1" : "0";
      const res = await post("/api/emulator/launch", { report: r.id, avd, unpin });
      if (!res.ok) { toast("Couldn't launch: " + (await res.text())); return; }
      emu = await res.json();
      renderEmu();
    };
  }

  function renderEmu() {
    const panel = $("#emu-panel");
    if (!panel) return;
    const st = emu.state;
    if (!st || st === "idle") { emuDevices = null; panel.innerHTML = ""; return; }
    const busy = st === "booting" || st === "installing" || st === "stopping";
    const spinner = busy ? `<span class="spin-sm"></span>` : (st === "running" ? `<span class="live-dot"></span>` : "");
    const title = { booting: "Starting emulator", installing: "Setting up", running: "Running", stopping: "Stopping", error: "Failed" }[st] || st;
    const fridaBadge = emu.fridaOn ? `<span class="frida-badge" title="SSL pinning bypassed — HTTPS is decrypted">🔓 unpinned</span>` : (emu.unpin && busy ? `<span class="muted small">starting Frida…</span>` : "");
    panel.innerHTML = `<div class="emu-box ${st === "error" ? "warn" : "live"}">
      <div class="emu-row">${spinner}<b>${title}${emu.appName ? " · " + esc(emu.appName) : ""}</b>
        ${emu.serial ? `<span class="muted mono small">${esc(emu.serial)}</span>` : ""}
        ${fridaBadge}
        <span class="grow"></span>
        ${st === "running" ? `<button id="emu-traffic" class="btn">View traffic</button>` : ""}
        ${st !== "stopping" && st !== "idle" ? `<button id="emu-stop" class="btn">${st === "error" ? "Dismiss" : "Stop"}</button>` : ""}
      </div>
      ${emu.message ? `<div class="muted small">${esc(emu.message)}</div>` : ""}
    </div>`;
    panel.querySelector("#emu-stop")?.addEventListener("click", async () => {
      if (st === "error") { emu = {}; renderEmu(); return; }
      await post("/api/emulator/stop");
    });
    panel.querySelector("#emu-traffic")?.addEventListener("click", () => {
      switchView("traffic");
      if (emu.appName) {
        const q = $("#q");
        if (q) { q.value = "app:" + emu.appName.split(" (")[0]; q.dispatchEvent(new Event("input", { bubbles: true })); }
      }
    });
  }

  function crossLink(host) {
    switchView("traffic");
    const q = $("#q");
    if (q) { q.value = "host:" + host; q.dispatchEvent(new Event("input", { bubbles: true })); }
    toast("Showing traffic for " + host);
  }

  async function openCode(id, file, line) {
    const view = $("#codeview");
    view.hidden = false;
    view.innerHTML = `<div class="cv-head"><span class="mono">${esc(file)}</span><span class="grow"></span><button class="cv-x">✕</button></div><div class="cv-body"><p class="muted pad">Loading…</p></div>`;
    view.querySelector(".cv-x").onclick = () => { view.hidden = true; };
    try {
      const data = await (await fetch(`/api/apps/reports/${id}/file?path=${encodeURIComponent(file)}&line=${line}`)).json();
      view.querySelector(".cv-body").innerHTML = data.html;
      const target = view.querySelector("#L" + line);
      if (target) { target.classList.add("hl"); target.scrollIntoView({ block: "center" }); }
    } catch {
      view.querySelector(".cv-body").innerHTML = `<p class="bad pad">Couldn't open this file.</p>`;
    }
  }

  function save() { try { localStorage.setItem("sift-manual", showManual ? "1" : "0"); } catch {} }
  function shortFile(f) { const p = f.split("/"); return p.length > 2 ? "…/" + p.slice(-2).join("/") : f; }
  function fmtBytes(n) { return n < 1048576 ? (n / 1024).toFixed(0) + " KB" : (n / 1048576).toFixed(1) + " MB"; }

  return { activate };
})();
window.Apps = Apps;

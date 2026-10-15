// Sender view: edit any request as raw HTTP text and send it again, through whichever route
// you choose. The sending, parsing and proxying all happen in Go; this file is the editor,
// the tab strip and the response pane. Shares globals ($, esc, post, toast, switchView) with
// app.js.
"use strict";

const Sender = (() => {
  let tabs = [];
  let routes = [];
  let ifaces = [];
  let cur = "";          // open tab id
  let hist = [];         // history of the open tab
  let shown = null;      // entry currently in the response pane
  let resMode = "raw";
  let activated = false;
  let saveTimer = 0;

  const el = {};
  const pick = () => {
    el.tabs = $("#sendtabs"); el.raw = $("#send-raw"); el.res = $("#send-res");
    el.target = $("#send-target"); el.route = $("#send-route"); el.cl = $("#send-cl");
    el.meta = $("#send-meta"); el.hist = $("#sendhist"); el.go = $("#send-go");
  };

  // ---------------------------------------------------------------- state

  async function activate() {
    if (!activated) { pick(); wire(); activated = true; }
    await loadState();
  }

  async function loadState() {
    const st = await (await fetch("/api/sender/state")).json();
    tabs = st.tabs || []; routes = st.routes || []; ifaces = st.interfaces || [];
    if (!tabs.some(t => t.id === cur)) cur = tabs.length ? tabs[0].id : "";
    renderTabs(); renderRoutes(); loadTab();
    await loadHistory();
  }

  const tab = () => tabs.find(t => t.id === cur);

  function loadTab() {
    const t = tab();
    if (!t) return;
    el.raw.value = t.raw || "";
    el.target.value = t.target || "";
    el.route.value = t.route || "direct";
    if (!el.route.value) el.route.value = "direct";
  }

  // Everything typed is saved server-side, so a reload or restart keeps it.
  function save() {
    const t = tab();
    if (!t) return;
    t.raw = el.raw.value; t.target = el.target.value; t.route = el.route.value;
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => post("/api/sender/tabs/save",
      { id: t.id, raw: t.raw, target: t.target, route: t.route }), 400);
  }

  // ---------------------------------------------------------------- tab strip

  function renderTabs() {
    let html = "";
    for (const t of tabs) {
      html += `<div class="st${t.id === cur ? " on" : ""}" data-tab="${esc(t.id)}" title="Double-click to rename">` +
        `<span class="st-n">${esc(t.name || "Request")}</span>` +
        `<button class="st-x" data-close="${esc(t.id)}" title="Close">×</button></div>`;
    }
    html += `<button class="st-add" id="send-add" title="New request">+</button>`;
    el.tabs.innerHTML = html;
  }

  function renderRoutes() {
    el.route.innerHTML = routes.map(r => `<option value="${esc(r.id)}">${esc(r.name)}</option>`).join("") +
      `<option value="__manage">Manage routes…</option>`;
    const t = tab();
    el.route.value = t && routes.some(r => r.id === t.route) ? t.route : "direct";
  }

  async function newTab(fromFlow) {
    const res = await post("/api/sender/tabs/new", fromFlow ? { from: fromFlow } : {});
    const data = await res.json();
    tabs = data.tabs; cur = data.tab.id;
    renderTabs(); renderRoutes(); loadTab(); await loadHistory();
    el.raw.focus();
  }

  async function closeTab(id) {
    const data = await (await post("/api/sender/tabs/close", { id })).json();
    tabs = data.tabs;
    if (cur === id) cur = tabs[0].id;
    renderTabs(); renderRoutes(); loadTab(); await loadHistory();
  }

  function rename(id) {
    const t = tabs.find(x => x.id === id);
    if (!t) return;
    const name = prompt("Name this request", t.name || "Request");
    if (name === null) return;
    t.name = name.trim() || "Request";
    post("/api/sender/tabs/save", { id: t.id, name: t.name, raw: t.raw, target: t.target, route: t.route });
    renderTabs();
  }

  // ---------------------------------------------------------------- sending

  async function send() {
    const t = tab();
    if (!t) return;
    save();
    el.go.disabled = true;
    el.meta.textContent = "Sending…";
    try {
      const res = await post("/api/sender/send", {
        id: t.id, raw: el.raw.value, target: el.target.value,
        route: el.route.value, update_cl: el.cl.checked ? "1" : "0",
      });
      const e = await res.json();
      if (e.error) { el.meta.innerHTML = `<span class="bad">${esc(e.error)}</span>`; return; }
      shown = e;
      await loadHistory();
      showEntry(e);
    } finally {
      el.go.disabled = false;
    }
  }

  async function loadHistory() {
    if (!cur) { hist = []; el.hist.innerHTML = ""; return; }
    hist = await (await fetch(`/api/sender/history?id=${encodeURIComponent(cur)}`)).json();
    renderHistory();
  }

  function renderHistory() {
    if (!hist.length) {
      el.hist.innerHTML = `<span class="muted hist-empty">No sends yet — Ctrl+Enter sends.</span>`;
      return;
    }
    el.hist.innerHTML = `<span class="muted hist-lbl">History</span>` + hist.map(e => {
      const cls = e.err ? "c5" : "c" + Math.min(Math.floor(e.status / 100), 5);
      const label = e.err ? "failed" : e.status;
      const on = shown && shown.n === e.n ? " on" : "";
      return `<button class="he${on}" data-entry="${e.n}" title="${esc(e.err || e.target)}">` +
        `<b class="${cls}">${esc(String(label))}</b> <i>${e.dur} ms</i> <i>${fmtSize(e.size)}</i></button>`;
    }).reverse().join("");
  }

  async function openEntry(n) {
    const e = await (await fetch(`/api/sender/entry?id=${encodeURIComponent(cur)}&n=${n}`)).json();
    shown = e;
    renderHistory();
    showEntry(e);
  }

  // ---------------------------------------------------------------- response pane

  function splitRaw(raw) {
    const i = raw.indexOf("\r\n\r\n");
    if (i < 0) return [raw, ""];
    return [raw.slice(0, i), raw.slice(i + 4)];
  }

  function showEntry(e) {
    const bits = [];
    if (e.err) bits.push(`<span class="bad">${esc(e.err)}</span>`);
    else bits.push(`<b>${e.status} ${esc(e.reason || "")}</b>`, `${e.dur} ms`, fmtSize(e.size));
    bits.push(esc(e.route));
    if (e.note) bits.push(`<span class="warn">${esc(e.note)}</span>`);
    if (e.truncated) bits.push(`<span class="warn">shown to 2 MB of ${fmtSize(e.truncated)}</span>`);
    el.meta.innerHTML = bits.join(" · ");
    document.querySelectorAll("[data-sres]").forEach(b => b.classList.toggle("on", b.dataset.sres === resMode));
    renderRes();
  }

  function renderRes() {
    const e = shown;
    if (!e) { el.res.innerHTML = `<p class="placeholder">Send the request to see the response.</p>`; return; }
    if (e.err && !e.res) { el.res.innerHTML = `<p class="placeholder bad">${esc(e.err)}</p>`; return; }
    const [head, body] = splitRaw(e.res || "");
    const pre = document.createElement("pre");
    pre.className = "code wrap sendout";
    switch (resMode) {
      case "headers":
        pre.textContent = head;
        break;
      case "pretty":
        pre.textContent = head + "\n\n" + beautify(body);
        break;
      case "diff":
        showDiff(body);
        return;
      case "render": {
        if (!e.flow) { pre.textContent = body; break; }
        const f = document.createElement("iframe");
        f.className = "frame sendframe";
        f.src = `/api/flows/${e.flow}/body/res`;
        el.res.innerHTML = "";
        el.res.append(f);
        return;
      }
      default:
        pre.textContent = e.res || "";
    }
    el.res.innerHTML = "";
    el.res.append(pre);
  }

  function beautify(body) {
    const t = body.trim();
    if (!t) return body;
    try {
      if (t[0] === "{" || t[0] === "[") return JSON.stringify(JSON.parse(t), null, 2);
    } catch {}
    return body;
  }

  // A line-by-line diff against the send before this one, so you can see what your edit
  // changed. The earlier response is fetched on demand and cached on its history entry.
  async function showDiff(body) {
    const box = document.createElement("pre");
    box.className = "code wrap sendout diff";
    el.res.innerHTML = "";
    el.res.append(box);
    const i = hist.findIndex(e => shown && e.n === shown.n);
    if (i <= 0) { box.textContent = "No earlier send in this tab to compare against."; return; }
    const earlier = hist[i - 1];
    if (earlier.raw === undefined) {
      box.textContent = "Loading the earlier response…";
      const e = await (await fetch(`/api/sender/entry?id=${encodeURIComponent(cur)}&n=${earlier.n}`)).json();
      earlier.raw = e.res || "";
      if (resMode !== "diff") return;
    }
    const oldLines = splitRaw(earlier.raw)[1].split("\n");
    const newLines = body.split("\n");
    const inOld = new Set(oldLines), inNew = new Set(newLines);
    let out = "", changed = false;
    for (const l of oldLines) if (!inNew.has(l)) { out += `<span class="dm">− ${esc(l)}</span>\n`; changed = true; }
    for (const l of newLines) {
      if (inOld.has(l)) out += `  ${esc(l)}\n`;
      else { out += `<span class="dp">+ ${esc(l)}</span>\n`; changed = true; }
    }
    box.innerHTML = changed ? out : "Identical to the previous response.";
  }

  // ---------------------------------------------------------------- routes dialog

  function routesModal() {
    const own = routes.filter(r => r.id !== "direct" && r.id !== "sift"); // built-ins aren't editable
    const rows = own.length ? own.map(r => `<tr>
        <td>${esc(r.name)}</td>
        <td class="mono">${esc(r.kind)}${r.host ? " " + esc(r.host) + ":" + (r.port || "") : ""}</td>
        <td class="mono">${r.bind ? esc(r.bind) : "any"}</td>
        <td class="end"><button class="link" data-redit="${esc(r.id)}">Edit</button>
          <button class="link bad" data-rdel="${esc(r.id)}">Delete</button></td></tr>`).join("")
      : `<tr><td colspan="4" class="muted">No saved routes yet. Direct and “Through Sift” are always available.</td></tr>`;
    const ifaceOpts = `<option value="">Any (let Windows choose)</option>` +
      ifaces.map(i => `<option value="${esc(i.ip)}">${esc(i.name)} — ${esc(i.ip)}</option>`).join("");
    $("#modal").innerHTML = `<div class="overlay" data-backdrop><div class="modal wide">
      <header class="mh"><h2>Sender routes</h2><button class="x" data-close>✕</button></header>
      <div class="form">
        <p class="muted">A route decides how a request leaves this machine: straight out, back through
          Sift so your rules and breakpoints apply, or via an upstream proxy. Routes are saved in
          <span class="mono">%USERPROFILE%\\.sift\\sender.json</span>, never in the project.</p>
        <table class="rules"><thead><tr><th>Name</th><th>Proxy</th><th>Send from</th><th></th></tr></thead>
          <tbody>${rows}</tbody></table>
        <h3>Add or edit a route</h3>
        <form id="rform">
          <input type="hidden" name="id" value="">
          <div class="row2">
            <label>Name<input name="name" placeholder="Office SOCKS" autofocus></label>
            <label>Type<select name="kind">
              <option value="http">HTTP / HTTPS proxy</option>
              <option value="socks5">SOCKS5 proxy</option>
              <option value="direct">Direct (interface only)</option>
            </select></label>
          </div>
          <div class="row2">
            <label>Proxy host<input name="host" class="mono" placeholder="127.0.0.1"></label>
            <label>Port<input name="port" class="mono" placeholder="8080"></label>
          </div>
          <div class="row2">
            <label>Username <span class="muted">(optional)</span><input name="user" autocomplete="off"></label>
            <label>Password <span class="muted">(optional)</span><input name="pass" type="password" autocomplete="new-password"></label>
          </div>
          <div class="row3">
            <label>Send from<select name="bind">${ifaceOpts}</select></label>
            <label>Certificates<select name="verify">
              <option value="">Follow Settings</option>
              <option value="off">Accept any certificate</option>
              <option value="on">Always verify</option>
            </select></label>
            <label>Timeout (s)<input name="timeout" class="mono" placeholder="30"></label>
          </div>
          <label class="check"><input type="checkbox" name="follow" value="1"> Follow redirects</label>
          <p class="note bad" id="rerr" hidden></p>
          <div class="actions"><button type="button" class="btn" data-close>Close</button>
            <button class="btn primary">Save route</button></div>
        </form>
      </div>
    </div></div>`;
    const form = $("#rform");
    form.onsubmit = async ev => {
      ev.preventDefault();
      const data = await (await post("/api/sender/routes/save", new URLSearchParams(new FormData(form)))).json();
      if (data.error) { const p = $("#rerr"); p.textContent = data.error; p.hidden = false; return; }
      routes = data.routes;
      renderRoutes();
      el.route.value = data.saved;
      save();
      toast("Route saved");
      routesModal();
    };
    form.addEventListener("reset", () => { form.elements.id.value = ""; });
  }

  // Edit/Delete inside the routes dialog. Bound once, on the container that survives redraws.
  async function routesClick(ev) {
    const edit = ev.target.closest("[data-redit]"), del = ev.target.closest("[data-rdel]");
    const form = $("#rform");
    if (edit && form) {
      const r = routes.find(x => x.id === edit.dataset.redit);
      if (!r) return;
      for (const [k, v] of Object.entries({ id: r.id, name: r.name, kind: r.kind, host: r.host,
        port: r.port || "", user: r.user, bind: r.bind, verify: r.verify, timeout: r.timeout || "" })) {
        if (form.elements[k]) form.elements[k].value = v ?? "";
      }
      form.elements.follow.checked = !!r.follow;
      form.elements.name.focus();
    } else if (del) {
      if (!confirm("Delete this route?")) return;
      routes = (await (await post("/api/sender/routes/delete", { id: del.dataset.rdel })).json()).routes;
      renderRoutes();
      routesModal();
    }
  }

  // ---------------------------------------------------------------- wiring

  function wire() {
    el.tabs.addEventListener("click", e => {
      if (e.target.closest("#send-add")) return newTab();
      const x = e.target.closest("[data-close]");
      if (x) return closeTab(x.dataset.close);
      const t = e.target.closest("[data-tab]");
      if (t && t.dataset.tab !== cur) {
        save();
        cur = t.dataset.tab;
        shown = null;
        renderTabs(); loadTab(); renderRes(); el.meta.textContent = "";
        loadHistory();
      }
    });
    el.tabs.addEventListener("dblclick", e => {
      const t = e.target.closest("[data-tab]");
      if (t) rename(t.dataset.tab);
    });
    el.raw.addEventListener("input", save);
    el.target.addEventListener("input", save);
    el.route.addEventListener("change", () => {
      if (el.route.value === "__manage") { renderRoutes(); routesModal(); return; }
      save();
    });
    el.go.onclick = send;
    $("#send-routes").onclick = routesModal;
    $("#modal").addEventListener("click", routesClick);
    $("#sendmodes").addEventListener("click", e => {
      const b = e.target.closest("[data-sres]");
      if (!b) return;
      resMode = b.dataset.sres;
      document.querySelectorAll("[data-sres]").forEach(x => x.classList.toggle("on", x === b));
      renderRes();
    });
    $("#send-copy").onclick = () => shown && navigator.clipboard.writeText(shown.res || "").then(
      () => toast("Response copied"), () => toast("Clipboard not available"));
    $("#send-inspect").onclick = () => {
      if (!shown || !shown.flow) return toast("Nothing sent yet");
      switchView("traffic");
      select(shown.flow);
    };
    el.hist.addEventListener("click", e => {
      const b = e.target.closest("[data-entry]");
      if (b) openEntry(+b.dataset.entry);
    });
    // Ctrl+Enter sends from anywhere in the Sender.
    document.addEventListener("keydown", e => {
      if (!(e.ctrlKey || e.metaKey) || e.key !== "Enter") return;
      if ($("#sendview").hidden || $("#modal").innerHTML) return;
      e.preventDefault();
      send();
    });
    // Tab key indents instead of leaving the editor.
    el.raw.addEventListener("keydown", e => {
      if (e.key !== "Tab") return;
      e.preventDefault();
      const s = el.raw.selectionStart, t = el.raw.selectionEnd;
      el.raw.value = el.raw.value.slice(0, s) + "  " + el.raw.value.slice(t);
      el.raw.selectionStart = el.raw.selectionEnd = s + 2;
      save();
    });
  }

  // Called from the Traffic view: open a captured request in a new Sender tab.
  async function fromFlow(id) {
    switchView("sender");
    if (!activated) await activate();
    await newTab(id);
    toast("Opened in Sender");
  }

  return { activate, fromFlow };
})();

window.Sender = Sender;

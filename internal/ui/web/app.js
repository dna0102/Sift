"use strict";

const $ = (s, el = document) => el.querySelector(s);
const ROW = 22;

const S = {
  flows: [], byId: new Map(), view: [],
  sel: 0, scope: "", type: "", filter: null, bodyIds: null,
  sort: "id", asc: true, follow: true,
  expanded: new Set(), state: {},
  tabs: { req: "headers", res: "body", reqm: "", resm: "" },
};

const TYPES = { json: "JSON", html: "HTML", xml: "XML", js: "JS", css: "CSS", image: "Image", font: "Font", media: "Media",
  sse: "Stream", text: "Text", graphql: "GraphQL", ws: "WebSocket", tunnel: "Tunnel", tls: "TLS", other: "Other" };

function fmtSize(n) {
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  return (n / 1048576).toFixed(1) + " MB";
}
function fmtDur(ms) {
  if (ms < 0) return "";
  if (ms < 1000) return ms + " ms";
  if (ms < 60000) return (ms / 1000).toFixed(2) + " s";
  return Math.floor(ms / 60000) + "m " + Math.floor(ms / 1000) % 60 + "s";
}
function toast(text) {
  const t = document.createElement("div");
  t.className = "toast";
  t.textContent = text;
  $("#toasts").append(t);
  setTimeout(() => t.remove(), 3600);
}
function profileOptions(groups) {
  let html = `<option value="none">Go default (no impersonation)</option>`;
  for (const g of groups || []) {
    html += `<optgroup label="${esc(g.label)}">` +
      g.names.map(n => `<option value="${esc(n)}">${esc(n)}</option>`).join("") + `</optgroup>`;
  }
  return html;
}

function store(key, value) {
  try { return value === undefined ? localStorage.getItem(key) : localStorage.setItem(key, value); } catch { return null; }
}

async function post(url, data, multipart = false) {
  const body = multipart ? data : new URLSearchParams(data || {});
  const res = await fetch(url, { method: "POST", headers: { "X-Sift": "1" }, body });
  const msg = res.headers.get("X-Toast");
  if (msg) toast(decodeURIComponent(msg.replace(/\+/g, " ")));
  return res;
}

async function load() {
  const list = await (await fetch("/api/flows")).json();
  S.flows = list;
  S.byId = new Map(list.map(f => [f.id, f]));
  if (!S.byId.has(S.sel)) select(0);
  refresh(true);
}

function connect() {
  let opened = false;
  const es = new EventSource("/api/events");
  es.onopen = () => { if (opened) load(); opened = true; status(); };
  es.onerror = () => status("Reconnecting…");
  es.onmessage = e => apply(JSON.parse(e.data));
}

let detailTimer = 0;
function apply(b) {
  if (b.clear) {
    S.flows = S.flows.filter(f => f.st === "paused");
    S.byId = new Map(S.flows.map(f => [f.id, f]));
    if (!S.byId.has(S.sel)) select(0);
  }
  if (b.rm) {
    const rm = new Set(b.rm);
    S.flows = S.flows.filter(f => !rm.has(f.id));
    for (const id of rm) S.byId.delete(id);
    if (rm.has(S.sel)) select(0);
  }
  if (b.up) {
    let unordered = false;
    for (const f of b.up) {
      const old = S.byId.get(f.id);
      if (old) {
        Object.assign(old, f);
      } else {
        if (S.flows.length && S.flows[S.flows.length - 1].id > f.id) unordered = true;
        S.flows.push(f);
        S.byId.set(f.id, f);
      }
      if (f.id === S.sel && !detailTimer) detailTimer = setTimeout(() => { detailTimer = 0; loadDetail(true); }, 600);
    }
    if (unordered) S.flows.sort((a, b) => a.id - b.id);
  }
  if (b.state) applyState(b.state);
  refresh(b.clear || b.rm || b.up);
}

function compileFilter(q) {
  const tests = [];
  S.bodyIds = {};
  const wantContent = [];
  for (const m of q.matchAll(/(-?)(?:(\w+):)?("[^"]*"|\S+)/g)) {
    const neg = m[1] === "-", key = (m[2] || "").toLowerCase(), val = m[3].replace(/^"|"$/g, "").toLowerCase();
    if (!val) continue;
    let t;
    switch (key) {
      case "method": case "m": { const set = new Set(val.split(",")); t = f => set.has(f.m.toLowerCase()); break; }
      case "status": case "s":
        if (/^[1-5]xx$/.test(val)) t = f => Math.floor(f.s / 100) === +val[0];
        else if (val === "err") t = f => f.st === "error";
        else t = f => String(f.s) === val;
        break;
      case "host": case "h": t = f => f.h.includes(val); break;
      case "path": case "p": t = f => f.p.toLowerCase().includes(val); break;
      case "type": case "t": t = f => f.t === val || (TYPES[f.t] || "").toLowerCase() === val; break;
      case "app": case "a": t = f => (f.a || "").toLowerCase().includes(val); break;
      case "body": case "b": {
        wantContent.push(val);
        t = f => contentHas(val, f.id);
        break;
      }
      default: {
        wantContent.push(val);
        t = f => (f.m + " " + f.h + f.p + " " + f.s + " " + (f.a || "")).toLowerCase().includes(val) || contentHas(val, f.id);
      }
    }
    tests.push(neg ? f => !t(f) : t);
  }
  if (wantContent.length) searchBodies(wantContent);
  return tests.length ? f => tests.every(t => t(f)) : null;
}

function contentHas(term, id) {
  const set = S.bodyIds && S.bodyIds[term];
  return set === undefined ? false : set.has(id);
}

let searchSeq = 0;
async function searchBodies(terms) {
  const seq = ++searchSeq;
  const uniq = [...new Set(terms)];
  const results = await Promise.all(uniq.map(async term => {
    const ids = await (await post("/api/search", { q: term })).json();
    return [term, new Set(ids)];
  }));
  if (seq !== searchSeq) return;
  S.bodyIds = Object.fromEntries(results);
  refresh(true);
}

function inScope(f) {
  const sc = S.scope;
  if (!sc) return true;
  const [kind, v] = [sc.slice(0, sc.indexOf(":")), sc.slice(sc.indexOf(":") + 1)];
  if (kind === "host") return f.h === v;
  if (kind === "group") return f.h === v || f.h.endsWith("." + v);
  if (kind === "app") return f.a === v;
  if (kind === "pinned") return (S.state.pinned || []).some(p => f.h === p || f.h.endsWith("." + p));
  return true;
}

function matchType(f) {
  switch (S.type) {
    case "": return true;
    case "err": return f.st === "error" || f.s >= 400 || f.k === "tls";
    case "media": return f.t === "media" || f.t === "sse";
    case "other": return ["other", "text", "", "tunnel", "tls", "xml"].includes(f.t);
    default: return f.t === S.type;
  }
}

const SORTS = {
  status: f => f.s || (f.st === "error" ? 999 : 0), method: f => f.m, host: f => f.h, path: f => f.p,
  type: f => f.t, size: f => f.rs, dur: f => f.d, app: f => f.a || "",
};

function recompute() {
  const fl = S.filter;
  let v = S.flows.filter(f => inScope(f) && matchType(f) && (!fl || fl(f)));
  if (S.sort !== "id") {
    const key = SORTS[S.sort];
    v.sort((a, b) => { const x = key(a), y = key(b); return (x < y ? -1 : x > y ? 1 : a.id - b.id) * (S.asc ? 1 : -1); });
  } else if (!S.asc) v.reverse();
  S.view = v;
}

const list = $("#list"), spacer = $("#spacer"), pool = [];
let frame = 0, sideTimer = 0, dirty = false;

function refresh(changed) {
  if (changed) dirty = true;
  if (!frame) frame = requestAnimationFrame(() => {
    frame = 0;
    if (dirty) { recompute(); dirty = false; }
    renderRows();
    status();
  });
  if (!sideTimer) sideTimer = setTimeout(() => { sideTimer = 0; renderSide(); }, 400);
}

function statusCell(f) {
  if (f.k === "tunnel") return ["tunnel", "c0"];
  if (f.k === "tls") return ["failed", "c5"];
  if (f.st === "paused") return ["paused", "c5"];
  if (f.s) return [String(f.s), "c" + Math.min(Math.floor(f.s / 100), 5)];
  if (f.st === "error") return ["failed", "c5"];
  return ["…", "c0"];
}

function pathCell(f) {
  if (f.k === "tunnel") return !f.n ? "not decrypted" : f.n.startsWith("decrypted") ? f.n : "not decrypted: " + f.n;
  if (f.k === "tls") return "certificate rejected by the app";
  return f.p;
}

function renderRows() {
  const v = S.view, n = v.length;
  spacer.style.height = n * ROW + "px";
  $("#empty").hidden = S.flows.length > 0;
  if (S.follow && S.sort === "id") list.scrollTop = S.asc ? list.scrollHeight : 0;
  const top = list.scrollTop, first = Math.max(0, Math.floor(top / ROW) - 5);
  const last = Math.min(n, Math.ceil((top + list.clientHeight) / ROW) + 5);
  while (pool.length < last - first) {
    const r = document.createElement("div");
    r.className = "row";
    r.innerHTML = '<span class="id"></span><span></span><span class="me"></span><span class="ho"></span><span class="pa"><b></b><i></i></span><span class="ty"></span><span class="sz"></span><span class="du"></span><span class="ap"></span>';
    spacer.append(r);
    pool.push(r);
  }
  for (let i = 0; i < pool.length; i++) {
    const r = pool[i], idx = first + i, f = v[idx];
    if (!f) { if (r.style.display !== "none") { r.style.display = "none"; r.sig = ""; } continue; }
    const sig = `${idx}|${f.id}|${f.st}|${f.s}|${f.rs}|${f.d}|${f.ws}|${(f.g || []).length}|${S.sel === f.id}`;
    if (r.sig === sig) continue;
    r.sig = sig;
    r.style.display = "";
    r.style.transform = `translateY(${idx * ROW}px)`;
    r.dataset.id = f.id;
    const bad = f.k === "tls" || (f.st === "error" && !f.s);
    r.className = "row" + (idx % 2 ? " z" : "") + (S.sel === f.id ? " sel" : "") + (f.k === "tunnel" ? " dim" : "") + (bad ? " bad" : "");
    const c = r.children, [st, cls] = statusCell(f);
    c[0].textContent = f.id;
    c[1].textContent = st;
    c[1].className = cls;
    c[2].textContent = f.m;
    c[3].textContent = f.po && f.po !== 80 && f.po !== 443 ? f.h + ":" + f.po : f.h;
    c[4].firstChild.textContent = pathCell(f);
    c[4].lastChild.textContent = (f.g || []).join(" · ");
    c[4].title = f.sc + "://" + f.h + f.p;
    c[5].textContent = (TYPES[f.t] || "") + (f.ws ? " · " + f.ws : "");
    c[6].textContent = f.d >= 0 || f.rs ? fmtSize(f.rs) : "";
    c[7].textContent = fmtDur(f.d);
    c[8].textContent = f.a || "";
  }
}

list.addEventListener("scroll", () => {
  S.follow = S.asc ? list.scrollTop + list.clientHeight >= list.scrollHeight - ROW * 2 : list.scrollTop < ROW;
  refresh();
});
list.addEventListener("click", e => {
  const r = e.target.closest(".row");
  if (r) select(+r.dataset.id);
});

function select(id) {
  if (S.sel !== id) S.tabs.reqm = S.tabs.resm = "";
  S.sel = id;
  refresh();
  loadDetail(false);
}

function move(step) {
  const v = S.view;
  if (!v.length) return;
  let i = v.findIndex(f => f.id === S.sel);
  i = i < 0 ? (step > 0 ? 0 : v.length - 1) : Math.max(0, Math.min(v.length - 1, i + step));
  select(v[i].id);
  const y = i * ROW;
  if (y < list.scrollTop) list.scrollTop = y;
  else if (y + ROW > list.scrollTop + list.clientHeight) list.scrollTop = y + ROW - list.clientHeight;
}

$(".row.head").addEventListener("click", e => {
  const key = e.target.dataset.sort;
  if (!key) return;
  if (S.sort === key) S.asc = !S.asc;
  else { S.sort = key; S.asc = key === "id" || key === "host" || key === "path" || key === "method" || key === "app"; }
  document.querySelectorAll(".row.head span").forEach(s => {
    s.classList.toggle("sorted", s.dataset.sort === S.sort);
    s.classList.toggle("asc", s.dataset.sort === S.sort && S.asc);
  });
  S.follow = S.sort === "id";
  refresh(true);
});

const detail = $("#detail");
let shownId = 0;

async function loadDetail(isUpdate) {
  const id = S.sel;
  if (!id) { detail.innerHTML = '<p class="placeholder">Select a request.</p>'; shownId = 0; return; }
  const t = S.tabs;
  const res = await fetch(`/ui/detail/${id}?req=${t.req}&res=${t.res}&reqm=${t.reqm}&resm=${t.resm}`);
  if (id !== S.sel) return;
  if (!res.ok) { detail.innerHTML = '<p class="placeholder">This request is no longer available.</p>'; return; }
  const html = await res.text();
  const keep = isUpdate && shownId === id ? [...detail.querySelectorAll(".pane-body")].map(p => p.scrollTop) : [];
  detail.innerHTML = html;
  detail.querySelectorAll(".pane-body").forEach((p, i) => { p.scrollTop = keep[i] || 0; });
  shownId = id;
}

detail.addEventListener("click", e => {
  const tab = e.target.closest("[data-tab]"), mode = e.target.closest("[data-mode]");
  if (tab) {
    const [side, name] = tab.dataset.tab.split(":");
    S.tabs[side] = name;
    loadDetail(false);
  } else if (mode) {
    const [side, name] = mode.dataset.mode.split(":");
    S.tabs[side + "m"] = name;
    S.tabs[side] = "body";
    loadDetail(true);
  }
});

const sideList = $("#sidelist"), sideQ = $("#sideq");
const isIP = h => /^[\d.]+$/.test(h) || h.includes(":");

function baseDomain(h) {
  const p = h.split(".");
  if (p.length <= 2) return h;
  const two = new Set(["co", "com", "net", "org", "gov", "ac", "edu"]);
  return p.slice(p[p.length - 1].length === 2 && two.has(p[p.length - 2]) ? -3 : -2).join(".");
}

function esc(s) { return String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]); }

function item(scope, name, count, extra = "", twisty = "", pin = "") {
  const pinned = pin && (S.state.pinned || []).includes(pin);
  const star = pin ? `<span class="star${pinned ? " on" : ""}" data-pin="${esc(pin)}" title="${pinned ? "Unpin" : "Pin"}">${pinned ? "★" : "☆"}</span>` : "";
  const off = (scope.startsWith("app:") && (S.state.excludedApps || []).includes(scope.slice(4))) ? '<span class="nd" title="Not decrypted">no decrypt</span>' : "";
  return `<div class="si${S.scope === scope ? " on" : ""}${extra}" data-scope="${esc(scope)}">${twisty}<span class="nm">${esc(name)}</span>${off}${star}<span class="ct">${count}</span></div>`;
}

let lastSide = "";
function renderSide() {
  const q = sideQ.value.toLowerCase().trim();
  const hosts = new Map(), apps = new Map();
  for (const f of S.flows) {
    hosts.set(f.h, (hosts.get(f.h) || 0) + 1);
    if (f.a) apps.set(f.a, (apps.get(f.a) || 0) + 1);
  }
  const groups = new Map(), ips = [];
  for (const [h, c] of hosts) {
    if (q && !h.includes(q)) continue;
    if (isIP(h)) { ips.push([h, c]); continue; }
    const b = baseDomain(h);
    if (!groups.has(b)) groups.set(b, []);
    groups.get(b).push([h, c]);
  }
  let html = item("", "All requests", S.flows.length);
  const pinned = S.state.pinned || [];
  if (pinned.length) {
    html += '<div class="sh">Pinned</div>';
    for (const p of pinned) {
      if (p.startsWith("app:")) { html += item(p, p.slice(4), apps.get(p.slice(4)) || 0, "", "", p); continue; }
      let c = 0;
      for (const [h, n] of hosts) if (h === p || h.endsWith("." + p)) c += n;
      html += item("group:" + p, p, c, "", "", p);
    }
  }
  const appList = [...apps].filter(([a]) => !q || a.toLowerCase().includes(q)).sort((a, b) => b[1] - a[1]);
  if (appList.length) {
    html += '<div class="sh">Apps</div>';
    for (const [a, c] of appList) html += item("app:" + a, a, c, "", "", "app:" + a);
  }
  if (groups.size) {
    html += '<div class="sh">Domains</div>';
    for (const b of [...groups.keys()].sort()) {
      const kids = groups.get(b).sort((x, y) => x[0] < y[0] ? -1 : 1);
      const total = kids.reduce((s, k) => s + k[1], 0);
      if (kids.length === 1) { html += item("host:" + kids[0][0], kids[0][0], total, "", '<span class="tw"></span>', kids[0][0]); continue; }
      const open = S.expanded.has(b) || !!q;
      html += item("group:" + b, b, total, "", `<span class="tw" data-toggle="${esc(b)}">${open ? "▾" : "▸"}</span>`, b);
      if (open) for (const [h, c] of kids) html += item("host:" + h, h, c, " child", "", h);
    }
  }
  if (ips.length) {
    html += '<div class="sh">IP addresses</div>';
    for (const [h, c] of ips.sort()) html += item("host:" + h, h, c);
  }
  if (html !== lastSide) { sideList.innerHTML = html; lastSide = html; }
}

sideList.addEventListener("click", e => {
  const star = e.target.closest("[data-pin]");
  if (star) { post("/api/hosts/pin", { host: star.dataset.pin }); return; }
  const tw = e.target.closest("[data-toggle]");
  if (tw) {
    const b = tw.dataset.toggle;
    S.expanded.has(b) ? S.expanded.delete(b) : S.expanded.add(b);
    renderSide();
    return;
  }
  const it = e.target.closest(".si");
  if (!it) return;
  S.scope = it.dataset.scope;
  renderSide();
  refresh(true);
});
sideQ.addEventListener("input", renderSide);

const ctxMenu = document.createElement("div");
ctxMenu.className = "ctxmenu";
ctxMenu.hidden = true;
document.body.append(ctxMenu);
sideList.addEventListener("contextmenu", e => {
  const it = e.target.closest(".si");
  if (!it || !it.dataset.scope) return;
  e.preventDefault();
  const scope = it.dataset.scope, kind = scope.slice(0, scope.indexOf(":")), v = scope.slice(scope.indexOf(":") + 1);
  const pinKey = kind === "app" ? scope : v;
  const pinned = (S.state.pinned || []).includes(pinKey);
  const items = [[pinned ? "Unpin" : "Pin", () => post("/api/hosts/pin", { host: pinKey })]];
  if (kind === "app") {
    const off = (S.state.excludedApps || []).includes(v);
    items.push([off ? `Decrypt ${v} again` : `Don't decrypt ${v}`, () => post("/api/apps/decrypt", { app: v })]);
  } else {
    const pattern = kind === "group" ? "*." + v : v;
    items.push([`Don't decrypt ${pattern}`, () => post("/api/hosts/decrypt", { host: pattern })]);
    items.push([`Block ${v}…`, () => openModal(`/ui/modal/rules?type=block&host=${encodeURIComponent((kind === "group" ? "*." : "") + v)}`)]);
  }
  items.push(["Delete these requests", () => post("/api/flows/delete", { ids: S.flows.filter(f => inScopeOf(scope, f)).map(f => f.id).join(",") })]);
  showCtxMenu(e, items);
});

function showCtxMenu(e, items) {
  ctxMenu.innerHTML = "";
  for (const it of items) {
    if (!it) { ctxMenu.append(document.createElement("hr")); continue; }
    const [label, fn] = it;
    const b = document.createElement("button");
    b.textContent = label;
    b.onclick = () => { ctxMenu.hidden = true; fn(); };
    ctxMenu.append(b);
  }
  ctxMenu.hidden = false;
  ctxMenu.style.left = Math.min(e.clientX, innerWidth - 230) + "px";
  ctxMenu.style.top = Math.min(e.clientY, innerHeight - ctxMenu.offsetHeight - 8) + "px";
}

list.addEventListener("contextmenu", e => {
  const row = e.target.closest(".row");
  if (!row) return;
  e.preventDefault();
  const id = +row.dataset.id, f = S.byId.get(id);
  if (!f) return;
  select(id);
  const url = f.sc + "://" + f.h + (f.po && f.po !== 80 && f.po !== 443 ? ":" + f.po : "") + f.p;
  const items = [["Send to Sender", () => window.Sender && window.Sender.fromFlow(id)]];
  if (f.k === "http") {
    items.push(["Replay as-is", () => post(`/api/flows/${id}/replay`)],
      ["Edit and send…", () => openModal(`/ui/modal/compose?from=${id}`)]);
  }
  items.push(null,
    ["Copy URL", () => copy(url)],
    ["Copy as cURL…", () => openModal(`/ui/modal/code?id=${id}&lang=curl`)],
    null,
    [`Breakpoint on ${f.h}…`, () => openModal(`/ui/modal/rules?type=breakpoint&from=${id}`)],
    [`Map local…`, () => openModal(`/ui/modal/rules?type=map_local&from=${id}`)],
    [`Block ${f.h}`, () => openModal(`/ui/modal/rules?type=block&host=${encodeURIComponent(f.h)}`)],
    [`Don't decrypt ${f.h}`, () => post("/api/hosts/decrypt", { host: f.h })],
    null,
    ["Delete", () => post("/api/flows/delete", { ids: id })]);
  showCtxMenu(e, items);
});
addEventListener("click", e => { if (!ctxMenu.contains(e.target)) ctxMenu.hidden = true; });
addEventListener("blur", () => { ctxMenu.hidden = true; });

function inScopeOf(scope, f) {
  const saved = S.scope;
  S.scope = scope;
  const r = inScope(f);
  S.scope = saved;
  return r;
}

function applyState(st) {
  S.state = st;
  const rec = $("#rec");
  rec.classList.toggle("on", st.recording);
  rec.querySelector(".label").textContent = st.recording ? "Recording" : "Paused";
  $("#sysproxy").checked = st.systemProxy;
  $("#ssl").value = st.sslMode;
  $("#throttle").value = st.throttle || "off";
  $("#nocache").checked = st.noCache;
  $("#banner").hidden = st.trusted !== 0 || st.sslMode === "off";
  $("#proxyaddr").textContent = "127.0.0.1:" + st.proxyPort;
  if (st.theme === "system") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = st.theme;
  const bp = $("#bp");
  if (st.paused > 0 && !bp.innerHTML.trim()) showBreakpoint();
  if (!st.paused) bp.innerHTML = "";
  status();
  renderSide();
}

async function showBreakpoint() {
  $("#bp").innerHTML = await (await fetch("/ui/breakpoint")).text();
}

function status(extra) {
  const st = S.state, parts = [`Proxy 127.0.0.1:${st.proxyPort || ""}`];
  parts.push(st.systemProxy ? '<span class="on">System proxy on</span>' : "System proxy off");
  if (!st.recording) parts.push('<span class="warn">Recording paused</span>');
  if (st.throttle && st.throttle !== "off") parts.push('<span class="warn">Throttling</span>');
  if (st.rules) parts.push(st.rules + " rule" + (st.rules > 1 ? "s" : "") + " on");
  if (st.paused) parts.push(`<span class="warn">${st.paused} paused</span>`);
  if (st.passedHosts) parts.push(`<span class="link" data-modal="/ui/modal/ssl">${st.passedHosts} pinned host${st.passedHosts > 1 ? "s" : ""} passed through</span>`);
  if (extra) parts.push(`<span class="warn">${extra}</span>`);
  const shown = S.view.length, total = S.flows.length;
  parts.push('<span class="grow"></span>', shown === total ? `${total} requests` : `${shown} of ${total} requests`);
  const html = parts.map(p => p.startsWith("<span") ? p : `<span>${p}</span>`).join("");
  const el = $("#status");
  if (el.innerHTML !== html) el.innerHTML = html;
}

async function setting(data) {
  const st = await (await post("/api/settings", data)).json();
  applyState(st);
}

function switchView(view) {
  S.view_mode = view;
  document.querySelectorAll(".vt").forEach(b => b.classList.toggle("on", b.dataset.view === view));
  $("#content").hidden = view !== "traffic";
  $("#side").hidden = view !== "traffic";
  document.querySelectorAll("main > .gutter.v")[0].hidden = view !== "traffic";
  $("#sendview").hidden = view !== "sender";
  $("#jarview").hidden = view !== "jar";
  $("#appview").hidden = view !== "apps";
  if (view === "sender" && window.Sender) window.Sender.activate();
  if (view === "jar" && window.Jar) window.Jar.activate();
  if (view === "apps" && window.Apps) window.Apps.activate();
}
document.querySelectorAll(".vt").forEach(b => b.onclick = () => switchView(b.dataset.view));

$("#rec").onclick = () => setting({ recording: S.state.recording ? "0" : "1" });
$("#clear").onclick = () => post("/api/clear");
$("#sysproxy").onchange = e => setting({ system_proxy: e.target.checked ? "1" : "0" });
$("#ssl").onchange = e => setting({ ssl_mode: e.target.value });
$("#nocache").onchange = e => setting({ no_cache: e.target.checked ? "1" : "0" });
$("#throttle").onchange = e => {
  setting({ throttle: e.target.value });
  if (e.target.value === "custom") openModal("/ui/modal/throttle");
};

let filterTimer = 0;
$("#q").addEventListener("input", e => {
  clearTimeout(filterTimer);
  filterTimer = setTimeout(() => { S.filter = compileFilter(e.target.value); refresh(true); }, 150);
});

$("#types").addEventListener("click", e => {
  const b = e.target.closest("button");
  if (!b) return;
  S.type = S.type === b.dataset.type && b.dataset.type ? "" : b.dataset.type;
  document.querySelectorAll("#types button").forEach(x => x.classList.toggle("on", x.dataset.type === S.type));
  refresh(true);
});

function exportShown(kind) {
  const form = document.createElement("form");
  form.method = "POST";
  form.action = "/export/" + kind;
  const input = document.createElement("input");
  input.type = "hidden";
  input.name = "ids";
  input.value = S.view.map(f => f.id).join(",");
  form.append(input);
  document.body.append(form);
  form.submit();
  form.remove();
}
$("#export-har").onclick = () => exportShown("har");
$("#export-postman").onclick = () => exportShown("postman");

const modal = $("#modal");
async function openModal(url) {
  const res = await fetch(url);
  modal.innerHTML = await res.text();
  const auto = modal.querySelector("[autofocus]");
  if (auto) auto.focus();
}
const closeModal = () => { modal.innerHTML = ""; };

async function copy(text) {
  try { await navigator.clipboard.writeText(text); toast("Copied"); } catch { toast("Clipboard not available"); }
}

document.addEventListener("click", async e => {
  const t = e.target;
  for (const d of document.querySelectorAll("details.menu[open]")) {
    if (!d.contains(t) || t.closest("details.menu > div button, details.menu > div a")) d.open = false;
  }
  if (t.matches(".overlay[data-backdrop]") || t.closest("[data-close]")) return closeModal();
  const snd = t.closest("[data-sender]");
  if (snd && window.Sender) return window.Sender.fromFlow(+snd.dataset.sender);
  const m = t.closest("[data-modal]");
  if (m) return openModal(m.dataset.modal);
  const p = t.closest("[data-post]");
  if (p) {
    if (p.dataset.confirm && !confirm(p.dataset.confirm)) { if (p.type === "checkbox") e.preventDefault(); return; }
    if (p.dataset.busy) { p.disabled = true; p.textContent = p.dataset.busy; }
    const res = await post(p.dataset.post);
    if (p.dataset.target === "modal") modal.innerHTML = await res.text();
    if (S.sel && detail.contains(p)) loadDetail(true);
    return;
  }
  const c = t.closest("[data-copy], [data-copy-target], [data-copy-url]");
  if (c) {
    if (c.dataset.copyUrl) copy(await (await fetch(c.dataset.copyUrl)).text());
    else if (c.dataset.copyTarget) copy($(c.dataset.copyTarget).textContent);
    else copy(c.dataset.copy);
  }
});

document.addEventListener("submit", async e => {
  const form = e.target;
  const target = form.closest("#bp") ? $("#bp") : form.closest("#modal") ? modal : null;
  if (!target) return;
  e.preventDefault();
  const res = await post(form.getAttribute("action"), new FormData(form, e.submitter), form.enctype === "multipart/form-data");
  target.innerHTML = await res.text();
  if (target === $("#bp") && !target.innerHTML.trim() && S.state.paused > 1) showBreakpoint();
});

document.addEventListener("keydown", e => {
  const ctrl = e.ctrlKey || e.metaKey, k = e.key.toLowerCase();
  const typing = e.target.closest("input, textarea, select");
  if (e.key === "Escape") {
    document.querySelectorAll("details.menu[open]").forEach(d => { d.open = false; });
    if (modal.innerHTML) closeModal();
    else if (typing) e.target.blur();
    return;
  }
  if (ctrl && e.key === "Enter") {
    const form = $("#modal form, #bp form");
    if (form) { e.preventDefault(); form.requestSubmit(); }
    return;
  }
  if (ctrl && k === "k") { e.preventDefault(); post("/api/clear"); return; }
  if (ctrl && k === "e") { e.preventDefault(); $("#rec").click(); return; }
  if (ctrl && k === "f") { e.preventDefault(); $("#q").focus(); return; }
  if (typing || ctrl || e.altKey || modal.innerHTML || $("#bp").innerHTML.trim()) return;
  const moves = { arrowdown: 1, j: 1, arrowup: -1, k: -1, pagedown: 20, pageup: -20, home: -1e9, end: 1e9 };
  if (k in moves) { e.preventDefault(); S.follow = false; move(moves[k]); return; }
  if (k === "/") { e.preventDefault(); $("#q").focus(); return; }
  if (!S.sel) return;
  if (k === "delete" || k === "backspace") post("/api/flows/delete", { ids: S.sel });
  else if (k === "r") post(`/api/flows/${S.sel}/replay`);
  else if (k === "e") openModal(`/ui/modal/compose?from=${S.sel}`);
  else if (k === "s" && window.Sender) window.Sender.fromFlow(S.sel);
});

const root = document.documentElement.style;
for (const v of ["--side-w", "--detail-h", "--applist-w"]) { const saved = store("sift" + v); if (saved) root.setProperty(v, saved); }
document.querySelectorAll(".gutter").forEach(g => {
  g.addEventListener("pointerdown", down => {
    down.preventDefault();
    g.setPointerCapture(down.pointerId);
    const kind = g.dataset.resize;
    const horizontal = kind === "side" || kind === "applist";
    const name = { side: "--side-w", applist: "--applist-w", detail: "--detail-h" }[kind];
    const moveFn = e => {
      const val = horizontal ? Math.max(180, Math.min(480, e.clientX)) : Math.max(100, Math.min(innerHeight - 200, innerHeight - e.clientY - 22));
      root.setProperty(name, val + "px");
      refresh();
    };
    g.addEventListener("pointermove", moveFn);
    g.addEventListener("pointerup", () => { g.removeEventListener("pointermove", moveFn); store("sift" + name, root.getPropertyValue(name)); }, { once: true });
  });
});
addEventListener("resize", () => refresh());

(async () => {
  applyState(await (await fetch("/api/state")).json());
  await load();
  if (document.readyState === "complete") connect();
  else addEventListener("load", connect, { once: true });
})();

"use strict";

const Jar = (() => {
  let routes = [];
  let profiles = [];
  let result = null;
  let activated = false;
  const el = {};

  async function activate() {
    if (!activated) {
      el.url = $("#jar-url"); el.route = $("#jar-route"); el.profile = $("#jar-profile");
      el.follow = $("#jar-follow"); el.pattern = $("#jar-pattern"); el.regex = $("#jar-regex");
      el.meta = $("#jar-meta"); el.body = $("#jar-body"); el.go = $("#jar-go");
      wire();
      activated = true;
    }
    const st = await (await fetch("/api/sender/state")).json();
    routes = st.routes || [];
    profiles = st.profiles || [];
    el.route.innerHTML = routes.map(r => `<option value="${esc(r.id)}">${esc(r.name)}</option>`).join("");
    el.profile.innerHTML = profileOptions(profiles);
    try {
      el.url.value = el.url.value || localStorage.getItem("sift-jar-url") || "";
      el.profile.value = localStorage.getItem("sift-jar-profile") || "none";
    } catch {}
    if (!el.profile.value) el.profile.value = "none";
  }

  function wire() {
    el.go.onclick = run;
    el.pattern.addEventListener("input", () => { if (result) render(); });
    el.regex.addEventListener("change", () => { if (result) render(); });
    document.addEventListener("keydown", e => {
      if (!(e.ctrlKey || e.metaKey) || e.key !== "Enter") return;
      if ($("#jarview").hidden || $("#modal").innerHTML) return;
      e.preventDefault();
      run();
    });
    el.body.addEventListener("click", e => {
      const f = e.target.closest("[data-flow]");
      if (f) { switchView("traffic"); select(+f.dataset.flow); return; }
      const c = e.target.closest("[data-copy-value]");
      if (c) copy(c.dataset.copyValue);
    });
  }

  async function run() {
    const url = el.url.value.trim();
    if (!url) { el.meta.innerHTML = '<span class="bad">Enter a page first.</span>'; return; }
    try {
      localStorage.setItem("sift-jar-url", url);
      localStorage.setItem("sift-jar-profile", el.profile.value);
    } catch {}
    el.go.disabled = true;
    el.meta.textContent = "Fetching…";
    try {
      const res = await post("/api/sender/analyse", {
        url, route: el.route.value, profile: el.profile.value,
        pattern: el.pattern.value, regex: el.regex.checked ? "1" : "0",
        follow: el.follow.checked ? "1" : "0",
      });
      const d = await res.json();
      if (d.error) { el.meta.innerHTML = `<span class="bad">${esc(d.error)}</span>`; return; }
      result = d;
      render();
    } finally {
      el.go.disabled = false;
    }
  }

  function search() {
    const q = el.pattern.value.trim();
    if (!q || !result) return [];
    let hit;
    if (el.regex.checked) {
      let re;
      try { re = new RegExp(q, "i"); } catch { return null; }
      hit = (n, v) => re.test(n) || re.test(v);
    } else {
      const lower = q.toLowerCase();
      hit = (n, v) => n.toLowerCase().includes(lower) || String(v).toLowerCase().includes(lower);
    }
    const out = [];
    for (const c of result.jar || []) if (hit(c.name, c.value)) out.push(["cookie jar", c.name, c.value, 0]);
    for (const h of result.hops || []) {
      for (const c of h.received || []) if (hit(c.name, c.value)) out.push(["set-cookie", c.name, c.value, h.n]);
      for (const [k, v] of h.reqHead || []) if (hit(k, v)) out.push(["request header", k, v, h.n]);
      for (const [k, v] of h.resHead || []) if (hit(k, v)) out.push(["response header", k, v, h.n]);
    }
    return out;
  }

  function statusClass(s) { return s ? "c" + Math.min(Math.floor(s / 100), 5) : "c5"; }

  function cookieRows(list) {
    if (!list || !list.length) return '<p class="muted">none</p>';
    return `<table class="kv">${list.map(c => `<tr>
      <th>${esc(c.name)}</th>
      <td data-copy-value="${esc(c.value)}" title="Click to copy">${esc(c.value)}</td>
      <td class="jar-attr">${[c.domain, c.path, c.expires, c.secure ? "Secure" : "", c.httpOnly ? "HttpOnly" : ""].filter(Boolean).map(esc).join(" · ")}</td>
    </tr>`).join("")}</table>`;
  }

  function headRows(list) {
    if (!list || !list.length) return '<p class="muted">none</p>';
    return `<table class="kv">${list.map(([k, v]) => `<tr><th>${esc(k)}</th>
      <td data-copy-value="${esc(v)}" title="Click to copy">${esc(v)}</td></tr>`).join("")}</table>`;
  }

  function render() {
    const d = result;
    const bits = [`${d.hops.length} hop${d.hops.length === 1 ? "" : "s"}`, esc(d.route)];
    if (d.profile) bits.push(`TLS ${esc(d.profile)}`);
    if (d.error) bits.push(`<span class="bad">${esc(d.error)}</span>`);
    el.meta.innerHTML = bits.join(" · ");

    const matches = search();
    let html = "";
    if (el.pattern.value.trim()) {
      if (matches === null) {
        html += `<div class="jar-sec"><h3>Matches</h3><p class="bad">That regex doesn't compile.</p></div>`;
      } else {
        html += `<div class="jar-sec"><h3>Matches <i>${matches.length}</i></h3>` +
          (matches.length ? `<table class="kv">${matches.map(([where, n, v, hop]) => `<tr>
            <th>${esc(n)}</th>
            <td data-copy-value="${esc(v)}" title="Click to copy">${esc(v)}</td>
            <td class="jar-attr">${esc(where)}${hop ? " · hop " + hop : ""}</td></tr>`).join("")}</table>`
            : '<p class="muted">nothing matched</p>') + `</div>`;
      }
    }

    html += `<div class="jar-sec"><h3>Cookie jar <i>${(d.jar || []).length}</i></h3>${cookieRows(d.jar)}</div>`;

    for (const h of d.hops) {
      html += `<details class="jar-hop"${h.err || h.n === d.hops.length ? " open" : ""}>
        <summary>
          <b class="${statusClass(h.status)}">${h.err ? "failed" : h.status}</b>
          <span class="jar-m">${esc(h.method)}</span>
          <span class="jar-u">${esc(h.url)}</span>
          <i>${h.dur} ms</i>
          ${h.flow ? `<button class="link" data-flow="${h.flow}" title="Open in the Traffic inspector">inspect</button>` : ""}
        </summary>
        <div class="jar-hop-body">
          ${h.err ? `<p class="bad">${esc(h.err)}</p>` : ""}
          <h4>Cookies sent</h4>${cookieRows(h.sent)}
          <h4>Set-Cookie received</h4>${cookieRows(h.received)}
          <h4>Request headers</h4>${headRows(h.reqHead)}
          <h4>Response headers</h4>${headRows(h.resHead)}
        </div>
      </details>`;
    }
    el.body.innerHTML = html;
  }

  return { activate };
})();

window.Jar = Jar;

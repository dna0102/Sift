package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
)

//go:embed web
var webFS embed.FS

var methods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

type UI struct {
	app  *App
	tmpl *template.Template
	mux  *http.ServeMux
}

func NewUI(app *App) *UI {
	funcs := template.FuncMap{
		"summary": ruleSummary,
		"join":    func(s []string) string { return strings.Join(s, "\n") },
	}
	u := &UI{app: app, tmpl: template.Must(template.New("").Funcs(funcs).ParseFS(webFS, "web/modals.html")), mux: http.NewServeMux()}
	m := u.mux
	m.HandleFunc("GET /{$}", u.static("web/index.html", "text/html; charset=utf-8"))
	m.HandleFunc("GET /app.js", u.static("web/app.js", "text/javascript; charset=utf-8"))
	m.HandleFunc("GET /apps.js", u.static("web/apps.js", "text/javascript; charset=utf-8"))
	m.HandleFunc("GET /sender.js", u.static("web/sender.js", "text/javascript; charset=utf-8"))
	m.HandleFunc("GET /app.css", u.static("web/app.css", "text/css; charset=utf-8"))
	m.HandleFunc("GET /favicon.svg", u.static("web/favicon.svg", "image/svg+xml"))

	m.HandleFunc("GET /api/state", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, app.State()) })
	m.HandleFunc("GET /api/flows", u.flows)
	m.HandleFunc("GET /api/events", u.events)
	m.HandleFunc("GET /api/flows/{id}/body/{side}", u.body)
	m.HandleFunc("POST /api/flows/{id}/replay", u.replay)
	m.HandleFunc("POST /api/flows/delete", u.deleteFlows)
	m.HandleFunc("POST /api/clear", func(w http.ResponseWriter, r *http.Request) { app.store.Clear() })
	m.HandleFunc("POST /api/settings", u.settings)
	m.HandleFunc("POST /api/hosts/{op}", u.hostOp)
	m.HandleFunc("POST /api/apps/decrypt", u.appDecrypt)
	m.HandleFunc("POST /ui/pins/{op}", u.pinOp)
	m.HandleFunc("POST /ui/compat/{op}", u.compatOp)
	m.HandleFunc("POST /api/search", u.search)

	// mobile app analysis
	m.HandleFunc("GET /api/apps/reports", u.appReports)
	m.HandleFunc("GET /api/apps/reports/{id}", u.appReport)
	m.HandleFunc("GET /api/apps/events", u.appEvents)
	m.HandleFunc("GET /api/apps/reports/{id}/file", u.appFile)
	m.HandleFunc("POST /api/apps/analyse", u.appAnalyse)
	m.HandleFunc("POST /api/apps/reports/{id}/delete", u.appDeleteReport)
	m.HandleFunc("POST /api/apps/jadx", u.appEnsureJadx)

	u.senderRoutes(m)

	// emulator
	m.HandleFunc("GET /api/emulator/status", u.emuStatus)
	m.HandleFunc("GET /api/emulator/devices", u.emuDevices)
	m.HandleFunc("POST /api/emulator/launch", u.emuLaunch)
	m.HandleFunc("POST /api/emulator/stop", u.emuStop)

	m.HandleFunc("GET /ui/detail/{id}", u.detail)
	m.HandleFunc("GET /ui/modal/{name}", u.modal)
	m.HandleFunc("POST /ui/rules/save", u.saveRule)
	m.HandleFunc("POST /ui/rules/{id}/{op}", u.ruleOp)
	m.HandleFunc("POST /ui/ssl", u.saveSSL)
	m.HandleFunc("POST /ui/throttle", u.saveThrottle)
	m.HandleFunc("POST /ui/settings", u.saveSettings)
	m.HandleFunc("POST /ui/cert/{op}", u.certOp)
	m.HandleFunc("POST /ui/compose", u.compose)
	m.HandleFunc("POST /ui/import", u.importHAR)
	m.HandleFunc("GET /ui/breakpoint", u.breakpoint)
	m.HandleFunc("POST /ui/breakpoint/{id}", u.resolveBreakpoint)

	m.HandleFunc("/export/{kind}", u.export)
	m.HandleFunc("GET /cert/sift-ca.pem", u.certFile)
	m.HandleFunc("GET /cert/sift-ca.cer", u.certFile)
	return u
}

func (u *UI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	port := strconv.Itoa(u.app.uiPort)
	switch r.Host {
	case "127.0.0.1:" + port, "localhost:" + port, "[::1]:" + port:
	default: // blocks DNS-rebinding attacks from websites
		http.Error(w, "Sift only answers on 127.0.0.1", http.StatusForbidden)
		return
	}
	// state-changing calls must come from the dashboard itself (blocks cross-site form posts)
	if r.Method == http.MethodPost && r.Header.Get("X-Sift") != "1" && !strings.HasPrefix(r.URL.Path, "/export/") {
		http.Error(w, "missing X-Sift header", http.StatusForbidden)
		return
	}
	u.mux.ServeHTTP(w, r)
}

func (u *UI) static(name, ctype string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, _ := webFS.ReadFile(name)
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(data)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func toast(w http.ResponseWriter, msg string) {
	w.Header().Set("X-Toast", url.QueryEscape(msg))
}

func (u *UI) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := u.tmpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), 500)
	}
}

func (u *UI) flowArg(w http.ResponseWriter, r *http.Request) *Flow {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	f := u.app.store.Get(id)
	if f == nil {
		http.Error(w, "That request is no longer in the list.", http.StatusNotFound)
	}
	return f
}

// ---------------------------------------------------------------- list & live updates

func (u *UI) flows(w http.ResponseWriter, r *http.Request) {
	all := u.app.store.All()
	out := make([]Summary, len(all))
	for i, f := range all {
		out[i] = f.Summary()
	}
	writeJSON(w, out)
}

func (u *UI) events(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	rc := http.NewResponseController(w)
	ch := u.app.store.hub.Subscribe()
	defer u.app.store.hub.Unsubscribe(ch)
	state, _ := json.Marshal(batch{State: u.app.State()})
	fmt.Fprintf(w, "data: %s\n\n", state)
	rc.Flush()
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				return
			}
			if _, err := fmt.Fprintf(w, "data: %s\n\n", msg); err != nil {
				return
			}
			rc.Flush()
		case <-ping.C:
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
				return
			}
			rc.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (u *UI) detail(w http.ResponseWriter, r *http.Request) {
	f := u.flowArg(w, r)
	if f == nil {
		return
	}
	q := r.URL.Query()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, RenderDetail(f, DetailOpts{q.Get("req"), q.Get("res"), q.Get("reqm"), q.Get("resm")}, u.app))
}

func (u *UI) body(w http.ResponseWriter, r *http.Request) {
	f := u.flowArg(w, r)
	if f == nil {
		return
	}
	s := snap(f)
	data, ctype := s.body(r.PathValue("side"))
	// Captured content is untrusted: never let it run as part of the dashboard.
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; img-src * data: blob:; style-src * 'unsafe-inline'; font-src * data:; media-src *")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ctype)
	if r.URL.Query().Get("download") != "" {
		name := path.Base(strings.SplitN(s.Path, "?", 2)[0])
		if name == "/" || name == "." || name == "" {
			name = "body"
		}
		if path.Ext(name) == "" {
			if exts, _ := mime.ExtensionsByType(strings.Split(ctype, ";")[0]); len(exts) > 0 {
				name += exts[0]
			}
		}
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	}
	w.Write(data)
}

func (u *UI) replay(w http.ResponseWriter, r *http.Request) {
	if f := u.flowArg(w, r); f != nil {
		if err := u.app.Replay(f); err != nil {
			toast(w, err.Error())
			return
		}
		toast(w, "Sent again")
	}
}

func (u *UI) deleteFlows(w http.ResponseWriter, r *http.Request) {
	var ids []int64
	for _, s := range strings.Split(r.FormValue("ids"), ",") {
		if id, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil {
			ids = append(ids, id)
		}
	}
	n := u.app.store.Remove(ids)
	toast(w, fmt.Sprintf("Deleted %d", n))
}

func (u *UI) settings(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	on := func(k string) bool { return r.Form.Get(k) == "1" }
	app := u.app
	if r.Form.Has("system_proxy") {
		if err := app.SetSystemProxy(on("system_proxy")); err != nil {
			toast(w, "Couldn't change the system proxy: "+err.Error())
		}
	}
	app.cfg.Update(func(s *Settings) {
		if r.Form.Has("recording") {
			s.Recording = on("recording")
		}
		if r.Form.Has("no_cache") {
			s.NoCache = on("no_cache")
		}
		if v := r.Form.Get("ssl_mode"); v != "" {
			s.SSLMode = v
		}
		if v := r.Form.Get("throttle"); v != "" {
			s.Throttle.Preset = v
		}
	})
	app.store.hub.StateChanged()
	writeJSON(w, app.State())
}

func (u *UI) hostOp(w http.ResponseWriter, r *http.Request) {
	host := strings.TrimSpace(r.FormValue("host"))
	if !strings.HasPrefix(host, "app:") { // app names keep their case
		host = strings.ToLower(host)
	}
	if host == "" {
		return
	}
	toggle := func(list []string) ([]string, bool) {
		for i, h := range list {
			if h == host {
				return append(list[:i:i], list[i+1:]...), false
			}
		}
		return append(list, host), true
	}
	var added bool
	switch r.PathValue("op") {
	case "pin":
		u.app.cfg.Update(func(s *Settings) { s.Pinned, added = toggle(s.Pinned) })
		toast(w, map[bool]string{true: "Pinned ", false: "Unpinned "}[added]+strings.TrimPrefix(host, "app:"))
	case "decrypt":
		u.app.cfg.Update(func(s *Settings) { s.SSLExclude, added = toggle(s.SSLExclude) })
		toast(w, map[bool]string{true: "HTTPS for " + host + " now passes through encrypted", false: "Decrypting " + host + " again"}[added])
	}
	u.app.store.hub.StateChanged()
}

// search looks inside headers and bodies; plain filters run in the browser.
func (u *UI) search(w http.ResponseWriter, r *http.Request) {
	needle := bytes.ToLower([]byte(r.FormValue("q")))
	ids := []int64{}
	if len(needle) == 0 {
		writeJSON(w, ids)
		return
	}
	for _, f := range u.app.store.All() {
		s := snap(f)
		found := false
		for _, side := range []string{"req", "res"} {
			if data, _ := s.body(side); len(data) > 0 && bytes.Contains(bytes.ToLower(data), needle) {
				found = true
			}
		}
		for _, h := range []http.Header{s.ReqHeader, s.ResHeader} {
			for k, vs := range h {
				for _, v := range vs {
					if bytes.Contains(bytes.ToLower([]byte(k+": "+v)), needle) {
						found = true
					}
				}
			}
		}
		if found {
			ids = append(ids, s.ID)
		}
	}
	writeJSON(w, ids)
}

// ---------------------------------------------------------------- dialogs

func (u *UI) modal(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	switch r.PathValue("name") {
	case "rules":
		u.renderRules(w, q.Get("type"), u.ruleToEdit(q), "")
	case "ssl", "throttle", "settings", "cert", "import", "devices":
		u.renderSimple(w, r.PathValue("name"), "")
	case "compose":
		data := map[string]any{"Method": "GET", "URL": "https://", "Methods": methods}
		if id, err := strconv.ParseInt(q.Get("from"), 10, 64); err == nil {
			if f := u.app.store.Get(id); f != nil {
				f.mu.Lock()
				data["Method"], data["URL"] = f.Method, f.URL()
				data["Headers"] = headerText(f.ReqHeader)
				if !isBinary(f.ReqBody) {
					data["Body"] = string(f.ReqBody)
				}
				f.mu.Unlock()
			}
		}
		u.render(w, "compose", data)
	case "code":
		id, _ := strconv.ParseInt(q.Get("id"), 10, 64)
		f := u.app.store.Get(id)
		if f == nil {
			http.Error(w, "not found", 404)
			return
		}
		lang := q.Get("lang")
		u.render(w, "code", map[string]any{"ID": id, "Lang": lang, "Langs": CodeLangs, "Code": ToCode(f, lang)})
	default:
		http.NotFound(w, r)
	}
}

func headerText(h http.Header) string {
	var b strings.Builder
	for _, row := range headerRows(h) {
		b.WriteString(row[0] + ": " + row[1] + "\n")
	}
	return b.String()
}

func (u *UI) ruleToEdit(q url.Values) *Rule {
	typ := q.Get("type")
	if typ == "" {
		typ = "breakpoint"
	}
	switch {
	case q.Get("edit") == "new":
		r := NewRule(typ)
		return &r
	case q.Get("edit") != "":
		for _, r := range u.app.cfg.Get().Rules {
			if r.ID == q.Get("edit") {
				return &r
			}
		}
	case q.Get("host") != "":
		r := NewRule(typ)
		r.Pattern, r.Name = q.Get("host"), q.Get("host")
		return &r
	case q.Get("from") != "":
		id, _ := strconv.ParseInt(q.Get("from"), 10, 64)
		f := u.app.store.Get(id)
		if f == nil {
			return nil
		}
		r := NewRule(typ)
		f.mu.Lock()
		defer f.mu.Unlock()
		base := strings.SplitN(f.URL(), "?", 2)[0]
		r.Pattern, r.Method, r.Name = base, f.Method, f.Method+" "+strings.SplitN(f.Path, "?", 2)[0]
		if len(r.Name) > 60 {
			r.Name = r.Name[:60]
		}
		switch typ {
		case "map_local":
			if f.Status > 0 {
				r.Status = f.Status
				r.Headers = "Content-Type: " + f.ResHeader.Get("Content-Type")
				body := f.ResBody
				if !f.Decoded {
					body, _ = decodeBody(body, f.ResHeader.Get("Content-Encoding"))
				}
				if !isBinary(body) {
					r.Body = string(body)
				}
			}
		case "map_remote":
			r.Pattern, r.Method, r.To = f.Scheme+"://"+hostPort(f.Host, f.Port, f.Scheme)+"/*", "ANY", "http://localhost:3000"
		}
		return &r
	}
	return nil
}

func (u *UI) renderRules(w http.ResponseWriter, typ string, edit *Rule, msg string) {
	if typ == "" {
		typ = "breakpoint"
	}
	cfg := u.app.cfg.Get()
	counts := map[string]int{}
	var list []Rule
	for _, r := range cfg.Rules {
		if r.Enabled {
			counts[r.Type]++
		}
		if r.Type == typ {
			list = append(list, r)
		}
	}
	title, help := "", ""
	for _, t := range RuleTypes {
		if t.Key == typ {
			title, help = t.Label, t.Help
		}
	}
	u.render(w, "rules", map[string]any{"Types": RuleTypes, "Active": typ, "Counts": counts, "Title": title, "Help": help,
		"Rules": list, "Edit": edit, "Msg": msg, "Methods": append([]string{"ANY"}, methods...)})
}

func (u *UI) renderSimple(w http.ResponseWriter, name, msg string) {
	app := u.app
	data := map[string]any{"S": app.cfg.Get(), "Msg": msg, "Types": RuleTypes, "Active": name, "Counts": map[string]int{},
		"Presets": ThrottlePresets, "ProxyPort": app.proxyPort, "UIPort": app.uiPort, "LAN": lanAddresses(), "Home": app.home}
	for _, r := range app.cfg.Get().Rules {
		if r.Enabled {
			data["Counts"].(map[string]int)[r.Type]++
		}
	}
	switch name {
	case "cert":
		ca := app.ca
		data["Trusted"], data["Subject"], data["SHA1"], data["NotAfter"], data["PEM"] = ca.Trusted(), ca.Subject, ca.SHA1, ca.NotAfter.Format("2006-01-02"), ca.PEMPath
	case "ssl":
		data["Passed"] = app.PassedHosts()
		data["Known"] = strings.Join(KnownPinned, ", ")
	case "settings":
		data["Windows"] = runtime.GOOS == "windows"
		data["LoopExempt"], data["LoopTotal"] = LoopbackStatus()
	case "devices":
		data["Windows"] = runtime.GOOS == "windows"
		data["Firewall"] = FirewallAllowed()
		data["Trusted"] = app.ca.Trusted()
	}
	u.render(w, name, data)
}

// appDecrypt turns HTTPS decryption off (or back on) for everything an app sends.
func (u *UI) appDecrypt(w http.ResponseWriter, r *http.Request) {
	app := strings.TrimSpace(r.FormValue("app"))
	if app == "" {
		return
	}
	excluded := false
	u.app.cfg.Update(func(s *Settings) {
		for i, a := range s.SSLExcludeApps {
			if a == app {
				s.SSLExcludeApps = append(s.SSLExcludeApps[:i:i], s.SSLExcludeApps[i+1:]...)
				return
			}
		}
		s.SSLExcludeApps = append(s.SSLExcludeApps, app)
		excluded = true
	})
	if excluded {
		toast(w, app+" now connects without decryption (new connections)")
	} else {
		toast(w, "Decrypting "+app+" again")
	}
	u.app.store.hub.StateChanged()
}

// pinOp manages hosts that were passed through because their apps reject the certificate.
func (u *UI) pinOp(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(strings.TrimSpace(r.FormValue("host")))
	pins := u.app.proxy.pins
	switch r.PathValue("op") {
	case "forget": // try decrypting this host again
		pins.Remove(host)
		u.app.cfg.Update(func(s *Settings) { s.LearnedPins = slices.DeleteFunc(s.LearnedPins, func(h string) bool { return h == host }) })
	case "clear":
		for _, p := range pins.List() {
			pins.Remove(p.Host)
		}
		u.app.cfg.Update(func(s *Settings) { s.LearnedPins = nil })
	}
	u.app.store.hub.StateChanged()
	u.renderSimple(w, "ssl", "")
}

// compatOp runs the Windows fixes that need administrator rights.
func (u *UI) compatOp(w http.ResponseWriter, r *http.Request) {
	var err error
	page, msg := "settings", ""
	switch r.PathValue("op") {
	case "loopback-on":
		if err = SetLoopback(u.app.home, true); err == nil {
			msg = "Microsoft Store apps can now reach Sift. Restart any that were open."
		}
	case "loopback-off":
		if err = SetLoopback(u.app.home, false); err == nil {
			msg = "Removed the exemptions Sift added."
		}
	case "firewall":
		page = "devices"
		if err = AllowFirewall(); err == nil {
			msg = "Windows Firewall now lets other devices reach Sift."
		}
	}
	if err != nil {
		msg = "Couldn't apply: " + err.Error()
	}
	u.renderSimple(w, page, msg)
}

func (u *UI) saveRule(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	f := r.Form
	typ := f.Get("type")
	rule := NewRule(typ)
	if id := f.Get("id"); id != "" {
		rule.ID = id
	}
	rule.Name, rule.Pattern, rule.Method = strings.TrimSpace(f.Get("name")), strings.TrimSpace(f.Get("pattern")), f.Get("method")
	if rule.Pattern == "" {
		rule.Pattern = "*"
	}
	rule.Regex, rule.OnRequest, rule.OnResponse = f.Get("regex") == "1", f.Get("on_request") == "1", f.Get("on_response") == "1"
	rule.Status, _ = strconv.Atoi(f.Get("status"))
	rule.Headers, rule.Body, rule.File = f.Get("headers"), f.Get("body"), strings.TrimSpace(f.Get("file"))
	rule.To, rule.PreserveHost = strings.TrimSpace(f.Get("to")), f.Get("preserve_host") == "1"
	if a := f.Get("action"); a != "" {
		rule.Action = a
	}
	if t := f.Get("target"); t != "" {
		rule.Target = t
	}
	if o := f.Get("op"); o != "" {
		rule.Op = o
	}
	rule.Key, rule.Value, rule.Find, rule.Replace, rule.FindRegex = f.Get("key"), f.Get("value"), f.Get("find"), f.Get("replace"), f.Get("find_regex") == "1"
	u.app.cfg.Update(func(s *Settings) {
		for i := range s.Rules {
			if s.Rules[i].ID == rule.ID {
				rule.Enabled = s.Rules[i].Enabled
				s.Rules[i] = rule
				return
			}
		}
		s.Rules = append(s.Rules, rule)
	})
	u.app.store.hub.StateChanged()
	u.renderRules(w, typ, nil, "Saved. Applies to new requests right away.")
}

func (u *UI) ruleOp(w http.ResponseWriter, r *http.Request) {
	id, op := r.PathValue("id"), r.PathValue("op")
	typ := ""
	u.app.cfg.Update(func(s *Settings) {
		for i := range s.Rules {
			if s.Rules[i].ID != id {
				continue
			}
			typ = s.Rules[i].Type
			if op == "toggle" {
				s.Rules[i].Enabled = !s.Rules[i].Enabled
			} else if op == "delete" {
				s.Rules = append(s.Rules[:i], s.Rules[i+1:]...)
			}
			return
		}
	})
	u.app.store.hub.StateChanged()
	u.renderRules(w, typ, nil, "")
}

func lines(s string) []string {
	var out []string
	for _, l := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' }) {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func (u *UI) saveSSL(w http.ResponseWriter, r *http.Request) {
	u.app.cfg.Update(func(s *Settings) {
		s.SSLMode = r.FormValue("ssl_mode")
		s.SSLInclude = lines(r.FormValue("ssl_include"))
		s.SSLExclude = lines(r.FormValue("ssl_exclude"))
		s.SSLExcludeApps = lines(r.FormValue("ssl_exclude_apps"))
		s.AutoPassPinned = r.FormValue("auto_pass_pinned") == "1"
		s.SkipKnown = r.FormValue("skip_known_pinned") == "1"
	})
	u.app.store.hub.StateChanged()
	u.renderSimple(w, "ssl", "Saved. Applies to new connections.")
}

func (u *UI) saveThrottle(w http.ResponseWriter, r *http.Request) {
	num := func(k string, def int) int {
		if n, err := strconv.Atoi(strings.TrimSpace(r.FormValue(k))); err == nil && n >= 0 {
			return n
		}
		return def
	}
	u.app.cfg.Update(func(s *Settings) {
		t := &s.Throttle
		t.Preset = r.FormValue("preset")
		t.Latency, t.Down, t.Up = num("latency", t.Latency), num("down", t.Down), num("up", t.Up)
		t.Hosts = strings.TrimSpace(r.FormValue("hosts"))
	})
	u.app.store.hub.StateChanged()
	u.renderSimple(w, "throttle", "Applied.")
}

func (u *UI) saveSettings(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	on := func(k string) bool { return r.Form.Get(k) == "1" }
	num := func(k string, def, lo, hi int) int {
		if n, err := strconv.Atoi(strings.TrimSpace(r.Form.Get(k))); err == nil {
			return max(lo, min(hi, n))
		}
		return def
	}
	old := u.app.cfg.Get()
	u.app.cfg.Update(func(s *Settings) {
		s.AllowLAN, s.VerifyUpstream, s.NoCache, s.ShowTunnels = on("allow_lan"), on("verify_upstream"), on("no_cache"), on("show_tunnels")
		if b := strings.TrimSpace(r.Form.Get("bypass")); b != "" {
			s.Bypass = b
		}
		s.MaxFlows = num("max_flows", s.MaxFlows, 100, 1_000_000)
		s.MaxBodyMB = num("max_body_mb", s.MaxBodyMB, 1, 1024)
		s.MaxMemoryMB = num("max_memory_mb", s.MaxMemoryMB, 64, 65536)
		if t := r.Form.Get("theme"); t != "" {
			s.Theme = t
		}
	})
	now := u.app.cfg.Get()
	if now.AllowLAN != old.AllowLAN {
		if err := u.app.proxy.Relisten(now.AllowLAN); err != nil {
			toast(w, "Couldn't change the listening address: "+err.Error())
		}
	}
	if now.SystemProxy && now.Bypass != old.Bypass {
		u.app.SetSystemProxy(true)
	}
	u.app.store.trim()
	u.app.store.hub.StateChanged()
	u.renderSimple(w, "settings", "Saved.")
}

func (u *UI) certOp(w http.ResponseWriter, r *http.Request) {
	msg := ""
	switch r.PathValue("op") {
	case "install":
		var ok bool
		if ok, msg = u.app.ca.Install(); ok {
			u.app.proxy.pins.ClearUntrusted() // those hosts only failed because the certificate was missing
		}
	case "uninstall":
		_, msg = u.app.ca.Uninstall()
	default:
		u.app.ca.CheckTrusted()
	}
	u.app.store.hub.StateChanged()
	u.renderSimple(w, "cert", msg)
}

func (u *UI) compose(w http.ResponseWriter, r *http.Request) {
	err := u.app.Compose(r.FormValue("method"), r.FormValue("url"), r.FormValue("headers"), r.FormValue("body"))
	if err != nil {
		u.render(w, "compose", map[string]any{"Method": r.FormValue("method"), "URL": r.FormValue("url"), "Headers": r.FormValue("headers"),
			"Body": r.FormValue("body"), "Methods": methods, "Error": err.Error()})
		return
	}
	toast(w, "Sent")
}

func (u *UI) importHAR(w http.ResponseWriter, r *http.Request) {
	file, hdr, err := r.FormFile("file")
	if err != nil {
		u.renderSimple(w, "import", "Choose a .har file first.")
		return
	}
	defer file.Close()
	flows, err := ReadHAR(file, u.app.cfg.Get().MaxBody())
	if err != nil {
		u.renderSimple(w, "import", "That doesn't look like a HAR file: "+err.Error())
		return
	}
	for _, f := range flows {
		u.app.store.Add(f)
		u.app.store.Finished(f)
	}
	toast(w, fmt.Sprintf("Imported %d requests from %s", len(flows), hdr.Filename))
}

func (u *UI) breakpoint(w http.ResponseWriter, r *http.Request) {
	list := u.app.bps.List()
	if len(list) == 0 {
		return
	}
	p := list[0]
	f := p.Flow
	f.mu.Lock()
	data := map[string]any{"P": p, "Count": len(list), "Methods": methods, "Method": f.Method, "URL": f.URL(),
		"Binary": isBinary(p.Body), "Size": fmtSize(int64(len(p.Body))), "Body": string(p.Body), "Status": f.Status}
	if p.Phase == "request" {
		data["Headers"] = headerText(f.ReqHeader)
	} else {
		data["Headers"] = headerText(f.ResHeader)
	}
	f.mu.Unlock()
	u.render(w, "breakpoint", data)
}

func (u *UI) resolveBreakpoint(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	action := r.Form.Get("action")
	if action == "all" {
		u.app.bps.ResumeAll()
	} else {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		status, _ := strconv.Atoi(r.Form.Get("status"))
		u.app.bps.Resume(id, Decision{Action: action, Method: r.Form.Get("method"), URL: r.Form.Get("url"),
			Headers: r.Form.Get("headers"), Body: r.Form.Get("body"), EditBody: r.Form.Get("edit_body") == "1", Status: status})
	}
	time.Sleep(50 * time.Millisecond) // let the flow move on before showing the next one
	u.breakpoint(w, r)
}

// ---------------------------------------------------------------- export

func (u *UI) export(w http.ResponseWriter, r *http.Request) {
	flows := u.app.store.All()
	if ids := r.FormValue("ids"); ids != "" {
		want := map[int64]bool{}
		for _, s := range strings.Split(ids, ",") {
			if id, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil {
				want[id] = true
			}
		}
		kept := flows[:0]
		for _, f := range flows {
			if want[f.ID] {
				kept = append(kept, f)
			}
		}
		flows = kept
	}
	stamp := time.Now().Format("2006-01-02-150405")
	w.Header().Set("Content-Type", "application/json")
	switch r.PathValue("kind") {
	case "har":
		w.Header().Set("Content-Disposition", `attachment; filename="sift-`+stamp+`.har"`)
		WriteHAR(w, flows)
	case "postman":
		w.Header().Set("Content-Disposition", `attachment; filename="sift-`+stamp+`.postman_collection.json"`)
		WritePostman(w, flows)
	default:
		http.NotFound(w, r)
	}
}

func (u *UI) certFile(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, ".pem") {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="sift-ca.pem"`)
		w.Write(u.app.ca.PEM())
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="sift-ca.cer"`)
	w.Write(u.app.ca.DER())
}

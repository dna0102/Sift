package ui

import (
	"net/http"
	"strconv"
	"strings"

	"sift/internal/core"
	"sift/internal/sender"
)

func (u *UI) senderRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/sender/state", u.senderState)
	m.HandleFunc("POST /api/sender/tabs/new", u.senderNewTab)
	m.HandleFunc("POST /api/sender/tabs/save", u.senderSaveTab)
	m.HandleFunc("POST /api/sender/tabs/close", u.senderCloseTab)
	m.HandleFunc("POST /api/sender/send", u.senderSend)
	m.HandleFunc("GET /api/sender/history", u.senderHistory)
	m.HandleFunc("GET /api/sender/entry", u.senderEntry)
	m.HandleFunc("POST /api/sender/routes/save", u.senderSaveRoute)
	m.HandleFunc("POST /api/sender/routes/delete", u.senderDeleteRoute)
	m.HandleFunc("POST /api/sender/analyse", u.senderAnalyse)
}

func (u *UI) senderState(w http.ResponseWriter, r *http.Request) {
	s := u.app.Sender
	writeJSON(w, map[string]any{
		"tabs":       s.Tabs(),
		"routes":     s.Routes(),
		"interfaces": sender.LocalInterfaces(),
		"proxyPort":  u.app.ProxyPort,
		"profiles":   sender.Profiles(),
	})
}

func (u *UI) senderNewTab(w http.ResponseWriter, r *http.Request) {
	var from *core.Flow
	if id, err := strconv.ParseInt(r.FormValue("from"), 10, 64); err == nil {
		from = u.app.Store.Get(id)
	}
	t := u.app.Sender.NewTab(from)
	writeJSON(w, map[string]any{"tab": t, "tabs": u.app.Sender.Tabs()})
}

func (u *UI) senderSaveTab(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	u.app.Sender.SaveTab(r.Form.Get("id"), r.Form.Get("name"), r.Form.Get("raw"), r.Form.Get("target"), r.Form.Get("route"), r.Form.Get("profile"))
	w.WriteHeader(http.StatusNoContent)
}

func (u *UI) senderCloseTab(w http.ResponseWriter, r *http.Request) {
	u.app.Sender.CloseTab(r.FormValue("id"))
	writeJSON(w, map[string]any{"tabs": u.app.Sender.Tabs()})
}

func (u *UI) senderSend(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	in := sender.SendReq{Tab: r.Form.Get("id"), Raw: r.Form.Get("raw"), Target: r.Form.Get("target"),
		Route: r.Form.Get("route"), Profile: r.Form.Get("profile"), UpdateCL: r.Form.Get("update_cl") == "1"}

	u.app.Sender.SaveTab(in.Tab, "", in.Raw, in.Target, in.Route, in.Profile)
	e, err := u.app.Sender.Send(r.Context(), in)
	if err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, entryJSON(e, true))
}

func (u *UI) senderHistory(w http.ResponseWriter, r *http.Request) {
	list := u.app.Sender.History(r.URL.Query().Get("id"))
	out := make([]any, len(list))
	for i, e := range list {
		out[i] = entryJSON(e, false)
	}
	writeJSON(w, out)
}

func (u *UI) senderEntry(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	n, _ := strconv.Atoi(q.Get("n"))
	e := u.app.Sender.Entry(q.Get("id"), n)
	if e == nil {
		http.Error(w, "That send is no longer in the history.", http.StatusNotFound)
		return
	}
	writeJSON(w, entryJSON(e, true))
}

func entryJSON(e *sender.Entry, withBodies bool) map[string]any {
	m := map[string]any{"n": e.N, "at": e.At, "status": e.Status, "reason": e.Reason, "dur": e.Dur,
		"size": e.Size, "flow": e.Flow, "route": e.Route, "target": e.Target}
	if e.Err != "" {
		m["err"] = e.Err
	}
	if e.Note != "" {
		m["note"] = e.Note
	}
	if e.Profile != "" {
		m["profile"] = e.Profile
	}
	if withBodies {
		m["req"] = string(e.RawRequest())
		res := e.RawResponse()
		if len(res) > sender.MaxSenderShow {
			m["truncated"] = len(res)
			res = res[:sender.MaxSenderShow]
		}
		m["res"] = string(res)
	}
	return m
}

func (u *UI) senderSaveRoute(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	port, _ := strconv.Atoi(strings.TrimSpace(r.Form.Get("port")))
	timeout, _ := strconv.Atoi(strings.TrimSpace(r.Form.Get("timeout")))
	rt := &sender.Route{
		ID:      r.Form.Get("id"),
		Name:    strings.TrimSpace(r.Form.Get("name")),
		Kind:    r.Form.Get("kind"),
		Host:    strings.TrimSpace(r.Form.Get("host")),
		Port:    port,
		User:    r.Form.Get("user"),
		Pass:    r.Form.Get("pass"),
		Bind:    strings.TrimSpace(r.Form.Get("bind")),
		Verify:  r.Form.Get("verify"),
		Follow:  r.Form.Get("follow") == "1",
		Timeout: timeout,
		Profile: pickProfile(r.Form.Get("profile")),
		HTTP1:   r.Form.Get("http1") == "1",
	}
	if rt.Kind != "http" && rt.Kind != "socks5" && rt.Kind != "direct" {
		rt.Kind = "http"
	}
	if rt.Name == "" {
		rt.Name = rt.Kind + " " + rt.Host
	}
	if (rt.Kind == "http" || rt.Kind == "socks5") && rt.Host == "" {
		writeJSON(w, map[string]any{"error": "Enter the proxy's host or IP address."})
		return
	}
	u.app.Sender.SaveRoute(rt)
	writeJSON(w, map[string]any{"routes": u.app.Sender.Routes(), "saved": rt.ID})
}

func (u *UI) senderDeleteRoute(w http.ResponseWriter, r *http.Request) {
	u.app.Sender.DeleteRoute(r.FormValue("id"))
	writeJSON(w, map[string]any{"routes": u.app.Sender.Routes()})
}

func (u *UI) senderAnalyse(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	in := sender.JarRequest{
		URL:     r.Form.Get("url"),
		Raw:     r.Form.Get("raw"),
		Route:   r.Form.Get("route"),
		Profile: r.Form.Get("profile"),
		Pattern: r.Form.Get("pattern"),
		Regex:   r.Form.Get("regex") == "1",
		Follow:  r.Form.Get("follow") == "1",
	}
	res, err := u.app.Sender.Analyse(r.Context(), in)
	if err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, res)
}

func pickProfile(v string) string {
	v = strings.TrimSpace(v)
	if v == "none" {
		return ""
	}
	return v
}

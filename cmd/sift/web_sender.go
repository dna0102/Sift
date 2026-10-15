package main

// Dashboard API for the Sender view.

import (
	"net/http"
	"strconv"
	"strings"
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
}

func (u *UI) senderState(w http.ResponseWriter, r *http.Request) {
	s := u.app.sender
	writeJSON(w, map[string]any{
		"tabs":       s.Tabs(),
		"routes":     s.Routes(),
		"interfaces": localInterfaces(),
		"proxyPort":  u.app.proxyPort,
	})
}

func (u *UI) senderNewTab(w http.ResponseWriter, r *http.Request) {
	var from *Flow
	if id, err := strconv.ParseInt(r.FormValue("from"), 10, 64); err == nil {
		from = u.app.store.Get(id)
	}
	t := u.app.sender.NewTab(from)
	writeJSON(w, map[string]any{"tab": t, "tabs": u.app.sender.Tabs()})
}

func (u *UI) senderSaveTab(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	u.app.sender.SaveTab(r.Form.Get("id"), r.Form.Get("name"), r.Form.Get("raw"), r.Form.Get("target"), r.Form.Get("route"))
	w.WriteHeader(http.StatusNoContent)
}

func (u *UI) senderCloseTab(w http.ResponseWriter, r *http.Request) {
	u.app.sender.CloseTab(r.FormValue("id"))
	writeJSON(w, map[string]any{"tabs": u.app.sender.Tabs()})
}

func (u *UI) senderSend(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	in := SendReq{Tab: r.Form.Get("id"), Raw: r.Form.Get("raw"), Target: r.Form.Get("target"),
		Route: r.Form.Get("route"), UpdateCL: r.Form.Get("update_cl") == "1"}
	// Sending saves the tab too, so a reload keeps what was typed.
	u.app.sender.SaveTab(in.Tab, "", in.Raw, in.Target, in.Route)
	e, err := u.app.sender.Send(r.Context(), in)
	if err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, entryJSON(e, true))
}

func (u *UI) senderHistory(w http.ResponseWriter, r *http.Request) {
	list := u.app.sender.History(r.URL.Query().Get("id"))
	out := make([]any, len(list))
	for i, e := range list {
		out[i] = entryJSON(e, false)
	}
	writeJSON(w, out)
}

func (u *UI) senderEntry(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	n, _ := strconv.Atoi(q.Get("n"))
	e := u.app.sender.Entry(q.Get("id"), n)
	if e == nil {
		http.Error(w, "That send is no longer in the history.", http.StatusNotFound)
		return
	}
	writeJSON(w, entryJSON(e, true))
}

// entryJSON describes one send. The raw text is only included when asked for, so the history
// list stays small.
func entryJSON(e *Entry, withBodies bool) map[string]any {
	m := map[string]any{"n": e.N, "at": e.At, "status": e.Status, "reason": e.Reason, "dur": e.Dur,
		"size": e.Size, "flow": e.Flow, "route": e.Route, "target": e.Target}
	if e.Err != "" {
		m["err"] = e.Err
	}
	if e.Note != "" {
		m["note"] = e.Note
	}
	if withBodies {
		m["req"] = string(e.req)
		res := e.res
		if len(res) > maxSenderShow {
			m["truncated"] = len(res)
			res = res[:maxSenderShow]
		}
		m["res"] = string(res)
	}
	return m
}

func (u *UI) senderSaveRoute(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	port, _ := strconv.Atoi(strings.TrimSpace(r.Form.Get("port")))
	timeout, _ := strconv.Atoi(strings.TrimSpace(r.Form.Get("timeout")))
	rt := &Route{
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
	u.app.sender.SaveRoute(rt)
	writeJSON(w, map[string]any{"routes": u.app.sender.Routes(), "saved": rt.ID})
}

func (u *UI) senderDeleteRoute(w http.ResponseWriter, r *http.Request) {
	u.app.sender.DeleteRoute(r.FormValue("id"))
	writeJSON(w, map[string]any{"routes": u.app.sender.Routes()})
}

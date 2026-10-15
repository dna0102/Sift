package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"sift/internal/scan"
)

func (u *UI) scanRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/scan/findings", u.scanFindings)
	m.HandleFunc("GET /api/scan/finding/{id}", u.scanFinding)
	m.HandleFunc("GET /api/scan/checks", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, scan.AllChecks()) })
	m.HandleFunc("GET /api/scan/stats", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, u.app.Scanner.Store().Stats()) })
	m.HandleFunc("GET /api/scan/jobs", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, u.app.Scanner.Store().Jobs()) })
	m.HandleFunc("GET /api/scan/events", u.scanEvents)
	m.HandleFunc("POST /api/scan/passive", u.scanPassive)
	m.HandleFunc("POST /api/scan/clear", func(w http.ResponseWriter, r *http.Request) { u.app.Scanner.Store().Clear() })
	m.HandleFunc("POST /api/scan/stop", u.scanStop)
}

func (u *UI) scanFindings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, u.app.Scanner.Store().All())
}

func (u *UI) scanFinding(w http.ResponseWriter, r *http.Request) {
	f := u.app.Scanner.Store().Get(r.PathValue("id"))
	if f == nil {
		http.Error(w, "finding not found", http.StatusNotFound)
		return
	}
	writeJSON(w, f)
}

func (u *UI) scanPassive(w http.ResponseWriter, r *http.Request) {
	job := u.app.Scanner.PassiveSweep()
	toast(w, "Analysing captured traffic")
	writeJSON(w, job)
}

func (u *UI) scanStop(w http.ResponseWriter, r *http.Request) {
	if id := r.FormValue("job"); id != "" {
		u.app.Scanner.Stop(id)
	} else {
		u.app.Scanner.StopAll()
	}
	toast(w, "Stopping scan")
}

func (u *UI) scanEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	rc := http.NewResponseController(w)
	st := u.app.Scanner.Store()
	ch := st.Subscribe()
	defer st.Unsubscribe(ch)
	stats := st.Stats()
	snapshot, _ := json.Marshal(map[string]any{"findings": st.All(), "jobs": st.Jobs(), "stats": &stats})
	fmt.Fprintf(w, "data: %s\n\n", snapshot)
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

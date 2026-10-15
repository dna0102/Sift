package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"sift/internal/apk"
)

func (u *UI) appReports(w http.ResponseWriter, r *http.Request) {
	reports := u.app.Mobile.List()
	out := make([]apk.Report, 0, len(reports))
	for _, rep := range reports {
		out = append(out, rep.Snapshot(false))
	}
	writeJSON(w, map[string]any{"reports": out, "tools": u.app.Tools.Status()})
}

func (u *UI) appReport(w http.ResponseWriter, r *http.Request) {
	rep := u.reportArg(w, r)
	if rep == nil {
		return
	}
	writeJSON(w, rep.Snapshot(true))
}

func (u *UI) reportArg(w http.ResponseWriter, r *http.Request) *apk.Report {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	rep := u.app.Mobile.Get(id)
	if rep == nil {
		http.Error(w, "No such report", http.StatusNotFound)
	}
	return rep
}

func (u *UI) appAnalyse(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "upload failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "choose an .apk or .ipa file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, 1<<30))
	if err != nil {
		http.Error(w, "couldn't read the file", http.StatusBadRequest)
		return
	}
	rep, err := u.app.Analyser.Analyse(hdr.Filename, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"id": rep.ID})
}

func (u *UI) appDeleteReport(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	u.app.Mobile.Remove(id)
}

func (u *UI) appEnsureJadx(w http.ResponseWriter, r *http.Request) {
	u.app.Tools.EnsureJadx(func(ok bool, msg string) {
		if msg != "" {

		}
		u.app.Mobile.Changed(0)
	})
	writeJSON(w, u.app.Tools.Status())
}

func (u *UI) appFile(w http.ResponseWriter, r *http.Request) {
	rep := u.reportArg(w, r)
	if rep == nil {
		return
	}
	m := rep.Lock()
	m.Lock()
	src := rep.SrcDir
	m.Unlock()
	if src == "" {
		http.Error(w, "nothing decompiled", http.StatusNotFound)
		return
	}
	rel := r.URL.Query().Get("path")
	clean := filepath.Clean(filepath.Join(src, filepath.FromSlash(rel)))
	srcAbs, _ := filepath.Abs(src)
	absClean, _ := filepath.Abs(clean)
	if !strings.HasPrefix(absClean, srcAbs+string(os.PathSeparator)) {
		http.Error(w, "bad path", http.StatusForbidden)
		return
	}
	data, err := os.ReadFile(clean)
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	if len(data) > 2<<20 {
		data = data[:2<<20]
	}
	line, _ := strconv.Atoi(r.URL.Query().Get("line"))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"path": rel, "line": line, "html": highlightSource(rel, data),
	})
}

func (u *UI) appEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	rc := http.NewResponseController(w)
	ch := u.app.Mobile.Subscribe()
	defer u.app.Mobile.Unsubscribe(ch)

	fmt.Fprintf(w, "data: %s\n\n", mustJSON(map[string]any{"tools": u.app.Tools.Status(), "emulator": u.app.Emulator.Status()}))
	rc.Flush()
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()

	poll := time.NewTicker(400 * time.Millisecond)
	defer poll.Stop()
	for {
		select {
		case <-ch:
			fmt.Fprintf(w, "data: %s\n\n", mustJSON(map[string]any{"reload": true, "tools": u.app.Tools.Status(), "emulator": u.app.Emulator.Status()}))
			if rc.Flush() != nil {
				return
			}
		case <-poll.C:
			st := u.app.Tools.Status()
			emu := u.app.Emulator.Status()
			if st.Downloading || (emu.State != "idle" && emu.State != "error") {
				fmt.Fprintf(w, "data: %s\n\n", mustJSON(map[string]any{"tools": st, "emulator": emu}))
				if rc.Flush() != nil {
					return
				}
			}
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

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

package ui

import (
	"bufio"
	"bytes"
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
	roots := rep.SourceRoots()
	if len(roots) == 0 {
		http.Error(w, "This app's extracted files aren't available any more. Re-open the app.", http.StatusNotFound)
		return
	}
	rel := r.URL.Query().Get("path")
	path := ""
	for _, root := range roots {
		if p := resolveUnder(root, rel); p != "" {
			path = p
			break
		}
	}
	if path == "" {
		http.Error(w, rel+" isn't in this app's extracted files. Re-open the app if Sift was restarted.", http.StatusNotFound)
		return
	}
	line, _ := strconv.Atoi(r.URL.Query().Get("line"))
	data, first, err := readWindow(path, line, 600)
	if err != nil {
		http.Error(w, "couldn't read "+rel+": "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"path": rel, "line": line, "first": first, "html": highlightSource(rel, data, first),
	})
}

func resolveUnder(root, rel string) string {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return ""
	}
	p, err := filepath.Abs(filepath.Join(rootAbs, filepath.FromSlash(rel)))
	if err != nil || !strings.HasPrefix(p, rootAbs+string(os.PathSeparator)) {
		return ""
	}
	if st, err := os.Stat(p); err != nil || st.IsDir() {
		return ""
	}
	return p
}

func readWindow(path string, line, span int) ([]byte, int, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, 0, err
	}
	if st.Size() <= 1<<20 {
		data, err := os.ReadFile(path)
		return data, 1, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	first := max(1, line-span/2)
	last := first + span
	var out bytes.Buffer
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for n := 1; sc.Scan(); n++ {
		if n < first {
			continue
		}
		if n > last {
			break
		}
		if n > first {
			out.WriteByte('\n')
		}
		out.Write(sc.Bytes())
	}
	return out.Bytes(), first, sc.Err()
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

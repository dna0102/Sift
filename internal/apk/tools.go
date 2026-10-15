package apk

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	jadxVersion = "1.5.6"
	jadxURL     = "https://github.com/skylot/jadx/releases/download/v" + jadxVersion + "/jadx-" + jadxVersion + ".zip"
)

type Tools struct {
	home string

	mu       sync.Mutex
	jadxPath string

	dlMu     sync.Mutex
	dling    bool
	progress atomic.Int64
	total    atomic.Int64
	dlErr    string
}

func NewTools(home string) *Tools {
	t := &Tools{home: filepath.Join(home, "tools")}
	os.MkdirAll(t.home, 0o755)
	return t
}

func (t *Tools) jadxDir() string { return filepath.Join(t.home, "jadx-"+jadxVersion) }

func (t *Tools) launcherName() string {
	if runtime.GOOS == "windows" {
		return "jadx.bat"
	}
	return "jadx"
}

func (t *Tools) JadxPath() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.jadxPath != "" {
		return t.jadxPath
	}
	cached := filepath.Join(t.jadxDir(), "bin", t.launcherName())
	if FileExists(cached) {
		t.jadxPath = cached
		return cached
	}
	if p, err := exec.LookPath("jadx"); err == nil {
		t.jadxPath = p
		return p
	}
	return ""
}

func FileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func JavaAvailable() bool {
	if _, err := exec.LookPath("java"); err == nil {
		return true
	}
	if home := os.Getenv("JAVA_HOME"); home != "" {
		return FileExists(filepath.Join(home, "bin", "java")) || FileExists(filepath.Join(home, "bin", "java.exe"))
	}
	return false
}

type ToolStatus struct {
	JadxReady   bool   `json:"jadxReady"`
	JavaReady   bool   `json:"javaReady"`
	Downloading bool   `json:"downloading"`
	Progress    int64  `json:"progress"`
	Total       int64  `json:"total"`
	Percent     int    `json:"percent"`
	Error       string `json:"error,omitempty"`
	JadxVersion string `json:"jadxVersion"`
}

func (t *Tools) Status() ToolStatus {
	t.dlMu.Lock()
	dling, dlErr := t.dling, t.dlErr
	t.dlMu.Unlock()
	done, total := t.progress.Load(), t.total.Load()
	pct := 0
	if total > 0 {
		pct = int(done * 100 / total)
	}
	return ToolStatus{JadxReady: t.JadxPath() != "", JavaReady: JavaAvailable(), Downloading: dling,
		Progress: done, Total: total, Percent: pct, Error: dlErr, JadxVersion: jadxVersion}
}

func (t *Tools) EnsureJadx(onDone func(bool, string)) {
	if t.JadxPath() != "" {
		if onDone != nil {
			onDone(true, "")
		}
		return
	}
	t.dlMu.Lock()
	if t.dling {
		t.dlMu.Unlock()
		return
	}
	if !JavaAvailable() {
		t.dlMu.Unlock()
		if onDone != nil {
			onDone(false, "Java isn't installed. jadx needs a Java runtime (JRE 11+). Install one from https://adoptium.net and try again.")
		}
		return
	}
	t.dling, t.dlErr = true, ""
	t.dlMu.Unlock()

	go func() {
		err := t.downloadJadx()
		t.dlMu.Lock()
		t.dling = false
		if err != nil {
			t.dlErr = err.Error()
		}
		t.dlMu.Unlock()
		if onDone != nil {
			if err != nil {
				onDone(false, "Couldn't set up jadx: "+err.Error())
			} else {
				onDone(true, "jadx is ready.")
			}
		}
	}()
}

func (t *Tools) downloadJadx() error {
	t.progress.Store(0)
	t.total.Store(0)
	tmp := filepath.Join(t.home, "jadx.zip.part")
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(jadxURL)
	if err != nil {
		out.Close()
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		out.Close()
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}
	t.total.Store(resp.ContentLength)
	if _, err := io.Copy(&progressWriter{out, &t.progress}, resp.Body); err != nil {
		out.Close()
		return err
	}
	out.Close()

	dir := t.jadxDir()
	os.RemoveAll(dir)
	if err := unzipTo(tmp, dir); err != nil {
		return err
	}
	launcher := filepath.Join(dir, "bin", t.launcherName())
	if !FileExists(launcher) {
		return fmt.Errorf("jadx launcher not found after unpacking")
	}
	if runtime.GOOS != "windows" {
		os.Chmod(launcher, 0o755)
	}
	t.mu.Lock()
	t.jadxPath = launcher
	t.mu.Unlock()
	return nil
}

type progressWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (pw *progressWriter) Write(b []byte) (int, error) {
	n, err := pw.w.Write(b)
	pw.n.Add(int64(n))
	return n, err
}

func unzipTo(zipPath, dest string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	destAbs, _ := filepath.Abs(dest)
	for _, f := range zr.File {
		target := filepath.Join(dest, f.Name)
		abs, _ := filepath.Abs(target)
		if !strings.HasPrefix(abs, destAbs+string(os.PathSeparator)) && abs != destAbs {
			continue
		}
		if f.FileInfo().IsDir() {
			os.MkdirAll(target, 0o755)
			continue
		}
		os.MkdirAll(filepath.Dir(target), 0o755)
		rc, err := f.Open()
		if err != nil {
			return err
		}
		w, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(w, rc)
		w.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

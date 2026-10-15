package main

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// Certificate pinning: some apps only accept their server's real certificate, so
// decrypting their traffic breaks them. Sift notices when an app rejects its
// certificate and lets later connections to that host through untouched, so the app
// keeps working. (Same idea as mitmproxy's tls_passthrough example.)

// KnownPinned are services that pin certificates or break when decrypted.
// Used when "skip services known to pin" is on.
var KnownPinned = []string{
	"*.apple.com", "*.icloud.com", "*.mzstatic.com", "*.apple-cloudkit.com", "*.push.apple.com",
	"*.whatsapp.net", "*.whatsapp.com", "*.signal.org",
	"*.dropbox.com", "*.dropboxapi.com",
	"*.1password.com", "*.bitwarden.com",
	"*.update.microsoft.com", "*.windowsupdate.com", "*.delivery.mp.microsoft.com",
	"*.events.data.microsoft.com",
	"*.battle.net", "*.blizzard.com",
}

type PinInfo struct {
	Host     string
	Reason   string
	Failures int
	Since    time.Time
}

type pinEntry struct {
	failures int
	first    time.Time
	last     time.Time
	active   bool
	reason   string
}

type PinTracker struct {
	mu    sync.Mutex
	hosts map[string]*pinEntry
}

func NewPinTracker() *PinTracker { return &PinTracker{hosts: map[string]*pinEntry{}} }

// Failed records a rejected handshake. It returns true when the host is now passed through.
//   - An explicit TLS alert from the app ("bad certificate", "unknown CA") counts immediately.
//   - The app silently hanging up mid-handshake counts after the second time within 2 minutes,
//     since that also happens for harmless reasons.
func (t *PinTracker) Failed(host string, alert bool, caTrusted bool) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.hosts[host]
	now := time.Now()
	if e == nil || now.Sub(e.last) > 2*time.Minute && !e.active {
		e = &pinEntry{first: now}
		t.hosts[host] = e
	}
	e.failures++
	e.last = now
	if e.active {
		return false
	}
	if alert || e.failures >= 2 {
		e.active = true
		e.reason = "app rejected the certificate (pinning)"
		if !caTrusted {
			e.reason = "Sift certificate not trusted yet"
		}
		return true
	}
	return false
}

func (t *PinTracker) Has(host string) bool { return t.Reason(host) != "" }

// Reason says why host is passed through, or "" if it isn't.
func (t *PinTracker) Reason(host string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e := t.hosts[host]; e != nil && e.active {
		return e.reason
	}
	return ""
}

func (t *PinTracker) Add(host, reason string) {
	t.mu.Lock()
	t.hosts[host] = &pinEntry{active: true, reason: reason, first: time.Now(), last: time.Now()}
	t.mu.Unlock()
}

func (t *PinTracker) Remove(host string) {
	t.mu.Lock()
	delete(t.hosts, host)
	t.mu.Unlock()
}

// ClearUntrusted forgets hosts that only failed because the certificate wasn't installed yet.
func (t *PinTracker) ClearUntrusted() {
	t.mu.Lock()
	for h, e := range t.hosts {
		if strings.Contains(e.reason, "not trusted") {
			delete(t.hosts, h)
		}
	}
	t.mu.Unlock()
}

func (t *PinTracker) List() []PinInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []PinInfo
	for h, e := range t.hosts {
		if e.active {
			out = append(out, PinInfo{Host: h, Reason: e.reason, Failures: e.failures, Since: e.first})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

func (t *PinTracker) Count() int { return len(t.List()) }

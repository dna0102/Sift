package proxy

import (
	"sort"
	"strings"
	"sync"
	"time"
)

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
	mu      sync.Mutex
	hosts   map[string]*pinEntry
	clients map[string]*clientTrust
}

type clientTrust struct {
	failed    map[string]time.Time
	learned   []string
	lastOK    time.Time
	distrusts bool
}

const (
	distrustWindow = 3 * time.Minute
	distrustHosts  = 3
	untrustedPass  = "Sift certificate not trusted by this device"
)

func NewPinTracker() *PinTracker {
	return &PinTracker{hosts: map[string]*pinEntry{}, clients: map[string]*clientTrust{}}
}

func (t *PinTracker) client(key string) *clientTrust {
	c := t.clients[key]
	if c == nil {
		c = &clientTrust{failed: map[string]time.Time{}}
		t.clients[key] = c
	}
	return c
}

func (t *PinTracker) Succeeded(key string) (recovered bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.client(key)
	c.lastOK = time.Now()
	recovered = c.distrusts
	c.distrusts = false
	clear(c.failed)
	return recovered
}

func (t *PinTracker) Rejected(key, host string) (distrusts bool, unlearn []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	c := t.client(key)
	for h, at := range c.failed {
		if now.Sub(at) > distrustWindow {
			delete(c.failed, h)
		}
	}
	c.failed[host] = now
	if c.distrusts {
		return true, nil
	}
	if len(c.failed) < distrustHosts || now.Sub(c.lastOK) < distrustWindow {
		return false, nil
	}
	c.distrusts = true
	for h := range c.failed {
		if e := t.hosts[h]; e != nil && e.active {
			e.reason = untrustedPass
		}
	}
	unlearn, c.learned = c.learned, nil
	return true, unlearn
}

func (t *PinTracker) Learned(key, host string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.client(key)
	c.learned = append(c.learned, host)
}

func (t *PinTracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	clear(t.hosts)
	clear(t.clients)
}

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
			e.reason = untrustedPass
		}
		return true
	}
	return false
}

func (t *PinTracker) Has(host string) bool { return t.Reason(host) != "" }

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

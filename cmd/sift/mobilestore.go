package main

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// A Report is one analysed app. It mirrors how the traffic Store works: kept in memory,
// with a live-update channel so the dashboard shows progress as the analysis runs.

type Report struct {
	mu *sync.Mutex

	ID       int64     `json:"id"`
	Name     string    `json:"name"`     // file name
	Kind     string    `json:"kind"`     // apk | ipa
	Size     int64     `json:"size"`     // input file size
	Added    time.Time `json:"-"`
	State    string    `json:"state"`    // queued | downloading-tool | decompiling | scanning | done | error
	Progress string    `json:"progress"` // human text for the current stage
	Error    string    `json:"error,omitempty"`

	// identity
	Package   string   `json:"package,omitempty"`
	Label     string   `json:"label,omitempty"`
	Version   string   `json:"version,omitempty"`
	Build     string   `json:"build,omitempty"`
	MinSDK    string   `json:"minSdk,omitempty"`
	TargetSDK string   `json:"targetSdk,omitempty"`
	Platform  string   `json:"platform,omitempty"` // Android / iOS
	Signer    string   `json:"signer,omitempty"`

	Permissions []string   `json:"permissions,omitempty"`
	Components  []Component `json:"components,omitempty"`
	DeepLinks   []string   `json:"deepLinks,omitempty"`
	Cleartext   bool       `json:"cleartext"`         // allows cleartext HTTP
	CleartextNote string   `json:"cleartextNote,omitempty"`

	Findings []Finding `json:"findings,omitempty"`
	Hosts    []string  `json:"hosts,omitempty"` // unique endpoint hosts, for cross-linking

	SrcDir   string `json:"-"` // decompiled output on disk
	InPath   string `json:"-"` // the saved APK/IPA on disk (for running in the emulator)
	Counts   map[string]int `json:"counts"` // findings per kind
	QuickScan bool  `json:"quickScan"` // true = scanned directly (too big to fully decompile)
}

// apkPath returns the saved APK path if it still exists (for the emulator), else "".
func (r *Report) apkPath() string {
	r.lock().Lock()
	defer r.lock().Unlock()
	if r.Kind == "apk" && r.InPath != "" && fileExists(r.InPath) {
		return r.InPath
	}
	return ""
}

type Component struct {
	Type     string `json:"type"` // activity | service | receiver | provider
	Name     string `json:"name"`
	Exported bool   `json:"exported"`
}

func (r *Report) lock() *sync.Mutex {
	if r.mu == nil {
		r.mu = &sync.Mutex{}
	}
	return r.mu
}

func (r *Report) set(fn func()) {
	m := r.lock()
	m.Lock()
	fn()
	m.Unlock()
}

// snapshot returns a copy safe to hand to JSON encoding.
func (r *Report) snapshot(full bool) Report {
	m := r.lock()
	m.Lock()
	defer m.Unlock()
	c := *r
	c.mu = nil
	if !full { // list view: drop the big slices
		c.Findings = nil
		c.Components = nil
		c.Permissions = nil
		c.DeepLinks = nil
		c.Hosts = nil
	}
	return c
}

type MobileStore struct {
	mu      sync.RWMutex
	reports map[int64]*Report
	order   []int64
	seq     atomic.Int64
	subs    map[chan int64]struct{}
}

func NewMobileStore() *MobileStore {
	return &MobileStore{reports: map[int64]*Report{}, subs: map[chan int64]struct{}{}}
}

func (s *MobileStore) Add(r *Report) {
	r.ID = s.seq.Add(1)
	r.Added = time.Now()
	if r.Counts == nil {
		r.Counts = map[string]int{}
	}
	s.mu.Lock()
	s.reports[r.ID] = r
	s.order = append(s.order, r.ID)
	// keep at most 30 reports
	for len(s.order) > 30 {
		old := s.order[0]
		s.order = s.order[1:]
		if rep := s.reports[old]; rep != nil {
			cleanupReport(rep)
		}
		delete(s.reports, old)
	}
	s.mu.Unlock()
	s.Changed(r.ID)
}

func (s *MobileStore) Get(id int64) *Report {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.reports[id]
}

func (s *MobileStore) List() []*Report {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Report, 0, len(s.order))
	for i := len(s.order) - 1; i >= 0; i-- { // newest first
		out = append(out, s.reports[s.order[i]])
	}
	return out
}

func (s *MobileStore) Remove(id int64) {
	s.mu.Lock()
	if r := s.reports[id]; r != nil {
		cleanupReport(r)
		delete(s.reports, id)
		s.order = slicesDeleteInt64(s.order, id)
	}
	s.mu.Unlock()
	s.Changed(id)
}

func slicesDeleteInt64(s []int64, v int64) []int64 {
	out := s[:0]
	for _, x := range s {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

// --- live updates ---

func (s *MobileStore) Subscribe() chan int64 {
	ch := make(chan int64, 64)
	s.mu.Lock()
	s.subs[ch] = struct{}{}
	s.mu.Unlock()
	return ch
}

func (s *MobileStore) Unsubscribe(ch chan int64) {
	s.mu.Lock()
	if _, ok := s.subs[ch]; ok {
		delete(s.subs, ch)
		close(ch)
	}
	s.mu.Unlock()
}

// Changed notifies subscribers that report id updated (throttled by the caller where noisy).
func (s *MobileStore) Changed(id int64) {
	s.mu.RLock()
	for ch := range s.subs {
		select {
		case ch <- id:
		default:
		}
	}
	s.mu.RUnlock()
}

func (r *Report) recount() {
	counts := map[string]int{}
	hostSet := map[string]bool{}
	for _, f := range r.Findings {
		counts[f.Kind]++
		if f.Kind == "endpoint" {
			if h := hostOf(f.Value); h != "" {
				hostSet[h] = true
			}
		}
	}
	hosts := make([]string, 0, len(hostSet))
	for h := range hostSet {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	r.Counts = counts
	r.Hosts = hosts
}

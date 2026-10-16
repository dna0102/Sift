package apk

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type Report struct {
	mu *sync.Mutex

	ID       int64     `json:"id"`
	Name     string    `json:"name"`
	Kind     string    `json:"kind"`
	Size     int64     `json:"size"`
	Added    time.Time `json:"-"`
	State    string    `json:"state"`
	Progress string    `json:"progress"`
	Error    string    `json:"error,omitempty"`

	Package   string `json:"package,omitempty"`
	Label     string `json:"label,omitempty"`
	Version   string `json:"version,omitempty"`
	Build     string `json:"build,omitempty"`
	MinSDK    string `json:"minSdk,omitempty"`
	TargetSDK string `json:"targetSdk,omitempty"`
	Platform  string `json:"platform,omitempty"`
	Signer    string `json:"signer,omitempty"`

	Permissions   []string    `json:"permissions,omitempty"`
	Components    []Component `json:"components,omitempty"`
	DeepLinks     []string    `json:"deepLinks,omitempty"`
	Cleartext     bool        `json:"cleartext"`
	CleartextNote string      `json:"cleartextNote,omitempty"`

	Findings []Finding `json:"findings,omitempty"`
	Hosts    []string  `json:"hosts,omitempty"`

	SrcDir    string         `json:"-"`
	ScanDir   string         `json:"-"`
	InPath    string         `json:"-"`
	Counts    map[string]int `json:"counts"`
	QuickScan bool           `json:"quickScan"`
}

func (r *Report) APKPath() string {
	r.Lock().Lock()
	defer r.Lock().Unlock()
	if r.Kind == "apk" && r.InPath != "" && FileExists(r.InPath) {
		return r.InPath
	}
	return ""
}

type Component struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Exported bool   `json:"exported"`
}

func (r *Report) SourceRoots() []string {
	r.Lock().Lock()
	defer r.Lock().Unlock()
	var roots []string
	for _, d := range []string{r.ScanDir, r.SrcDir} {
		if d != "" && (len(roots) == 0 || roots[0] != d) {
			roots = append(roots, d)
		}
	}
	return roots
}

func (r *Report) Lock() *sync.Mutex {
	if r.mu == nil {
		r.mu = &sync.Mutex{}
	}
	return r.mu
}

func (r *Report) set(fn func()) {
	m := r.Lock()
	m.Lock()
	fn()
	m.Unlock()
}

func (r *Report) Snapshot(full bool) Report {
	m := r.Lock()
	m.Lock()
	defer m.Unlock()
	c := *r
	c.mu = nil
	if !full {
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
	for i := len(s.order) - 1; i >= 0; i-- {
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

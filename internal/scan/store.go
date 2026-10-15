package scan

import (
	"encoding/json"
	"sync"
	"time"
)

type Store struct {
	mu       sync.RWMutex
	findings map[string]*Finding
	order    []string
	jobs     map[string]*JobStatus
	joborder []string

	clients map[chan []byte]struct{}
	dirty   map[string]struct{}
	jdirty  map[string]struct{}
	cleared bool
	cmu     sync.Mutex
}

func NewStore() *Store {
	s := &Store{
		findings: map[string]*Finding{},
		jobs:     map[string]*JobStatus{},
		clients:  map[chan []byte]struct{}{},
		dirty:    map[string]struct{}{},
		jdirty:   map[string]struct{}{},
	}
	go s.loop()
	return s
}

const maxEvidence = 12

func (s *Store) Add(f *Finding) bool {
	f.stamp()
	s.mu.Lock()
	cur, ok := s.findings[f.ID]
	isNew := !ok
	if ok {
		cur.Count++
		cur.Last = time.Now().UnixMilli()
		if sevRank[f.Severity] < sevRank[cur.Severity] {
			cur.Severity = f.Severity
		}
		if confRank[f.Confidence] < confRank[cur.Confidence] {
			cur.Confidence = f.Confidence
		}
		cur.Evidence = mergeEvidence(cur.Evidence, f.Evidence)
		cur.Flows = mergeInts(cur.Flows, f.Flows)
	} else {
		s.findings[f.ID] = f
		s.order = append(s.order, f.ID)
	}
	s.mu.Unlock()
	s.mark(f.ID)
	return isNew
}

func mergeEvidence(a, b []Evidence) []Evidence {
	for _, e := range b {
		if len(a) >= maxEvidence {
			break
		}
		a = append(a, e)
	}
	return a
}

func mergeInts(a, b []int64) []int64 {
	seen := map[int64]bool{}
	for _, v := range a {
		seen[v] = true
	}
	for _, v := range b {
		if !seen[v] {
			a = append(a, v)
			seen[v] = true
		}
	}
	return a
}

func (s *Store) Get(id string) *Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findings[id]
}

func (s *Store) Annotate(id, text string) bool {
	s.mu.Lock()
	f, ok := s.findings[id]
	if ok {
		f.AITriage = text
	}
	s.mu.Unlock()
	if ok {
		s.mark(id)
	}
	return ok
}

func (s *Store) All() []*Finding {
	s.mu.RLock()
	out := make([]*Finding, 0, len(s.order))
	for _, id := range s.order {
		out = append(out, s.findings[id])
	}
	s.mu.RUnlock()
	sortFindings(out)
	return out
}

func (s *Store) Clear() {
	s.mu.Lock()
	s.findings = map[string]*Finding{}
	s.order = nil
	s.mu.Unlock()
	s.cmu.Lock()
	s.cleared = true
	s.dirty = map[string]struct{}{}
	s.cmu.Unlock()
}

type Stats struct {
	Total    int            `json:"total"`
	BySev    map[string]int `json:"bySev"`
	ByHost   map[string]int `json:"byHost"`
	RiskScore int           `json:"riskScore"`
}

func (s *Store) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := Stats{BySev: map[string]int{}, ByHost: map[string]int{}}
	for _, id := range s.order {
		f := s.findings[id]
		st.Total++
		st.BySev[string(f.Severity)]++
		st.ByHost[f.Host]++
		st.RiskScore += f.Severity.Score()
	}
	return st
}

func (s *Store) setJob(j *JobStatus) {
	s.mu.Lock()
	if _, ok := s.jobs[j.ID]; !ok {
		s.joborder = append(s.joborder, j.ID)
	}
	s.jobs[j.ID] = j
	s.mu.Unlock()
	s.markJob(j.ID)
}

func (s *Store) Jobs() []*JobStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*JobStatus, 0, len(s.joborder))
	for _, id := range s.joborder {
		out = append(out, s.jobs[id])
	}
	return out
}

func (s *Store) Job(id string) *JobStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.jobs[id]
}

func (s *Store) mark(id string) {
	s.cmu.Lock()
	s.dirty[id] = struct{}{}
	s.cmu.Unlock()
}

func (s *Store) markJob(id string) {
	s.cmu.Lock()
	s.jdirty[id] = struct{}{}
	s.cmu.Unlock()
}

func (s *Store) Subscribe() chan []byte {
	ch := make(chan []byte, 256)
	s.cmu.Lock()
	s.clients[ch] = struct{}{}
	s.cmu.Unlock()
	return ch
}

func (s *Store) Unsubscribe(ch chan []byte) {
	s.cmu.Lock()
	if _, ok := s.clients[ch]; ok {
		delete(s.clients, ch)
		close(ch)
	}
	s.cmu.Unlock()
}

type event struct {
	Findings []*Finding   `json:"findings,omitempty"`
	Jobs     []*JobStatus `json:"jobs,omitempty"`
	Cleared  bool         `json:"cleared,omitempty"`
	Stats    *Stats       `json:"stats,omitempty"`
}

func (s *Store) loop() {
	for range time.Tick(200 * time.Millisecond) {
		s.cmu.Lock()
		if len(s.dirty) == 0 && len(s.jdirty) == 0 && !s.cleared {
			s.cmu.Unlock()
			continue
		}
		dirty, jdirty, cleared := s.dirty, s.jdirty, s.cleared
		s.dirty, s.jdirty, s.cleared = map[string]struct{}{}, map[string]struct{}{}, false
		s.cmu.Unlock()

		ev := event{Cleared: cleared}
		s.mu.RLock()
		for id := range dirty {
			if f := s.findings[id]; f != nil {
				ev.Findings = append(ev.Findings, f)
			}
		}
		for id := range jdirty {
			if j := s.jobs[id]; j != nil {
				ev.Jobs = append(ev.Jobs, j)
			}
		}
		s.mu.RUnlock()
		st := s.Stats()
		ev.Stats = &st

		data, _ := json.Marshal(ev)
		s.cmu.Lock()
		for ch := range s.clients {
			select {
			case ch <- data:
			default:
				delete(s.clients, ch)
				close(ch)
			}
		}
		s.cmu.Unlock()
	}
}

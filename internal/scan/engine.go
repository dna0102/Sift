package scan

import (
	"strconv"
	"sync"
	"time"

	"sift/internal/core"
)

type JobStatus struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	State    string `json:"state"`
	Target   string `json:"target"`
	Started  int64  `json:"started"`
	Ended    int64  `json:"ended,omitempty"`
	Requests int    `json:"requests"`
	Findings int    `json:"findings"`
	Queued   int    `json:"queued"`
	Done     int    `json:"done"`
	Note     string `json:"note,omitempty"`
}

type Engine struct {
	flows         *core.Store
	store         *Store
	cfg           *core.Config
	req           Requester
	passiveChecks []passiveCheck

	mu      sync.Mutex
	seq     int
	cancels map[string]func()
}

func NewEngine(flows *core.Store, cfg *core.Config) *Engine {
	cm := passiveCheckMap()
	checks := make([]passiveCheck, 0, len(cm))
	for _, id := range []string{"headers", "cookies", "cors", "infoleak", "mixedtls", "secrets", "jsendpoints"} {
		checks = append(checks, cm[id])
	}
	return &Engine{
		flows: flows, store: NewStore(), cfg: cfg,
		passiveChecks: checks, cancels: map[string]func(){},
	}
}

func (e *Engine) SetRequester(r Requester) { e.req = r }

func (e *Engine) Store() *Store { return e.store }

func (e *Engine) newJobID(kind string) string {
	e.mu.Lock()
	e.seq++
	n := e.seq
	e.mu.Unlock()
	return kind + "-" + strconv.Itoa(n)
}

func (e *Engine) PassiveSweep() *JobStatus {
	all := e.flows.All()
	job := &JobStatus{ID: e.newJobID("passive"), Kind: "passive", State: "running",
		Target: "captured traffic", Started: time.Now().UnixMilli(), Queued: len(all)}
	e.store.setJob(job)
	before := e.store.Stats().Total
	go func() {
		for i, f := range all {
			e.Passive(f)
			job.Done = i + 1
			if i%50 == 0 {
				e.store.setJob(job)
			}
		}
		job.State = "done"
		job.Ended = time.Now().UnixMilli()
		job.Findings = e.store.Stats().Total - before
		e.store.setJob(job)
	}()
	return job
}

func (e *Engine) Stop(id string) {
	e.mu.Lock()
	cancel := e.cancels[id]
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (e *Engine) StopAll() {
	e.mu.Lock()
	for _, c := range e.cancels {
		c()
	}
	e.mu.Unlock()
}

func (e *Engine) registerCancel(id string, cancel func()) {
	e.mu.Lock()
	e.cancels[id] = cancel
	e.mu.Unlock()
}

func (e *Engine) clearCancel(id string) {
	e.mu.Lock()
	delete(e.cancels, id)
	e.mu.Unlock()
}

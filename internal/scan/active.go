package scan

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sift/internal/core"
)

var errBudget = errors.New("request budget exhausted")

type runner struct {
	ctx     context.Context
	req     Requester
	store   *Store
	opts    Options
	timeout time.Duration

	sem    chan struct{}
	ticker *time.Ticker
	budget atomic.Int64

	job      *JobStatus
	jobMu    sync.Mutex
	requests atomic.Int64
	findings atomic.Int64
	doneT    atomic.Int64
}

func newRunner(ctx context.Context, req Requester, store *Store, job *JobStatus, opts Options) *runner {
	r := &runner{ctx: ctx, req: req, store: store, opts: opts, job: job,
		sem: make(chan struct{}, opts.Concurrency), timeout: time.Duration(opts.TimeoutSec) * time.Second}
	r.budget.Store(int64(opts.MaxRequests))
	if opts.RateLimit > 0 {
		r.ticker = time.NewTicker(time.Second / time.Duration(opts.RateLimit))
	}
	return r
}

func (r *runner) stop() {
	if r.ticker != nil {
		r.ticker.Stop()
	}
}

func (r *runner) send(req *Request) (*Response, error) {
	if r.ctx.Err() != nil {
		return nil, r.ctx.Err()
	}
	if r.budget.Add(-1) < 0 {
		return nil, errBudget
	}
	select {
	case r.sem <- struct{}{}:
	case <-r.ctx.Done():
		return nil, r.ctx.Err()
	}
	defer func() { <-r.sem }()
	if r.ticker != nil {
		select {
		case <-r.ticker.C:
		case <-r.ctx.Done():
			return nil, r.ctx.Err()
		}
	}
	if req.Route == "" {
		req.Route = r.opts.Route
	}
	if req.Profile == "" {
		req.Profile = r.opts.Profile
	}
	ctx, cancel := context.WithTimeout(r.ctx, r.timeout)
	defer cancel()
	res, err := r.req.Do(ctx, req)
	if n := r.requests.Add(1); n%10 == 0 {
		r.syncJob()
	}
	return res, err
}

func (r *runner) add(f *Finding) {
	r.findings.Add(1)
	r.store.Add(f)
	r.syncJob()
}

func (r *runner) syncJob() {
	r.jobMu.Lock()
	r.job.Requests = int(r.requests.Load())
	r.job.Findings = int(r.findings.Load())
	r.job.Done = int(r.doneT.Load())
	j := *r.job
	r.jobMu.Unlock()
	r.store.setJob(&j)
	r.jobMu.Lock()
	*r.job = j
	r.jobMu.Unlock()
}

func (r *runner) baselineFor(t *target) *baseline {
	var resps []*Response
	for i := 0; i < 2; i++ {
		res, err := r.send(t.request("scan-base"))
		if err != nil || res == nil {
			break
		}
		resps = append(resps, res)
	}
	return newBaseline(resps)
}

type probe struct {
	run      *runner
	target   *target
	point    Insertion
	baseline *baseline
	opts     Options
}

func (p *probe) send(payload string, encode bool) (*Response, error) {
	req := p.point.apply(p.target, payload, encode)
	return p.run.send(req)
}

func (p *probe) add(f *Finding) {
	f.Method = p.target.method
	f.URL = p.target.url()
	f.Host = p.target.host
	if f.Param == "" {
		f.Param = p.point.Name
	}
	if f.Where == "" {
		f.Where = p.point.Where
	}
	p.run.add(f)
}

type activeCheck struct {
	id string
	fn func(*probe)
}

var activeChecks = []activeCheck{
	{"reflection", checkReflection},
	{"sqli", checkSQLi},
	{"ssti", checkSSTI},
	{"cmdi", checkCmdInjection},
	{"traversal", checkTraversal},
	{"redirect", checkOpenRedirect},
	{"crlf", checkCRLF},
	{"ssrf", checkSSRF},
	{"nosqli", checkNoSQLi},
}

func (e *Engine) Start(opts Options) (*JobStatus, error) {
	opts = opts.normalize()
	if e.req == nil {
		return nil, errors.New("the scanner has no way to send requests")
	}
	if len(nonEmpty(opts.Scope.Include)) == 0 {
		return nil, errors.New("set at least one in-scope host before running an active scan")
	}
	job := &JobStatus{ID: e.newJobID("active"), Kind: "active", State: "running",
		Target: strings.Join(nonEmpty(opts.Scope.Include), ", "), Started: time.Now().UnixMilli()}
	ctx, cancel := context.WithCancel(context.Background())
	e.registerCancel(job.ID, cancel)
	e.store.setJob(job)

	go func() {
		defer e.clearCancel(job.ID)
		run := newRunner(ctx, e.req, e.store, job, opts)
		defer run.stop()

		targets := e.buildTargets(opts)
		job.Queued = len(targets)
		e.store.setJob(job)

		var wg sync.WaitGroup
		tasks := make(chan *target)
		workers := opts.Concurrency
		if workers > len(targets) {
			workers = len(targets)
		}
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for t := range tasks {
					if ctx.Err() != nil {
						return
					}
					e.scanTarget(run, t, opts)
					run.doneT.Add(1)
					run.syncJob()
				}
			}()
		}
		for _, t := range targets {
			select {
			case tasks <- t:
			case <-ctx.Done():
			}
		}
		close(tasks)
		wg.Wait()

		if opts.Discover && ctx.Err() == nil {
			e.discover(run, opts)
		}

		run.syncJob()
		if ctx.Err() != nil {
			job.State = "stopped"
		} else {
			job.State = "done"
		}
		job.Ended = time.Now().UnixMilli()
		e.store.setJob(job)
	}()
	return job, nil
}

func (e *Engine) scanTarget(run *runner, t *target, opts Options) {
	pts := insertionPoints(t)
	if opts.wants("reflection") || opts.wants("ssrf") || opts.wants("crlf") {
		pts = append(pts, headerPoints(t)...)
	}
	if len(pts) == 0 {
		return
	}
	base := run.baselineFor(t)
	for _, pt := range pts {
		if run.ctx.Err() != nil {
			return
		}
		p := &probe{run: run, target: t, point: pt, baseline: base, opts: opts}
		for _, chk := range activeChecks {
			if !opts.wants(chk.id) {
				continue
			}
			if run.ctx.Err() != nil {
				return
			}
			chk.fn(p)
		}
	}
	if opts.wants("xxe") {
		checkXXE(&targetProbe{run: run, target: t, baseline: base, opts: opts})
	}
}

func (e *Engine) buildTargets(opts Options) []*target {
	var flows []*core.Flow
	if len(opts.Seeds) > 0 {
		for _, id := range opts.Seeds {
			if f := e.flows.Get(id); f != nil {
				flows = append(flows, f)
			}
		}
	} else {
		flows = e.flows.All()
	}
	seen := map[string]bool{}
	var out []*target
	for _, f := range flows {
		t := targetFromFlow(f)
		if t == nil || t.host == "" {
			continue
		}
		if !opts.Scope.InScope(t.url()) {
			continue
		}
		t.route, t.profile = opts.Route, opts.Profile
		key := t.method + " " + t.host + t.path + "?" + paramNames(t)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
	}
	return out
}

func paramNames(t *target) string {
	var names []string
	for _, p := range insertionPoints(t) {
		names = append(names, p.Where+":"+p.Name)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

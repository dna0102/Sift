package main

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Pending is a request or response held at a breakpoint until the user decides.
type Pending struct {
	ID      int64
	Flow    *Flow
	Phase   string // request | response
	Rule    string
	Body    []byte
	Created time.Time
	ch      chan Decision
}

type Decision struct {
	Action   string // continue | execute | abort
	Method   string
	URL      string
	Headers  string
	Body     string
	EditBody bool
	Status   int
}

type Breakpoints struct {
	mu    sync.Mutex
	seq   int64
	items map[int64]*Pending
}

func NewBreakpoints() *Breakpoints { return &Breakpoints{items: map[int64]*Pending{}} }

// Pause blocks the exchange until Resume is called or the app disconnects.
func (b *Breakpoints) Pause(ctx context.Context, app *App, f *Flow, phase string, rule *Rule, body []byte) Decision {
	if f.ID == 0 { // breakpoints always show up, even with recording paused
		app.store.Add(f)
	}
	name := rule.Name
	if name == "" {
		name = rule.Pattern
	}
	b.mu.Lock()
	b.seq++
	p := &Pending{ID: b.seq, Flow: f, Phase: phase, Rule: name, Body: body, Created: time.Now(), ch: make(chan Decision, 1)}
	b.items[p.ID] = p
	b.mu.Unlock()

	f.mu.Lock()
	prev := f.State
	f.State = "paused"
	f.Tags = appendTag(f.Tags, "breakpoint")
	f.mu.Unlock()
	app.store.Touch(f)
	app.store.hub.StateChanged()

	var d Decision
	select {
	case d = <-p.ch:
	case <-ctx.Done():
		d = Decision{Action: "abort"}
	}
	b.mu.Lock()
	delete(b.items, p.ID)
	b.mu.Unlock()
	f.mu.Lock()
	f.State = prev
	f.mu.Unlock()
	app.store.Touch(f)
	app.store.hub.StateChanged()
	return d
}

func (b *Breakpoints) Resume(id int64, d Decision) {
	b.mu.Lock()
	p := b.items[id]
	b.mu.Unlock()
	if p != nil {
		select {
		case p.ch <- d:
		default:
		}
	}
}

func (b *Breakpoints) ResumeAll() {
	for _, p := range b.List() {
		b.Resume(p.ID, Decision{Action: "continue"})
	}
}

func (b *Breakpoints) List() []*Pending {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]*Pending, 0, len(b.items))
	for _, p := range b.items {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (b *Breakpoints) Count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.items)
}

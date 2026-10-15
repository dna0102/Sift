package core

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Flow struct {
	mu sync.Mutex

	ID    int64
	Kind  string
	Start time.Time
	End   time.Time
	State string
	App   string

	Method, Scheme, Host string
	Port                 int
	Path, Proto          string
	Client, Server       string

	ReqHeader http.Header
	ReqBody   []byte
	ReqSize   int64
	ReqTrunc  bool

	Status     int
	StatusText string
	ResProto   string
	ResHeader  http.Header
	ResTrailer http.Header
	ResBody    []byte
	ResSize    int64
	ResTrunc   bool
	Decoded    bool

	Err        string
	Note       string
	Tags       []string
	MappedFrom string
	Timing     Timing

	WS      []WSMessage
	WSCount int

	BytesUp, BytesDown atomic.Int64

	MaxBody int
	mem     int64
}

type Timing struct {
	DNS, Connect, TLS, Send, Wait, Receive time.Duration
	Reused                                 bool
}

type WSMessage struct {
	Out  bool
	Op   byte
	Time time.Time
	Size int
	Data []byte
}

func (f *Flow) Lock()   { f.mu.Lock() }
func (f *Flow) Unlock() { f.mu.Unlock() }

func (f *Flow) URL() string {
	return f.Scheme + "://" + HostPort(f.Host, f.Port, f.Scheme) + f.Path
}

func (f *Flow) Tag(t string) {
	f.Lock()
	for _, x := range f.Tags {
		if x == t {
			f.Unlock()
			return
		}
	}
	f.Tags = append(f.Tags, t)
	f.Unlock()
}

func (f *Flow) Capture(res bool, b []byte) {
	f.Lock()
	if res {
		f.ResSize += int64(len(b))
		if room := f.MaxBody - len(f.ResBody); room > 0 {
			f.ResBody = append(f.ResBody, b[:min(room, len(b))]...)
		} else {
			f.ResTrunc = true
		}
	} else {
		f.ReqSize += int64(len(b))
		if room := f.MaxBody - len(f.ReqBody); room > 0 {
			f.ReqBody = append(f.ReqBody, b[:min(room, len(b))]...)
		} else {
			f.ReqTrunc = true
		}
	}
	f.Unlock()
}

func (f *Flow) Fail(msg string) {
	f.Lock()
	if f.Err == "" {
		f.Err = msg
	}
	f.State = "error"
	f.Unlock()
}

type Summary struct {
	ID      int64    `json:"id"`
	Kind    string   `json:"k"`
	Method  string   `json:"m"`
	Scheme  string   `json:"sc"`
	Host    string   `json:"h"`
	Port    int      `json:"po"`
	Path    string   `json:"p"`
	Status  int      `json:"s"`
	State   string   `json:"st"`
	Type    string   `json:"t"`
	ReqType string   `json:"rt,omitempty"`
	ReqSize int64    `json:"rq"`
	ResSize int64    `json:"rs"`
	Dur     int64    `json:"d"`
	Start   int64    `json:"ts"`
	App     string   `json:"a,omitempty"`
	Tags    []string `json:"g,omitempty"`
	Err     string   `json:"e,omitempty"`
	Note    string   `json:"n,omitempty"`
	WS      int      `json:"ws,omitempty"`
}

func (f *Flow) Summary() Summary {
	f.Lock()
	defer f.Unlock()
	s := Summary{ID: f.ID, Kind: f.Kind, Method: f.Method, Scheme: f.Scheme, Host: f.Host, Port: f.Port, Path: f.Path,
		Status: f.Status, State: f.State, ReqSize: f.ReqSize, ResSize: f.ResSize, Start: f.Start.UnixMilli(),
		App: f.App, Tags: f.Tags, Err: f.Err, Note: f.Note, WS: f.WSCount, Dur: -1}
	if f.Kind == "tunnel" {
		s.ReqSize, s.ResSize = f.BytesUp.Load(), f.BytesDown.Load()
	}
	if !f.End.IsZero() {
		s.Dur = f.End.Sub(f.Start).Milliseconds()
	}
	s.Type = Classify(f)
	if f.ReqHeader != nil {
		s.ReqType = f.ReqHeader.Get("Content-Type")
	}
	return s
}

type Store struct {
	mu    sync.RWMutex
	flows map[int64]*Flow
	order []*Flow
	seq   atomic.Int64
	mem   int64
	cfg   *Config
	Hub   *Hub

	OnFinish func(*Flow)
}

func NewStore(cfg *Config) *Store {
	s := &Store{flows: map[int64]*Flow{}, cfg: cfg}
	s.Hub = newHub(s)
	return s
}

func (s *Store) NextID() int64 { return s.seq.Add(1) }

func (s *Store) Add(f *Flow) {
	s.mu.Lock()
	if f.ID == 0 {
		f.ID = s.NextID()
	}
	s.flows[f.ID] = f
	s.order = append(s.order, f)
	s.mu.Unlock()
	s.Hub.mark(f.ID)
	s.Trim()
}

func (s *Store) Touch(f *Flow) {
	if f != nil && f.ID != 0 {
		s.Hub.mark(f.ID)
	}
}

func (s *Store) Finished(f *Flow) {
	f.Lock()
	m := int64(len(f.ReqBody)+len(f.ResBody)) + 2048
	for _, w := range f.WS {
		m += int64(len(w.Data)) + 64
	}
	delta := m - f.mem
	f.mem = m
	f.Unlock()
	s.mu.Lock()
	if _, ok := s.flows[f.ID]; ok {
		s.mem += delta
	}
	s.mu.Unlock()
	s.Touch(f)
	s.Trim()
	if s.OnFinish != nil {
		s.OnFinish(f)
	}
}

func (s *Store) Get(id int64) *Flow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.flows[id]
}

func (s *Store) All() []*Flow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]*Flow(nil), s.order...)
}

func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.order)
}

func (s *Store) Remove(ids []int64) int {
	if len(ids) == 0 {
		return 0
	}
	drop := make(map[int64]bool, len(ids))
	for _, id := range ids {
		drop[id] = true
	}
	s.mu.Lock()
	var removed []int64

	n := 0
	for n < len(s.order) && drop[s.order[n].ID] {
		n++
	}
	if n == len(drop) {
		for _, f := range s.order[:n] {
			delete(s.flows, f.ID)
			s.mem -= f.mem
			removed = append(removed, f.ID)
		}
		s.order = append([]*Flow(nil), s.order[n:]...)
	} else {
		kept := make([]*Flow, 0, len(s.order))
		for _, f := range s.order {
			if drop[f.ID] {
				delete(s.flows, f.ID)
				s.mem -= f.mem
				removed = append(removed, f.ID)
			} else {
				kept = append(kept, f)
			}
		}
		s.order = kept
	}
	s.mu.Unlock()
	s.Hub.removed(removed)
	return len(removed)
}

func (s *Store) Clear() {
	s.mu.Lock()
	var kept []*Flow
	for _, f := range s.order {
		if f.State == "paused" {
			kept = append(kept, f)
		}
	}
	s.order = kept
	s.flows = map[int64]*Flow{}
	s.mem = 0
	for _, f := range kept {
		s.flows[f.ID] = f
	}
	s.mu.Unlock()
	s.Hub.clear()
}

func (s *Store) Trim() {
	cfg := s.cfg.Get()
	maxN, maxMem := cfg.MaxFlows, int64(cfg.MaxMemoryMB)<<20
	if maxN < 100 {
		maxN = 100
	}
	s.mu.RLock()
	over := len(s.order) > maxN || s.mem > maxMem
	s.mu.RUnlock()
	if !over {
		return
	}

	maxN, maxMem = maxN*9/10, maxMem*9/10
	s.mu.Lock()
	var drop []int64
	n, mem := len(s.order), s.mem
	for _, f := range s.order {
		if n <= maxN && mem <= maxMem {
			break
		}
		if f.End.IsZero() && f.Kind != "tls" {
			continue
		}
		drop = append(drop, f.ID)
		n--
		mem -= f.mem
	}
	s.mu.Unlock()
	if len(drop) > 0 {
		s.Remove(drop)
	}
}

func (s *Store) Hosts() map[string]int {
	out := map[string]int{}
	for _, f := range s.All() {
		out[f.Host]++
	}
	return out
}

type Hub struct {
	store   *Store
	mu      sync.Mutex
	dirty   map[int64]struct{}
	rm      []int64
	cleared bool
	state   bool
	clients map[chan []byte]struct{}
	StateFn func() any
}

func newHub(s *Store) *Hub {
	h := &Hub{store: s, dirty: map[int64]struct{}{}, clients: map[chan []byte]struct{}{}}
	go h.loop()
	return h
}

func (h *Hub) mark(id int64) {
	h.mu.Lock()
	h.dirty[id] = struct{}{}
	h.mu.Unlock()
}

func (h *Hub) removed(ids []int64) {
	if len(ids) == 0 {
		return
	}
	h.mu.Lock()
	h.rm = append(h.rm, ids...)
	h.mu.Unlock()
}

func (h *Hub) clear() {
	h.mu.Lock()
	h.cleared = true
	h.dirty = map[int64]struct{}{}
	h.rm = nil
	h.mu.Unlock()
}

func (h *Hub) StateChanged() {
	h.mu.Lock()
	h.state = true
	h.mu.Unlock()
}

func (h *Hub) Subscribe() chan []byte {
	ch := make(chan []byte, 256)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *Hub) Unsubscribe(ch chan []byte) {
	h.mu.Lock()
	if _, ok := h.clients[ch]; ok {
		delete(h.clients, ch)
		close(ch)
	}
	h.mu.Unlock()
}

type Batch struct {
	Up    []Summary `json:"up,omitempty"`
	Rm    []int64   `json:"rm,omitempty"`
	Clear bool      `json:"clear,omitempty"`
	State any       `json:"state,omitempty"`
}

func (h *Hub) loop() {
	for range time.Tick(120 * time.Millisecond) {
		h.mu.Lock()
		if len(h.dirty) == 0 && len(h.rm) == 0 && !h.cleared && !h.state {
			h.mu.Unlock()
			continue
		}
		dirty, rm, cleared, state := h.dirty, h.rm, h.cleared, h.state
		h.dirty, h.rm, h.cleared, h.state = map[int64]struct{}{}, nil, false, false
		h.mu.Unlock()

		b := Batch{Rm: rm, Clear: cleared}
		ids := make([]int64, 0, len(dirty))
		for id := range dirty {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for _, id := range ids {
			if f := h.store.Get(id); f != nil {
				b.Up = append(b.Up, f.Summary())
			}
		}
		if state && h.StateFn != nil {
			b.State = h.StateFn()
		}
		data, _ := json.Marshal(b)
		h.mu.Lock()
		for ch := range h.clients {
			select {
			case ch <- data:
			default:
				delete(h.clients, ch)
				close(ch)
			}
		}
		h.mu.Unlock()
	}
}

func AppendTag(tags []string, t string) []string {
	for _, x := range tags {
		if x == t {
			return tags
		}
	}
	return append(tags, t)
}

func HasTag(tags []string, t string) bool {
	for _, x := range tags {
		if strings.EqualFold(x, t) {
			return true
		}
	}
	return false
}

func HeaderRows(h http.Header) [][2]string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var rows [][2]string
	for _, k := range keys {
		for _, v := range h[k] {
			rows = append(rows, [2]string{k, v})
		}
	}
	return rows
}

package ui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"sift/internal/ai"
	"sift/internal/scan"
)

func (u *UI) aiRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/ai/config", u.aiConfig)
	m.HandleFunc("POST /api/ai/config", u.aiSaveConfig)
	m.HandleFunc("POST /api/ai/triage", u.aiTriage)
	m.HandleFunc("POST /api/ai/correlate", u.aiCorrelate)
	m.HandleFunc("POST /api/ai/recommend", u.aiRecommend)
	m.HandleFunc("POST /api/ai/verify/{id}", u.aiVerify)
	m.HandleFunc("POST /api/ai/chat", u.aiChat)
}

func (u *UI) aiConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"config":  u.app.AI.PublicConfig(),
		"presets": ai.Presets(),
		"tasks":   ai.Tasks,
		"enabled": u.app.AI.Enabled(),
	})
}

func (u *UI) aiSaveConfig(w http.ResponseWriter, r *http.Request) {
	var cfg ai.Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	u.app.AI.SetConfig(cfg)
	toast(w, "AI settings saved")
	writeJSON(w, map[string]any{"config": u.app.AI.PublicConfig(), "enabled": u.app.AI.Enabled()})
}

func (u *UI) aiGuard(w http.ResponseWriter) bool {
	if !u.app.AI.Enabled() {
		writeJSON(w, map[string]any{"error": "No AI provider is configured. Add one in AI settings."})
		return false
	}
	return true
}

func findingsJSON(list []*scan.Finding, max int) string {
	if len(list) > max {
		list = list[:max]
	}
	type lite struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Title      string `json:"title"`
		Severity   string `json:"severity"`
		Confidence string `json:"confidence"`
		URL        string `json:"url"`
		Param      string `json:"param,omitempty"`
		Where      string `json:"where,omitempty"`
		Payload    string `json:"payload,omitempty"`
		Detail     string `json:"detail"`
		Evidence   string `json:"evidence,omitempty"`
	}
	out := make([]lite, 0, len(list))
	for _, f := range list {
		l := lite{ID: f.ID, Type: f.Type, Title: f.Title, Severity: string(f.Severity),
			Confidence: string(f.Confidence), URL: f.URL, Param: f.Param, Where: f.Where,
			Payload: f.Payload, Detail: f.Detail}
		var ev []string
		for _, e := range f.Evidence {
			ev = append(ev, e.Label+": "+e.Snippet)
		}
		l.Evidence = strings.Join(ev, " | ")
		if len(l.Evidence) > 600 {
			l.Evidence = l.Evidence[:600]
		}
		out = append(out, l)
	}
	b, _ := json.Marshal(out)
	return string(b)
}

func (u *UI) trafficSummary() string {
	hosts := map[string]int{}
	methods := map[string]int{}
	var endpoints []string
	seen := map[string]bool{}
	for _, f := range u.app.Store.All() {
		if f.Kind != "http" {
			continue
		}
		hosts[f.Host]++
		methods[f.Method]++
		key := f.Method + " " + f.Host + strings.SplitN(f.Path, "?", 2)[0]
		if !seen[key] && len(endpoints) < 60 {
			seen[key] = true
			endpoints = append(endpoints, key)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d hosts, methods: %v\n", len(hosts), methods)
	hostList := make([]string, 0, len(hosts))
	for h, n := range hosts {
		hostList = append(hostList, fmt.Sprintf("%s (%d)", h, n))
	}
	sort.Strings(hostList)
	b.WriteString("hosts: " + strings.Join(hostList, ", ") + "\n")
	b.WriteString("endpoints:\n" + strings.Join(endpoints, "\n"))
	return b.String()
}

func (u *UI) aiTriage(w http.ResponseWriter, r *http.Request) {
	if !u.aiGuard(w) {
		return
	}
	list := u.app.Scanner.Store().All()
	if len(list) == 0 {
		writeJSON(w, map[string]any{"error": "There are no findings to triage yet."})
		return
	}
	res, err := u.app.AI.Triage(r.Context(), findingsJSON(list, 80))
	if err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	for _, it := range res.Items {
		note := it.Verdict
		if it.Priority != "" {
			note += " · " + it.Priority
		}
		if it.Rationale != "" {
			note += " — " + it.Rationale
		}
		u.app.Scanner.Store().Annotate(it.ID, note)
	}
	writeJSON(w, res)
}

func (u *UI) aiCorrelate(w http.ResponseWriter, r *http.Request) {
	if !u.aiGuard(w) {
		return
	}
	res, err := u.app.AI.Correlate(r.Context(), findingsJSON(u.app.Scanner.Store().All(), 80), u.trafficSummary())
	writeAIText(w, res, err)
}

func (u *UI) aiRecommend(w http.ResponseWriter, r *http.Request) {
	if !u.aiGuard(w) {
		return
	}
	ctx := "Traffic:\n" + u.trafficSummary() + "\n\nFindings:\n" + findingsJSON(u.app.Scanner.Store().All(), 60)
	res, err := u.app.AI.Recommend(r.Context(), ctx)
	writeAIText(w, res, err)
}

func (u *UI) aiVerify(w http.ResponseWriter, r *http.Request) {
	if !u.aiGuard(w) {
		return
	}
	f := u.app.Scanner.Store().Get(r.PathValue("id"))
	if f == nil {
		writeJSON(w, map[string]any{"error": "finding not found"})
		return
	}
	b, _ := json.Marshal(f)
	res, err := u.app.AI.Verify(r.Context(), string(b))
	writeAIText(w, res, err)
}

func (u *UI) aiChat(w http.ResponseWriter, r *http.Request) {
	if !u.aiGuard(w) {
		return
	}
	var in struct {
		History  []ai.Message `json:"history"`
		Question string       `json:"question"`
		Context  bool         `json:"context"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	ctx := ""
	if in.Context {
		ctx = "Traffic:\n" + u.trafficSummary() + "\n\nFindings:\n" + findingsJSON(u.app.Scanner.Store().All(), 40)
	}
	res, err := u.app.AI.Chat(r.Context(), in.History, in.Question, ctx)
	writeAIText(w, res, err)
}

func writeAIText(w http.ResponseWriter, res *ai.TextResult, err error) {
	if err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, res)
}

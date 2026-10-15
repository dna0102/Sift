package ai

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

const (
	TaskTriage    = "triage"
	TaskCorrelate = "correlate"
	TaskRecommend = "recommend"
	TaskVerify    = "verify"
	TaskChat      = "chat"
)

var Tasks = []struct{ ID, Name, Detail string }{
	{TaskTriage, "Triage", "Judge each finding: real, false positive, or needs verification, with a priority."},
	{TaskCorrelate, "Correlate", "Connect evidence across requests to spot chained or higher-impact issues."},
	{TaskRecommend, "Recommend tests", "Suggest the next tests and the most promising attack surface."},
	{TaskVerify, "Verify", "Reason about whether a specific finding is exploitable and how to prove it."},
	{TaskChat, "Chat", "General questions about the captured traffic and findings."},
}

type ProviderConfig struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Kind    string   `json:"kind"`
	BaseURL string   `json:"baseURL"`
	APIKey  string   `json:"apiKey"`
	Models  []string `json:"models"`
}

type Route struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

type TaskRoute struct {
	Provider  string  `json:"provider"`
	Model     string  `json:"model"`
	Fallbacks []Route `json:"fallbacks"`
}

type Config struct {
	Enabled   bool                 `json:"enabled"`
	Providers []ProviderConfig     `json:"providers"`
	Tasks     map[string]TaskRoute `json:"tasks"`
}

type Manager struct {
	mu   sync.RWMutex
	cfg  Config
	path string
}

func NewManager(home string) *Manager {
	m := &Manager{path: filepath.Join(home, "ai.json"), cfg: Config{Tasks: map[string]TaskRoute{}}}
	if data, err := os.ReadFile(m.path); err == nil {
		_ = json.Unmarshal(data, &m.cfg)
	}
	if m.cfg.Tasks == nil {
		m.cfg.Tasks = map[string]TaskRoute{}
	}
	return m
}

func (m *Manager) Enabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.Enabled && len(m.cfg.Providers) > 0
}

func (m *Manager) Config() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

func (m *Manager) PublicConfig() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c := m.cfg
	c.Providers = make([]ProviderConfig, len(m.cfg.Providers))
	for i, p := range m.cfg.Providers {
		pc := p
		if pc.APIKey != "" {
			pc.APIKey = "set"
		}
		c.Providers[i] = pc
	}
	return c
}

func (m *Manager) SetConfig(in Config) {
	m.mu.Lock()
	old := map[string]string{}
	for _, p := range m.cfg.Providers {
		old[p.ID] = p.APIKey
	}
	for i := range in.Providers {
		if in.Providers[i].APIKey == "" || in.Providers[i].APIKey == "set" {
			in.Providers[i].APIKey = old[in.Providers[i].ID]
		}
	}
	if in.Tasks == nil {
		in.Tasks = map[string]TaskRoute{}
	}
	m.cfg = in
	data, _ := json.MarshalIndent(m.cfg, "", "  ")
	m.mu.Unlock()
	tmp := m.path + ".tmp"
	if os.WriteFile(tmp, data, 0o600) == nil {
		_ = os.Rename(tmp, m.path)
	}
}

func buildProvider(p ProviderConfig) (Provider, error) {
	switch p.Kind {
	case "openai", "ollama", "vllm", "custom", "":
		base := p.BaseURL
		if base == "" {
			base = "https://api.openai.com/v1"
		}
		return openAIProvider{baseURL: base, key: p.APIKey}, nil
	case "anthropic":
		return anthropicProvider{baseURL: p.BaseURL, key: p.APIKey}, nil
	case "gemini":
		return geminiProvider{baseURL: p.BaseURL, key: p.APIKey}, nil
	}
	return nil, errors.New("unknown provider kind " + p.Kind)
}

func (m *Manager) resolveProvider(id string) (Provider, ProviderConfig, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, p := range m.cfg.Providers {
		if p.ID == id {
			prov, err := buildProvider(p)
			if err != nil {
				return nil, p, false
			}
			return prov, p, true
		}
	}
	return nil, ProviderConfig{}, false
}

func (m *Manager) routesFor(task string) []Route {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Route
	if tr, ok := m.cfg.Tasks[task]; ok && tr.Provider != "" {
		out = append(out, Route{tr.Provider, tr.Model})
		out = append(out, tr.Fallbacks...)
	}
	if len(out) == 0 && len(m.cfg.Providers) > 0 {
		p := m.cfg.Providers[0]
		model := ""
		if len(p.Models) > 0 {
			model = p.Models[0]
		}
		out = append(out, Route{p.ID, model})
	}
	return out
}

type RunResult struct {
	*ChatResponse
	Provider string `json:"provider"`
	Route    string `json:"route"`
}

func (m *Manager) Run(ctx context.Context, task string, req ChatRequest) (*RunResult, error) {
	routes := m.routesFor(task)
	if len(routes) == 0 {
		return nil, errors.New("no AI provider is configured")
	}
	var lastErr error
	for _, r := range routes {
		prov, pc, ok := m.resolveProvider(r.Provider)
		if !ok {
			lastErr = errors.New("provider " + r.Provider + " is not available")
			continue
		}
		req.Model = r.Model
		if req.Model == "" && len(pc.Models) > 0 {
			req.Model = pc.Models[0]
		}
		res, err := prov.Chat(ctx, req)
		if err != nil {
			lastErr = err
			continue
		}
		return &RunResult{ChatResponse: res, Provider: pc.Name, Route: r.Provider + "/" + req.Model}, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no usable AI route")
	}
	return nil, lastErr
}

type Preset struct {
	Kind    string   `json:"kind"`
	Name    string   `json:"name"`
	BaseURL string   `json:"baseURL"`
	Local   bool     `json:"local"`
	NeedKey bool     `json:"needKey"`
	Models  []string `json:"models"`
}

func Presets() []Preset {
	return []Preset{
		{"openai", "OpenAI", "https://api.openai.com/v1", false, true, []string{"gpt-4o", "gpt-4o-mini", "o4-mini"}},
		{"anthropic", "Anthropic Claude", "https://api.anthropic.com", false, true, []string{"claude-opus-4-8", "claude-sonnet-4-5", "claude-haiku-4-5"}},
		{"gemini", "Google Gemini", "https://generativelanguage.googleapis.com", false, true, []string{"gemini-2.5-pro", "gemini-2.5-flash"}},
		{"ollama", "Ollama (local)", "http://localhost:11434/v1", true, false, []string{"llama3.1", "qwen2.5", "mistral"}},
		{"vllm", "vLLM (local/self-hosted)", "http://localhost:8000/v1", true, false, nil},
		{"custom", "Custom OpenAI-compatible", "", false, false, nil},
	}
}


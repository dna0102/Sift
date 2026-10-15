package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func openAIStub(reply string, status int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != 0 {
			w.WriteHeader(status)
			w.Write([]byte(`{"error":"boom"}`))
			return
		}
		resp := map[string]any{
			"model":   "stub",
			"choices": []map[string]any{{"message": map[string]string{"role": "assistant", "content": reply}}},
			"usage":   map[string]int{"prompt_tokens": 3, "completion_tokens": 5},
		}
		json.NewEncoder(w).Encode(resp)
	}))
}

func newManager(t *testing.T) *Manager {
	return NewManager(t.TempDir())
}

func TestRunRoutesToProvider(t *testing.T) {
	srv := openAIStub("hello from model", 0)
	defer srv.Close()
	m := newManager(t)
	m.SetConfig(Config{Enabled: true,
		Providers: []ProviderConfig{{ID: "a", Name: "A", Kind: "openai", BaseURL: srv.URL, Models: []string{"stub"}}},
		Tasks:     map[string]TaskRoute{TaskChat: {Provider: "a", Model: "stub"}}})
	res, err := m.Run(context.Background(), TaskChat, ChatRequest{Messages: []Message{{Role: "user", Content: "hi"}}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Content != "hello from model" {
		t.Fatalf("unexpected content %q", res.Content)
	}
}

func TestRunFallsBack(t *testing.T) {
	bad := openAIStub("", 500)
	defer bad.Close()
	good := openAIStub("recovered", 0)
	defer good.Close()
	m := newManager(t)
	m.SetConfig(Config{Enabled: true,
		Providers: []ProviderConfig{
			{ID: "bad", Name: "bad", Kind: "openai", BaseURL: bad.URL, Models: []string{"x"}},
			{ID: "good", Name: "good", Kind: "openai", BaseURL: good.URL, Models: []string{"y"}},
		},
		Tasks: map[string]TaskRoute{TaskChat: {Provider: "bad", Model: "x", Fallbacks: []Route{{Provider: "good", Model: "y"}}}}})
	res, err := m.Run(context.Background(), TaskChat, ChatRequest{Messages: []Message{{Role: "user", Content: "hi"}}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Content != "recovered" {
		t.Fatalf("expected fallback to succeed, got %q", res.Content)
	}
}

func TestSetConfigPreservesKey(t *testing.T) {
	m := newManager(t)
	m.SetConfig(Config{Providers: []ProviderConfig{{ID: "a", Name: "A", Kind: "openai", APIKey: "secret"}}})
	m.SetConfig(Config{Providers: []ProviderConfig{{ID: "a", Name: "A2", Kind: "openai", APIKey: ""}}})
	if got := m.Config().Providers[0].APIKey; got != "secret" {
		t.Fatalf("expected key preserved, got %q", got)
	}
	if pub := m.PublicConfig().Providers[0].APIKey; pub != "set" {
		t.Fatalf("public config should redact key, got %q", pub)
	}
}

func TestTriageParsesJSON(t *testing.T) {
	srv := openAIStub(`{"items":[{"id":"abc","verdict":"confirmed","priority":"high","rationale":"reflected unescaped","nextSteps":["build PoC"]}]}`, 0)
	defer srv.Close()
	m := newManager(t)
	m.SetConfig(Config{Enabled: true,
		Providers: []ProviderConfig{{ID: "a", Name: "A", Kind: "openai", BaseURL: srv.URL, Models: []string{"stub"}}},
		Tasks:     map[string]TaskRoute{TaskTriage: {Provider: "a", Model: "stub"}}})
	res, err := m.Triage(context.Background(), `[{"id":"abc"}]`)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 1 || res.Items[0].Verdict != "confirmed" {
		t.Fatalf("unexpected triage %+v", res.Items)
	}
}

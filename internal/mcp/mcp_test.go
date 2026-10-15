package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sift/internal/core"
	"sift/internal/scan"
)

func testServer(t *testing.T) (*Server, *scan.Engine) {
	cfg := core.LoadConfig(t.TempDir())
	eng := scan.NewEngine(core.NewStore(cfg), cfg)
	s := NewServer(t.TempDir(), core.NewStore(cfg), eng, "test")
	return s, eng
}

func call(t *testing.T, s *Server, token, method string, params any) rpcResponse {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.Handler()(rec, req)
	if token == "" {
		return rpcResponse{}
	}
	var resp rpcResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	return resp
}

func TestMCPUnauthorized(t *testing.T) {
	s, _ := testServer(t)
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.Handler()(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}
}

func TestMCPInitializeAndTools(t *testing.T) {
	s, _ := testServer(t)
	resp := call(t, s, s.Token(), "initialize", nil)
	m, _ := resp.Result.(map[string]any)
	if m["protocolVersion"] != protocolVersion {
		t.Fatalf("bad initialize result: %v", resp.Result)
	}
	tl := call(t, s, s.Token(), "tools/list", nil)
	tm, _ := tl.Result.(map[string]any)
	tools, _ := tm["tools"].([]any)
	if len(tools) < 5 {
		t.Fatalf("expected tools listed, got %d", len(tools))
	}
}

func TestMCPListFindings(t *testing.T) {
	s, eng := testServer(t)
	eng.Store().Add(&scan.Finding{Type: "xss-reflected", Title: "XSS", Severity: scan.SevHigh,
		Confidence: scan.ConfFirm, URL: "https://t.test/", Host: "t.test"})
	resp := call(t, s, s.Token(), "tools/call", map[string]any{"name": "list_findings", "arguments": map[string]any{}})
	text := toolText(t, resp)
	if !strings.Contains(text, "xss-reflected") {
		t.Fatalf("expected finding in tool result, got %s", text)
	}
}

func TestMCPStartScanRequiresScope(t *testing.T) {
	s, _ := testServer(t)
	resp := call(t, s, s.Token(), "tools/call", map[string]any{"name": "start_active_scan", "arguments": map[string]any{"include": []any{}}})
	m, _ := resp.Result.(map[string]any)
	if m["isError"] != true {
		t.Fatalf("expected error starting scan with no scope, got %v", resp.Result)
	}
}

func toolText(t *testing.T, resp rpcResponse) string {
	t.Helper()
	m, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("no result: %+v", resp)
	}
	content, _ := m["content"].([]any)
	if len(content) == 0 {
		t.Fatal("no content")
	}
	first, _ := content[0].(map[string]any)
	s, _ := first["text"].(string)
	return s
}

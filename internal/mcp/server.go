package mcp

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"sift/internal/core"
	"sift/internal/scan"
)

const protocolVersion = "2024-11-05"

type Server struct {
	flows   *core.Store
	engine  *scan.Engine
	token   string
	version string
}

func NewServer(home string, flows *core.Store, engine *scan.Engine, version string) *Server {
	s := &Server{flows: flows, engine: engine, version: version}
	path := filepath.Join(home, "mcp.token")
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 16 {
		s.token = strings.TrimSpace(string(data))
	} else {
		b := make([]byte, 24)
		rand.Read(b)
		s.token = hex.EncodeToString(b)
		_ = os.WriteFile(path, []byte(s.token), 0o600)
	}
	return s
}

func (s *Server) Token() string { return s.token }

func (s *Server) authorized(r *http.Request) bool {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		if strings.TrimSpace(strings.TrimPrefix(h, "Bearer ")) == s.token {
			return true
		}
	}
	return r.URL.Query().Get("token") == s.token
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func (s *Server) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !s.authorized(r) {
			http.Error(w, "unauthorized: pass the Sift MCP token", http.StatusUnauthorized)
			return
		}
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeRPC(w, rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}})
			return
		}
		if len(req.ID) == 0 {
			s.dispatch(req)
			w.WriteHeader(http.StatusAccepted)
			return
		}
		resp := s.dispatch(req)
		resp.JSONRPC, resp.ID = "2.0", req.ID
		writeRPC(w, resp)
	}
}

func writeRPC(w http.ResponseWriter, resp rpcResponse) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) dispatch(req rpcRequest) rpcResponse {
	switch req.Method {
	case "initialize":
		return rpcResponse{Result: map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "sift", "version": s.version},
		}}
	case "ping":
		return rpcResponse{Result: map[string]any{}}
	case "tools/list":
		return rpcResponse{Result: map[string]any{"tools": toolList()}}
	case "tools/call":
		return s.callTool(req.Params)
	case "notifications/initialized":
		return rpcResponse{Result: map[string]any{}}
	}
	return rpcResponse{Error: &rpcError{Code: -32601, Message: "method not found: " + req.Method}}
}

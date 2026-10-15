package mcp

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"sift/internal/core"
	"sift/internal/scan"
)

type toolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func obj(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

func str(desc string) map[string]any    { return map[string]any{"type": "string", "description": desc} }
func num(desc string) map[string]any    { return map[string]any{"type": "integer", "description": desc} }
func boolp(desc string) map[string]any  { return map[string]any{"type": "boolean", "description": desc} }
func strArr(desc string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": desc}
}

func toolList() []toolDef {
	return []toolDef{
		{"list_findings", "List vulnerability findings, optionally filtered by minimum severity.",
			obj(map[string]any{"severity": str("minimum severity: critical, high, medium, low, info"), "limit": num("max findings to return")})},
		{"get_finding", "Get one finding in full, including evidence, payload and remediation.",
			obj(map[string]any{"id": str("finding id")}, "id")},
		{"scan_stats", "Summary counts of findings by severity and host, plus an overall risk score.", obj(nil)},
		{"scan_jobs", "List scan jobs and their progress.", obj(nil)},
		{"list_flows", "List captured HTTP requests, optionally filtered.",
			obj(map[string]any{"host": str("host substring"), "method": str("HTTP method"), "status": num("status code"), "limit": num("max rows, default 50")})},
		{"get_flow", "Get one captured request and its response as text.",
			obj(map[string]any{"id": num("flow id")}, "id")},
		{"passive_scan", "Run passive analysis over all captured traffic. Sends nothing.", obj(nil)},
		{"start_active_scan", "Start an active scan against in-scope hosts. Only hosts in 'include' are tested.",
			obj(map[string]any{
				"include":   strArr("in-scope host patterns, e.g. example.com or *.example.com"),
				"exclude":   strArr("host patterns to skip"),
				"checks":    strArr("check ids to run; omit for all"),
				"intensity": str("light, normal, thorough or insane"),
				"discover":  boolp("also discover hidden paths and parameters"),
			}, "include")},
		{"stop_scan", "Stop a running scan, or all scans if no job id is given.",
			obj(map[string]any{"job": str("job id; omit to stop all")})},
	}
}

func (s *Server) callTool(params json.RawMessage) rpcResponse {
	var p struct {
		Name string          `json:"name"`
		Args json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return errResult("bad tool call: " + err.Error())
	}
	args := map[string]any{}
	if len(p.Args) > 0 {
		_ = json.Unmarshal(p.Args, &args)
	}
	switch p.Name {
	case "list_findings":
		return s.listFindings(args)
	case "get_finding":
		return s.getFinding(args)
	case "scan_stats":
		return textResult(s.engine.Store().Stats())
	case "scan_jobs":
		return textResult(s.engine.Store().Jobs())
	case "list_flows":
		return s.listFlows(args)
	case "get_flow":
		return s.getFlow(args)
	case "passive_scan":
		return textResult(s.engine.PassiveSweep())
	case "start_active_scan":
		return s.startActive(args)
	case "stop_scan":
		if job, _ := args["job"].(string); job != "" {
			s.engine.Stop(job)
		} else {
			s.engine.StopAll()
		}
		return textResult(map[string]string{"status": "stopping"})
	}
	return errResult("unknown tool: " + p.Name)
}

func (s *Server) listFindings(args map[string]any) rpcResponse {
	minSev, _ := args["severity"].(string)
	limit := intArg(args, "limit", 100)
	rank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	maxRank := 4
	if minSev != "" {
		if r, ok := rank[strings.ToLower(minSev)]; ok {
			maxRank = r
		}
	}
	var out []*scan.Finding
	for _, f := range s.engine.Store().All() {
		if rank[string(f.Severity)] > maxRank {
			continue
		}
		out = append(out, f)
		if len(out) >= limit {
			break
		}
	}
	return textResult(out)
}

func (s *Server) getFinding(args map[string]any) rpcResponse {
	id, _ := args["id"].(string)
	f := s.engine.Store().Get(id)
	if f == nil {
		return errResult("finding not found: " + id)
	}
	return textResult(f)
}

type flowRow struct {
	ID     int64  `json:"id"`
	Method string `json:"method"`
	URL    string `json:"url"`
	Status int    `json:"status"`
	Type   string `json:"type"`
	Size   int64  `json:"size"`
}

func (s *Server) listFlows(args map[string]any) rpcResponse {
	host, _ := args["host"].(string)
	method, _ := args["method"].(string)
	status := intArg(args, "status", 0)
	limit := intArg(args, "limit", 50)
	var rows []flowRow
	all := s.flows.All()
	for i := len(all) - 1; i >= 0 && len(rows) < limit; i-- {
		f := all[i]
		sm := f.Summary()
		if sm.Kind != "http" {
			continue
		}
		if host != "" && !strings.Contains(sm.Host, host) {
			continue
		}
		if method != "" && !strings.EqualFold(sm.Method, method) {
			continue
		}
		if status != 0 && sm.Status != status {
			continue
		}
		rows = append(rows, flowRow{ID: sm.ID, Method: sm.Method, URL: f.URL(), Status: sm.Status, Type: sm.Type, Size: sm.ResSize})
	}
	return textResult(rows)
}

func (s *Server) getFlow(args map[string]any) rpcResponse {
	id := int64(intArg(args, "id", 0))
	f := s.flows.Get(id)
	if f == nil {
		return errResult("flow not found")
	}
	return textResult(map[string]string{"request": renderSide(f, false), "response": renderSide(f, true)})
}

func renderSide(f *core.Flow, res bool) string {
	f.Lock()
	defer f.Unlock()
	var b strings.Builder
	if !res {
		fmt.Fprintf(&b, "%s %s %s\n", f.Method, f.Path, f.Proto)
		for _, row := range core.HeaderRows(f.ReqHeader) {
			fmt.Fprintf(&b, "%s: %s\n", row[0], row[1])
		}
		b.WriteString("\n")
		if !core.IsBinary(f.ReqBody) {
			b.WriteString(clip(string(f.ReqBody), 4000))
		} else {
			fmt.Fprintf(&b, "[%d bytes binary]", len(f.ReqBody))
		}
	} else {
		fmt.Fprintf(&b, "%s %d %s\n", f.ResProto, f.Status, f.StatusText)
		for _, row := range core.HeaderRows(f.ResHeader) {
			fmt.Fprintf(&b, "%s: %s\n", row[0], row[1])
		}
		b.WriteString("\n")
		body := f.ResBody
		if !core.IsBinary(body) {
			b.WriteString(clip(string(body), 8000))
		} else {
			fmt.Fprintf(&b, "[%d bytes binary]", len(body))
		}
	}
	return b.String()
}

func (s *Server) startActive(args map[string]any) rpcResponse {
	opts := scan.Options{Active: true,
		Scope:     scan.Scope{Include: strSlice(args["include"]), Exclude: strSlice(args["exclude"])},
		Checks:    strSlice(args["checks"]),
		Intensity: scan.Intensity(strArg(args, "intensity")),
		Discover:  boolArg(args, "discover"),
	}
	job, err := s.engine.Start(opts)
	if err != nil {
		return errResult(err.Error())
	}
	return textResult(job)
}

func textResult(v any) rpcResponse {
	data, _ := json.MarshalIndent(v, "", "  ")
	return rpcResponse{Result: map[string]any{"content": []map[string]any{{"type": "text", "text": string(data)}}}}
}

func errResult(msg string) rpcResponse {
	return rpcResponse{Result: map[string]any{"content": []map[string]any{{"type": "text", "text": msg}}, "isError": true}}
}

func intArg(args map[string]any, key string, def int) int {
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case string:
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func strArg(args map[string]any, key string) string {
	s, _ := args[key].(string)
	return s
}

func boolArg(args map[string]any, key string) bool {
	b, _ := args[key].(bool)
	return b
}

func strSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, x := range arr {
		if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

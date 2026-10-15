package core

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type Rule struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	Regex   bool   `json:"regex"`
	Method  string `json:"method"`

	OnRequest  bool `json:"on_request"`
	OnResponse bool `json:"on_response"`

	Status  int    `json:"status"`
	Headers string `json:"headers"`
	Body    string `json:"body"`
	File    string `json:"file"`

	To           string `json:"to"`
	PreserveHost bool   `json:"preserve_host"`

	Action string `json:"action"`

	Target    string `json:"target"`
	Op        string `json:"op"`
	Key       string `json:"key"`
	Value     string `json:"value"`
	Find      string `json:"find"`
	Replace   string `json:"replace"`
	FindRegex bool   `json:"find_regex"`
}

var RuleTypes = []struct{ Key, Label, Help string }{
	{"breakpoint", "Breakpoints", "Pause matching requests or responses so you can edit or abort them."},
	{"map_local", "Map Local", "Answer matching requests with a local file or a custom body."},
	{"map_remote", "Map Remote", "Send matching requests to another server. Path and query are kept unless the target has a path."},
	{"block", "Block List", "Refuse matching requests with 403, or drop the connection."},
	{"allow", "Allow List", "When any allow rule is on, only matching traffic is recorded."},
	{"rewrite", "Rewrite", "Set or remove headers, replace text in bodies, or change the status code."},
}

func ruleLabel(t string) string {
	for _, r := range RuleTypes {
		if r.Key == t {
			return r.Label
		}
	}
	return t
}

func NewRule(t string) Rule {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	return Rule{ID: hex.EncodeToString(b), Type: t, Enabled: true, Pattern: "*", Method: "ANY",
		OnRequest: true, OnResponse: true, Status: 200, Action: "forbid", Target: "response", Op: "set_header"}
}

type matcher func(url, host string, port int) bool

var (
	matchMu    sync.Mutex
	matchCache = map[string]matcher{}
)

func wildcard(s string) *regexp.Regexp {
	parts := strings.Split(s, "*")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	return regexp.MustCompile("(?i)^" + strings.Join(parts, ".*") + "$")
}

func compilePattern(pattern string, isRegex bool) matcher {
	key := strconv.FormatBool(isRegex) + pattern
	matchMu.Lock()
	defer matchMu.Unlock()
	if m, ok := matchCache[key]; ok {
		return m
	}
	m := buildMatcher(strings.TrimSpace(pattern), isRegex)
	if len(matchCache) > 4096 {
		clear(matchCache)
	}
	matchCache[key] = m
	return m
}

func buildMatcher(p string, isRegex bool) matcher {
	if isRegex {
		rx, err := regexp.Compile("(?i)" + p)
		if err != nil {
			return func(string, string, int) bool { return false }
		}
		return func(url, _ string, _ int) bool { return rx.MatchString(url) }
	}
	if p == "" || p == "*" {
		return func(string, string, int) bool { return true }
	}
	if !strings.Contains(p, "/") {
		rx := wildcard(p)
		var root *regexp.Regexp
		if strings.HasPrefix(p, "*.") {
			root = wildcard(p[2:])
		}
		return func(_, host string, port int) bool {
			hp := host + ":" + strconv.Itoa(port)
			return rx.MatchString(host) || rx.MatchString(hp) || (root != nil && (root.MatchString(host) || root.MatchString(hp)))
		}
	}
	if !regexp.MustCompile(`(?i)^[a-z*]+://`).MatchString(p) {
		p = "*://" + p
	}
	rx := wildcard(p)
	return func(url, _ string, _ int) bool {
		if rx.MatchString(url) {
			return true
		}
		if i := strings.IndexByte(url, '?'); i >= 0 {
			return rx.MatchString(url[:i])
		}
		return false
	}
}

func HostMatches(patterns []string, host string, port int) bool {
	url := "https://" + host + "/"
	for _, p := range patterns {
		if strings.TrimSpace(p) != "" && compilePattern(p, false)(url, host, port) {
			return true
		}
	}
	return false
}

func (r *Rule) matches(method, url, host string, port int) bool {
	m := strings.ToUpper(r.Method)
	if m != "" && m != "ANY" && m != strings.ToUpper(method) {
		return false
	}
	p := r.Pattern
	if p == "" {
		p = "*"
	}
	return compilePattern(p, r.Regex)(url, host, port)
}

type Matched struct {
	Block, MapLocal, MapRemote, BpRequest, BpResponse *Rule
	Rewrites                                          []*Rule
	AllowActive, Allowed                              bool
}

func (m *Matched) NeedsFullResponse() bool {
	if m.BpResponse != nil {
		return true
	}
	for _, r := range m.Rewrites {
		if r.Target == "response" && r.Op == "replace_body" {
			return true
		}
	}
	return false
}

func (m *Matched) NeedsFullRequest() bool {
	if m.BpRequest != nil {
		return true
	}
	for _, r := range m.Rewrites {
		if r.Target == "request" && r.Op == "replace_body" {
			return true
		}
	}
	return false
}

func MatchRules(rules []Rule, method, url, host string, port int) *Matched {
	m := &Matched{}
	for i := range rules {
		r := &rules[i]
		if !r.Enabled {
			continue
		}
		if r.Type == "allow" {
			m.AllowActive = true
			if !m.Allowed && r.matches(method, url, host, port) {
				m.Allowed = true
			}
			continue
		}
		if !r.matches(method, url, host, port) {
			continue
		}
		switch r.Type {
		case "block":
			if m.Block == nil {
				m.Block = r
			}
		case "map_local":
			if m.MapLocal == nil {
				m.MapLocal = r
			}
		case "map_remote":
			if m.MapRemote == nil {
				m.MapRemote = r
			}
		case "breakpoint":
			if r.OnRequest && m.BpRequest == nil {
				m.BpRequest = r
			}
			if r.OnResponse && m.BpResponse == nil {
				m.BpResponse = r
			}
		case "rewrite":
			m.Rewrites = append(m.Rewrites, r)
		}
	}
	return m
}

func RuleSummary(r Rule) string {
	switch r.Type {
	case "breakpoint":
		var p []string
		if r.OnRequest {
			p = append(p, "request")
		}
		if r.OnResponse {
			p = append(p, "response")
		}
		if len(p) == 0 {
			return "no phase selected"
		}
		return "pause " + strings.Join(p, " + ")
	case "map_local":
		if r.File != "" {
			return strconv.Itoa(r.Status) + " from " + r.File
		}
		return strconv.Itoa(r.Status) + " custom body"
	case "map_remote":
		return "→ " + r.To
	case "block":
		if r.Action == "drop" {
			return "drop connection"
		}
		return "403 Forbidden"
	case "allow":
		return "record"
	case "rewrite":
		switch r.Op {
		case "set_header":
			return r.Target + ": set " + r.Key
		case "remove_header":
			return r.Target + ": remove " + r.Key
		case "replace_body":
			return r.Target + " body: " + r.Find + " → " + r.Replace
		case "set_status":
			return "status → " + r.Value
		}
	}
	return ""
}

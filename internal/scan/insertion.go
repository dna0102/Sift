package scan

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"sift/internal/core"
)

type target struct {
	method   string
	scheme   string
	host     string
	port     int
	path     string
	rawQuery string
	header   http.Header
	body     []byte
	ctype    string
	route    string
	profile  string
}

func (t *target) url() string {
	u := t.scheme + "://" + core.HostPort(t.host, t.port, t.scheme) + t.path
	if t.rawQuery != "" {
		u += "?" + t.rawQuery
	}
	return u
}

type Insertion struct {
	Name  string
	Where string
	Value string
	apply func(t *target, payload string, encode bool) *Request
}

func targetFromFlow(f *core.Flow) *target {
	f.Lock()
	defer f.Unlock()
	if f.Kind != "http" {
		return nil
	}
	path, rawQuery := f.Path, ""
	if i := strings.IndexByte(path, '?'); i >= 0 {
		rawQuery = path[i+1:]
		path = path[:i]
	}
	t := &target{method: f.Method, scheme: f.Scheme, host: f.Host, port: f.Port, path: path, rawQuery: rawQuery}
	if f.ReqHeader != nil {
		t.header = f.ReqHeader.Clone()
		t.ctype = strings.ToLower(f.ReqHeader.Get("Content-Type"))
	} else {
		t.header = http.Header{}
	}
	t.body = append([]byte(nil), f.ReqBody...)
	return t
}

func (t *target) request(tag string) *Request {
	return &Request{Method: t.method, URL: t.url(), Header: t.header.Clone(), Body: t.body,
		Route: t.route, Profile: t.profile, Tag: tag}
}

func pairs(raw string) [][2]string {
	var out [][2]string
	if raw == "" {
		return out
	}
	for _, p := range strings.Split(raw, "&") {
		k, v, _ := strings.Cut(p, "=")
		out = append(out, [2]string{k, v})
	}
	return out
}

func joinPairs(ps [][2]string) string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		if p[1] == "" && !strings.Contains(p[0], "=") {
			parts[i] = p[0]
		} else {
			parts[i] = p[0] + "=" + p[1]
		}
	}
	return strings.Join(parts, "&")
}

func enc(payload string, encode bool) string {
	if encode {
		return url.QueryEscape(payload)
	}
	return payload
}

func insertionPoints(t *target) []Insertion {
	var pts []Insertion

	for i, p := range pairs(t.rawQuery) {
		idx, name := i, decode(p[0])
		base := pairs(t.rawQuery)
		raw := base[idx][1]
		pts = append(pts, Insertion{Name: name, Where: "query", Value: decode(raw),
			apply: func(t *target, payload string, encode bool) *Request {
				ps := pairs(t.rawQuery)
				ps[idx][1] = enc(payload, encode)
				c := *t
				c.rawQuery = joinPairs(ps)
				return c.request("scan")
			}})
	}

	if strings.Contains(t.ctype, "x-www-form-urlencoded") {
		for i, p := range pairs(string(t.body)) {
			idx, name := i, decode(p[0])
			pts = append(pts, Insertion{Name: name, Where: "body", Value: decode(p[1]),
				apply: func(t *target, payload string, encode bool) *Request {
					ps := pairs(string(t.body))
					ps[idx][1] = enc(payload, encode)
					c := *t
					c.body = []byte(joinPairs(ps))
					return c.request("scan")
				}})
		}
	} else if strings.Contains(t.ctype, "json") && len(t.body) > 0 {
		for _, path := range jsonLeaves(t.body) {
			p := path
			pts = append(pts, Insertion{Name: p, Where: "json", Value: jsonGet(t.body, p),
				apply: func(t *target, payload string, encode bool) *Request {
					c := *t
					c.body = jsonSet(t.body, p, payload)
					return c.request("scan")
				}})
		}
	}

	if ck := t.header.Get("Cookie"); ck != "" {
		for i, part := range strings.Split(ck, ";") {
			name, val, _ := strings.Cut(strings.TrimSpace(part), "=")
			idx := i
			pts = append(pts, Insertion{Name: name, Where: "cookie", Value: val,
				apply: func(t *target, payload string, encode bool) *Request {
					parts := strings.Split(t.header.Get("Cookie"), ";")
					n, _, _ := strings.Cut(strings.TrimSpace(parts[idx]), "=")
					parts[idx] = n + "=" + enc(payload, encode)
					c := *t
					c.header = t.header.Clone()
					c.header.Set("Cookie", strings.Join(parts, ";"))
					return c.request("scan")
				}})
		}
	}

	return pts
}

func headerPoints(t *target) []Insertion {
	var pts []Insertion
	for _, name := range []string{"User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host", "True-Client-IP"} {
		h := name
		pts = append(pts, Insertion{Name: h, Where: "header", Value: t.header.Get(h),
			apply: func(t *target, payload string, encode bool) *Request {
				c := *t
				c.header = t.header.Clone()
				c.header.Set(h, payload)
				return c.request("scan")
			}})
	}
	return pts
}

func decode(s string) string {
	if d, err := url.QueryUnescape(s); err == nil {
		return d
	}
	return s
}

func jsonLeaves(body []byte) []string {
	var v any
	if json.Unmarshal(body, &v) != nil {
		return nil
	}
	var out []string
	var walk func(prefix string, node any)
	walk = func(prefix string, node any) {
		switch n := node.(type) {
		case map[string]any:
			for k, val := range n {
				p := k
				if prefix != "" {
					p = prefix + "." + k
				}
				walk(p, val)
			}
		case []any:
			for i, val := range n {
				walk(fmt.Sprintf("%s.%d", prefix, i), val)
			}
		case string, float64, bool:
			if prefix != "" {
				out = append(out, prefix)
			}
		}
	}
	walk("", v)
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}

func jsonGet(body []byte, path string) string {
	var v any
	if json.Unmarshal(body, &v) != nil {
		return ""
	}
	cur := v
	for _, step := range strings.Split(path, ".") {
		switch n := cur.(type) {
		case map[string]any:
			cur = n[step]
		case []any:
			var idx int
			fmt.Sscanf(step, "%d", &idx)
			if idx < len(n) {
				cur = n[idx]
			}
		}
	}
	if s, ok := cur.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", cur)
}

func jsonSet(body []byte, path, val string) []byte {
	var v any
	if json.Unmarshal(body, &v) != nil {
		return body
	}
	steps := strings.Split(path, ".")
	setStep(v, steps, val)
	out, err := json.Marshal(v)
	if err != nil {
		return body
	}
	return out
}

func setStep(node any, steps []string, val string) {
	if len(steps) == 0 {
		return
	}
	switch n := node.(type) {
	case map[string]any:
		if len(steps) == 1 {
			n[steps[0]] = val
			return
		}
		setStep(n[steps[0]], steps[1:], val)
	case []any:
		var idx int
		fmt.Sscanf(steps[0], "%d", &idx)
		if idx >= len(n) {
			return
		}
		if len(steps) == 1 {
			n[idx] = val
			return
		}
		setStep(n[idx], steps[1:], val)
	}
}

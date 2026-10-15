package scan

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"sift/internal/core"
)

func httpFlow(id int64, method, scheme, host string, port, status int, reqH, resH http.Header, reqBody, resBody []byte) *core.Flow {
	f := &core.Flow{ID: id, Kind: "http", Start: time.Now(), End: time.Now(), State: "done",
		Method: method, Scheme: scheme, Host: host, Port: port, Path: "/",
		Status: status, ReqHeader: reqH, ResHeader: resH, ReqBody: reqBody, ResBody: resBody, Decoded: true}
	return f
}

func newTestEngine() *Engine {
	cfg := core.LoadConfig(".")
	return NewEngine(core.NewStore(cfg), cfg)
}

func findType(fs []*Finding, typ string) *Finding {
	for _, f := range fs {
		if f.Type == typ {
			return f
		}
	}
	return nil
}

func TestPassiveHeadersAndCookies(t *testing.T) {
	e := newTestEngine()
	resH := http.Header{}
	resH.Set("Content-Type", "text/html; charset=utf-8")
	resH.Set("Set-Cookie", "sessionid=abc123; Path=/")
	f := httpFlow(1, "GET", "https", "example.com", 443, 200, http.Header{}, resH, nil, []byte("<html></html>"))
	e.Passive(f)

	fs := e.store.All()
	if findType(fs, "hdr-hsts") == nil {
		t.Error("expected missing HSTS finding")
	}
	if findType(fs, "hdr-csp") == nil {
		t.Error("expected missing CSP finding")
	}
	ck := findType(fs, "cookie-flags")
	if ck == nil {
		t.Fatal("expected cookie-flags finding")
	}
	if ck.Severity != SevMedium {
		t.Errorf("session cookie without Secure should be medium, got %s", ck.Severity)
	}
}

func TestPassiveCORSReflect(t *testing.T) {
	e := newTestEngine()
	reqH := http.Header{}
	reqH.Set("Origin", "https://evil.test")
	resH := http.Header{}
	resH.Set("Content-Type", "application/json")
	resH.Set("Access-Control-Allow-Origin", "https://evil.test")
	resH.Set("Access-Control-Allow-Credentials", "true")
	f := httpFlow(2, "GET", "https", "api.example.com", 443, 200, reqH, resH, nil, []byte("{}"))
	e.Passive(f)
	c := findType(e.store.All(), "cors-reflect")
	if c == nil || c.Severity != SevHigh {
		t.Fatalf("expected high CORS reflect finding, got %+v", c)
	}
}

func TestPassiveErrorDisclosure(t *testing.T) {
	e := newTestEngine()
	resH := http.Header{}
	resH.Set("Content-Type", "text/html")
	body := []byte("Warning: mysql_fetch_array(): supplied argument. You have an error in your SQL syntax; check the MySQL server")
	f := httpFlow(3, "GET", "https", "shop.example.com", 443, 500, http.Header{}, resH, nil, body)
	e.Passive(f)
	if findType(e.store.All(), "infoleak-error") == nil {
		t.Error("expected SQL error disclosure finding")
	}
}

func TestStoreDedupMerges(t *testing.T) {
	s := NewStore()
	mk := func() *Finding {
		return &Finding{Type: "hdr-csp", Title: "x", Severity: SevLow, Confidence: ConfFirm,
			URL: "https://a.test/", Host: "a.test", Flows: []int64{1}}
	}
	if !s.Add(mk()) {
		t.Fatal("first add should be new")
	}
	f2 := mk()
	f2.Flows = []int64{2}
	if s.Add(f2) {
		t.Fatal("second add of same key should merge, not be new")
	}
	all := s.All()
	if len(all) != 1 {
		t.Fatalf("expected 1 finding after merge, got %d", len(all))
	}
	if all[0].Count != 2 {
		t.Errorf("expected count 2, got %d", all[0].Count)
	}
	if len(all[0].Flows) != 2 {
		t.Errorf("expected 2 merged flows, got %d", len(all[0].Flows))
	}
}

type fakeReq struct {
	flows   *core.Store
	handler func(*Request) *Response
}

func (f fakeReq) Do(_ context.Context, r *Request) (*Response, error) {
	res := f.handler(r)
	if res == nil {
		res = &Response{Status: 200, Header: http.Header{}, Body: []byte("ok")}
	}
	if res.Header == nil {
		res.Header = http.Header{}
	}
	return res, nil
}

func seedFlow(s *core.Store, method, scheme, host string, port int, pathWithQuery string) {
	f := &core.Flow{Kind: "http", Start: time.Now(), End: time.Now(), State: "done", Method: method,
		Scheme: scheme, Host: host, Port: port, Path: pathWithQuery, Status: 200,
		ReqHeader: http.Header{}, ResHeader: http.Header{}, Decoded: true}
	s.Add(f)
}

func queryVal(rawurl, key string) string {
	u, err := url.Parse(rawurl)
	if err != nil {
		return ""
	}
	return u.Query().Get(key)
}

func waitJob(t *testing.T, e *Engine, id string) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if j := e.store.Job(id); j != nil && (j.State == "done" || j.State == "stopped" || j.State == "error") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("job %s did not finish", id)
}

func TestActiveReflectedXSS(t *testing.T) {
	cfg := core.LoadConfig(".")
	flows := core.NewStore(cfg)
	e := NewEngine(flows, cfg)
	e.SetRequester(fakeReq{flows: flows, handler: func(r *Request) *Response {
		q := queryVal(r.URL, "q")
		h := http.Header{}
		h.Set("Content-Type", "text/html")
		return &Response{Status: 200, Header: h, Body: []byte("<html><body>results for " + q + "</body></html>"), FlowID: 1}
	}})
	seedFlow(flows, "GET", "https", "t.test", 443, "/search?q=hello")

	job, err := e.Start(Options{Scope: Scope{Include: []string{"t.test"}}, Checks: []string{"reflection"},
		Intensity: IntensityLight, Concurrency: 1, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, e, job.ID)
	if findType(e.store.All(), "xss-reflected") == nil {
		t.Fatalf("expected reflected XSS finding, got %v", titles(e.store.All()))
	}
}

func TestActiveSQLiError(t *testing.T) {
	cfg := core.LoadConfig(".")
	flows := core.NewStore(cfg)
	e := NewEngine(flows, cfg)
	e.SetRequester(fakeReq{flows: flows, handler: func(r *Request) *Response {
		id := queryVal(r.URL, "id")
		body := "<html>product listing</html>"
		if strings.Contains(id, "'") {
			body = "You have an error in your SQL syntax; check the manual for MySQL near ''"
		}
		h := http.Header{}
		h.Set("Content-Type", "text/html")
		return &Response{Status: 200, Header: h, Body: []byte(body)}
	}})
	seedFlow(flows, "GET", "https", "shop.test", 443, "/item?id=5")

	job, err := e.Start(Options{Scope: Scope{Include: []string{"shop.test"}}, Checks: []string{"sqli"},
		Intensity: IntensityLight, Concurrency: 1, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, e, job.ID)
	f := findType(e.store.All(), "sqli")
	if f == nil {
		t.Fatalf("expected SQL injection finding, got %v", titles(e.store.All()))
	}
	if f.Severity != SevHigh {
		t.Errorf("sqli should be high, got %s", f.Severity)
	}
}

func TestActiveRequiresScope(t *testing.T) {
	cfg := core.LoadConfig(".")
	e := NewEngine(core.NewStore(cfg), cfg)
	e.SetRequester(fakeReq{handler: func(*Request) *Response { return nil }})
	if _, err := e.Start(Options{Checks: []string{"sqli"}}); err == nil {
		t.Fatal("expected error when no in-scope host is set")
	}
}

func titles(fs []*Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Type)
	}
	return out
}

func TestScopeMatching(t *testing.T) {
	sc := Scope{Include: []string{"*.example.com", "api.test"}, Exclude: []string{"secret.example.com"}}
	cases := map[string]bool{
		"https://api.example.com/x":    true,
		"https://api.test/y":           true,
		"https://secret.example.com/z": false,
		"https://other.org/":           false,
	}
	for url, want := range cases {
		if got := sc.InScope(url); got != want {
			t.Errorf("InScope(%s) = %v, want %v", url, got, want)
		}
	}
}

package scan

import (
	"net/http"
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

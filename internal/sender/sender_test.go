package sender

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"sift/internal/core"
)

func TestParseRawRequest(t *testing.T) {
	p, err := parseRaw("post /api/v1/login?a=1 HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\nX-Dup: one\nX-Dup: two\n\n{\"u\":\"a\"}")
	if err != nil {
		t.Fatal(err)
	}
	if p.Method != "POST" {
		t.Errorf("method = %q, want POST", p.Method)
	}
	if p.Path != "/api/v1/login?a=1" {
		t.Errorf("path = %q", p.Path)
	}
	if got := p.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("content-type = %q", got)
	}
	if got := p.Header.Values("X-Dup"); len(got) != 2 {
		t.Errorf("X-Dup = %v, want both values kept", got)
	}
	if string(p.Body) != `{"u":"a"}` {
		t.Errorf("body = %q", p.Body)
	}
}

func TestParseRawCRLFAndNoBody(t *testing.T) {
	p, err := parseRaw("GET / HTTP/1.1\r\nHost: x.test\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Body) != 0 {
		t.Errorf("body = %q, want empty", p.Body)
	}
	if p.Header.Get("Host") != "x.test" {
		t.Errorf("host = %q", p.Header.Get("Host"))
	}
}

func TestParseRawErrors(t *testing.T) {
	for _, raw := range []string{"", "   \n", "GET / HTTP/1.1\nbroken-header-line\n\n"} {
		if _, err := parseRaw(raw); err == nil {
			t.Errorf("parseRaw(%q) should have failed", raw)
		}
	}
}

func TestParseRawChunked(t *testing.T) {
	p, err := parseRaw("POST / HTTP/1.1\nHost: x.test\nTransfer-Encoding: chunked\n\nhi")
	if err != nil {
		t.Fatal(err)
	}
	if !p.Chunked {
		t.Error("Transfer-Encoding: chunked was not detected")
	}
}

func TestResolveTarget(t *testing.T) {
	cases := []struct {
		name, target, path     string
		scheme, host, wantPath string
		port                   int
	}{
		{"target wins", "https://a.test:8443", "/x", "https", "a.test", "/x", 8443},
		{"bare host defaults to https", "a.test", "/x", "https", "a.test", "/x", 443},
		{"explicit http", "http://a.test", "/x", "http", "a.test", "/x", 80},
		{"absolute request line", "", "http://b.test:81/y?z=1", "http", "b.test", "/y?z=1", 81},
		{"missing leading slash", "https://a.test", "x", "https", "a.test", "/x", 443},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &parsedRaw{Path: c.path, Header: http.Header{}}
			scheme, host, port, err := resolveTarget(c.target, p)
			if err != nil {
				t.Fatal(err)
			}
			if scheme != c.scheme || host != c.host || port != c.port || p.Path != c.wantPath {
				t.Errorf("got %s://%s:%d%s, want %s://%s:%d%s", scheme, host, port, p.Path, c.scheme, c.host, c.port, c.wantPath)
			}
		})
	}
}

func TestResolveTargetFallsBackToHostHeader(t *testing.T) {
	p := &parsedRaw{Path: "/x", Header: http.Header{"Host": {"h.test:8080"}}}
	scheme, host, port, err := resolveTarget("", p)
	if err != nil {
		t.Fatal(err)
	}
	if scheme != "https" || host != "h.test" || port != 8080 {
		t.Errorf("got %s://%s:%d", scheme, host, port)
	}
}

func TestResolveTargetRejectsNonHTTP(t *testing.T) {
	p := &parsedRaw{Path: "/x", Header: http.Header{}}
	if _, _, _, err := resolveTarget("ftp://a.test", p); err == nil {
		t.Error("ftp:// should be rejected")
	}
	if _, _, _, err := resolveTarget("", p); err == nil {
		t.Error("no target and no Host header should be rejected")
	}
}

func TestRawFromFlow(t *testing.T) {
	f := &core.Flow{Kind: "http", Method: "POST", Scheme: "https", Host: "api.test", Port: 443,
		Path: "/v1/thing", Proto: "HTTP/2.0", ReqBody: []byte(`{"a":1}`),
		ReqHeader: http.Header{"Content-Type": {"application/json"}, "Authorization": {"Bearer t"}}}
	raw, target, name := rawFromFlow(f)
	if !strings.HasPrefix(raw, "POST /v1/thing HTTP/1.1\n") {
		t.Errorf("first line wrong:\n%s", raw)
	}
	if !strings.Contains(raw, "\nHost: api.test\n") {
		t.Errorf("Host header missing:\n%s", raw)
	}
	if !strings.Contains(raw, "Authorization: Bearer t") || !strings.HasSuffix(raw, `{"a":1}`) {
		t.Errorf("headers or body missing:\n%s", raw)
	}
	if target != "https://api.test" {
		t.Errorf("target = %q", target)
	}
	if name != "POST /v1/thing" {
		t.Errorf("name = %q", name)
	}

	p, err := parseRaw(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Method != "POST" || p.Path != "/v1/thing" || string(p.Body) != `{"a":1}` {
		t.Errorf("round trip lost data: %+v", p)
	}
}

func TestRawRequestTextSetsContentLength(t *testing.T) {
	p := &parsedRaw{Method: "POST", Path: "/", Proto: "HTTP/1.1",
		Header: http.Header{"Host": {"ignored"}, "Content-Length": {"999"}, "X-A": {"1"}}, Body: []byte("abcd")}
	got := string(rawRequestText(p, "real.test", 4))
	if !strings.Contains(got, "Host: real.test\r\n") || strings.Contains(got, "Host: ignored") {
		t.Errorf("Host should come from the argument:\n%s", got)
	}
	if !strings.Contains(got, "Content-Length: 4\r\n") || strings.Contains(got, "999") {
		t.Errorf("Content-Length should be the computed one:\n%s", got)
	}
	if !strings.HasSuffix(got, "\r\n\r\nabcd") {
		t.Errorf("body should follow a blank line:\n%q", got)
	}
}

func fakeSOCKS5(t *testing.T, user, pass string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSOCKS5(c, user, pass)
		}
	}()
	return ln.Addr().String()
}

func serveSOCKS5(c net.Conn, user, pass string) {
	defer c.Close()
	r := bufio.NewReader(c)
	ver, _ := r.ReadByte()
	n, _ := r.ReadByte()
	methods := make([]byte, n)
	io.ReadFull(r, methods)
	if ver != 5 {
		return
	}
	want := byte(0x00)
	if user != "" {
		want = 0x02
	}
	ok := false
	for _, m := range methods {
		if m == want {
			ok = true
		}
	}
	if !ok {
		c.Write([]byte{0x05, 0xff})
		return
	}
	c.Write([]byte{0x05, want})
	if want == 0x02 {
		r.ReadByte()
		ul, _ := r.ReadByte()
		ub := make([]byte, ul)
		io.ReadFull(r, ub)
		pl, _ := r.ReadByte()
		pb := make([]byte, pl)
		io.ReadFull(r, pb)
		if string(ub) != user || string(pb) != pass {
			c.Write([]byte{0x01, 0x01})
			return
		}
		c.Write([]byte{0x01, 0x00})
	}

	head := make([]byte, 4)
	io.ReadFull(r, head)
	var host string
	switch head[3] {
	case 0x01:
		b := make([]byte, 4)
		io.ReadFull(r, b)
		host = net.IP(b).String()
	case 0x03:
		l, _ := r.ReadByte()
		b := make([]byte, l)
		io.ReadFull(r, b)
		host = string(b)
	case 0x04:
		b := make([]byte, 16)
		io.ReadFull(r, b)
		host = net.IP(b).String()
	}
	pb := make([]byte, 2)
	io.ReadFull(r, pb)
	port := binary.BigEndian.Uint16(pb)
	up, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))), 5*time.Second)
	if err != nil {
		c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	c.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 1})
	go io.Copy(up, r)
	io.Copy(c, up)
}

func TestSOCKS5NoAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "through socks")
	}))
	defer srv.Close()
	proxy := fakeSOCKS5(t, "", "")

	d := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return socks5Dial(ctx, d, proxy, "", "", addr)
	}}
	res, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if string(body) != "through socks" {
		t.Errorf("body = %q", body)
	}
}

func TestSOCKS5UserPass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "authed")
	}))
	defer srv.Close()
	proxy := fakeSOCKS5(t, "bob", "s3cret")
	d := &net.Dialer{Timeout: 5 * time.Second}

	tr := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return socks5Dial(ctx, d, proxy, "bob", "s3cret", addr)
	}}
	res, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if string(body) != "authed" {
		t.Errorf("body = %q", body)
	}

	tr2 := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return socks5Dial(ctx, d, proxy, "bob", "wrong", addr)
	}}
	if _, err := (&http.Client{Transport: tr2, Timeout: 10 * time.Second}).Get(srv.URL); err == nil {
		t.Error("a wrong password should fail")
	} else if !strings.Contains(err.Error(), "rejected the username or password") {
		t.Errorf("unhelpful error: %v", err)
	}
}

func TestSOCKS5ProxyDown(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()

	d := &net.Dialer{Timeout: 3 * time.Second}
	_, err := socks5Dial(context.Background(), d, dead, "", "", "example.test:443")
	if err == nil {
		t.Fatal("dialling a dead proxy should fail")
	}
	if !strings.Contains(err.Error(), "SOCKS5 proxy") {
		t.Errorf("error should name the proxy: %v", err)
	}
}

func TestSOCKS5UnreachableTarget(t *testing.T) {
	proxy := fakeSOCKS5(t, "", "")
	d := &net.Dialer{Timeout: 5 * time.Second}

	_, err := socks5Dial(context.Background(), d, proxy, "", "", "127.0.0.1:1")
	if err == nil {
		t.Fatal("an unreachable target should fail")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("want the proxy's reason, got: %v", err)
	}
}

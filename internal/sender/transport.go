package sender

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sort"
	"strconv"
	"strings"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"

	"sift/internal/core"
	"sift/internal/proxy"
)

type outgoing struct {
	route  *Route
	parsed *parsedRaw
	target string
	host   string
	clen   int64
	flow   *core.Flow
	jar    fhttp.CookieJar
}

type rawResponse struct {
	Proto   string
	Status  int
	Header  http.Header
	Body    []byte
	ReadErr error
}

func (s *Sender) doStdlib(ctx context.Context, o *outgoing) (*rawResponse, error) {
	p := o.parsed
	if o.flow != nil {
		ctx = httptrace.WithClientTrace(ctx, proxy.NewTrace(o.flow))
	}
	req, err := http.NewRequestWithContext(ctx, p.Method, o.target, bytes.NewReader(p.Body[:o.clen]))
	if err != nil {
		return nil, errors.New("Couldn't build the request: " + err.Error())
	}
	req.Header = p.Header.Clone()
	req.Header.Del("Host")
	req.Header.Del("Content-Length")
	req.Host = o.host
	if p.Chunked {
		req.Header.Del("Transfer-Encoding")
		req.TransferEncoding = []string{"chunked"}
		req.ContentLength = -1
	} else {
		req.ContentLength = o.clen
		if o.clen == 0 && !proxy.MethodsWithBody[p.Method] {
			req.Body = http.NoBody
		}
	}
	client, err := s.client(o.route)
	if err != nil {
		return nil, err
	}
	if o.jar != nil {
		client.Jar = &jarBridge{o.jar}
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(res.Body, maxSenderBody))
	return &rawResponse{Proto: res.Proto, Status: res.StatusCode, Header: res.Header, Body: body, ReadErr: readErr}, nil
}

func (s *Sender) doImpersonate(ctx context.Context, o *outgoing) (*rawResponse, error) {
	p := o.parsed
	client, err := s.impersonator(o.route, o.jar)
	if err != nil {
		return nil, err
	}
	req, err := fhttp.NewRequest(p.Method, o.target, bytes.NewReader(p.Body[:o.clen]))
	if err != nil {
		return nil, errors.New("Couldn't build the request: " + err.Error())
	}
	req = req.WithContext(ctx)
	req.Header = fhttp.Header{}
	seen := map[string]bool{}
	var order []string
	for _, name := range p.Order {
		lower := strings.ToLower(name)
		if lower == "host" || lower == "content-length" || seen[lower] {
			continue
		}
		seen[lower] = true
		req.Header[name] = p.Header.Values(name)
		order = append(order, name)
	}
	if len(order) > 0 {
		req.Header[fhttp.HeaderOrderKey] = order
	}
	req.Host = o.host
	if p.Chunked {
		req.Header.Del("Transfer-Encoding")
		req.TransferEncoding = []string{"chunked"}
		req.ContentLength = -1
	} else {
		req.ContentLength = o.clen
		if o.clen == 0 && !proxy.MethodsWithBody[p.Method] {
			req.Body = nil
		}
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(res.Body, maxSenderBody))
	hdr := http.Header{}
	for k, v := range res.Header {
		if k == fhttp.HeaderOrderKey || k == fhttp.PHeaderOrderKey {
			continue
		}
		hdr[http.CanonicalHeaderKey(k)] = v
	}
	return &rawResponse{Proto: res.Proto, Status: res.StatusCode, Header: hdr, Body: body, ReadErr: readErr}, nil
}

func (s *Sender) impersonator(rt *Route, jar fhttp.CookieJar) (tlsclient.HttpClient, error) {
	profile, ok := profileFor(rt.Profile)
	if !ok {
		return nil, errors.New("unknown TLS fingerprint " + strconv.Quote(rt.Profile))
	}
	timeout := rt.Timeout
	if timeout <= 0 {
		timeout = 30
	}
	opts := []tlsclient.HttpClientOption{
		tlsclient.WithClientProfile(profile),
		tlsclient.WithTimeoutSeconds(timeout),
	}
	if !rt.Follow {
		opts = append(opts, tlsclient.WithNotFollowRedirects())
	}
	if rt.HTTP1 {
		opts = append(opts, tlsclient.WithForceHttp1())
	}
	verify := s.cfg.Get().VerifyUpstream
	switch rt.Verify {
	case "on":
		verify = true
	case "off":
		verify = false
	}
	if !verify || rt.Kind == "sift" {
		opts = append(opts, tlsclient.WithInsecureSkipVerify())
	}
	if rt.Bind != "" {
		ip := net.ParseIP(strings.TrimSpace(rt.Bind))
		if ip == nil {
			return nil, errors.New("“Send from” must be an IP address of this computer")
		}
		opts = append(opts, tlsclient.WithLocalAddr(net.TCPAddr{IP: ip}))
	}
	if u := s.proxyURL(rt); u != "" {
		opts = append(opts, tlsclient.WithProxyUrl(u))
	}
	if jar != nil {
		opts = append(opts, tlsclient.WithCookieJar(jar))
	}
	return tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), opts...)
}

func (s *Sender) proxyURL(rt *Route) string {
	auth := ""
	if rt.User != "" {
		auth = url.UserPassword(rt.User, rt.Pass).String() + "@"
	}
	switch rt.Kind {
	case "sift":
		return "http://127.0.0.1:" + strconv.Itoa(s.port)
	case "http":
		return "http://" + auth + net.JoinHostPort(rt.Host, strconv.Itoa(portOr(rt.Port, 8080)))
	case "socks5":
		return "socks5://" + auth + net.JoinHostPort(rt.Host, strconv.Itoa(portOr(rt.Port, 1080)))
	}
	return ""
}

type jarBridge struct{ jar fhttp.CookieJar }

func (b *jarBridge) SetCookies(u *url.URL, cookies []*http.Cookie) {
	out := make([]*fhttp.Cookie, 0, len(cookies))
	for _, c := range cookies {
		out = append(out, &fhttp.Cookie{Name: c.Name, Value: c.Value, Path: c.Path, Domain: c.Domain,
			Expires: c.Expires, MaxAge: c.MaxAge, Secure: c.Secure, HttpOnly: c.HttpOnly})
	}
	b.jar.SetCookies(u, out)
}

func (b *jarBridge) Cookies(u *url.URL) []*http.Cookie {
	in := b.jar.Cookies(u)
	out := make([]*http.Cookie, 0, len(in))
	for _, c := range in {
		out = append(out, &http.Cookie{Name: c.Name, Value: c.Value, Path: c.Path, Domain: c.Domain,
			Expires: c.Expires, MaxAge: c.MaxAge, Secure: c.Secure, HttpOnly: c.HttpOnly})
	}
	return out
}

func profileFor(name string) (profiles.ClientProfile, bool) {
	p, ok := profiles.MappedTLSClients[name]
	return p, ok
}

type ProfileGroup struct {
	Label string   `json:"label"`
	Names []string `json:"names"`
}

func Profiles() []ProfileGroup {
	groups := map[string][]string{}
	for name := range profiles.MappedTLSClients {
		fam := profileFamily(name)
		groups[fam] = append(groups[fam], name)
	}
	order := []string{"Chrome", "Firefox", "Safari", "Opera", "Edge", "Brave", "Mobile apps", "Other"}
	out := make([]ProfileGroup, 0, len(order))
	for _, label := range order {
		names := groups[label]
		if len(names) == 0 {
			continue
		}
		sort.Sort(profileOrder(names))
		out = append(out, ProfileGroup{Label: label, Names: names})
	}
	return out
}

func profileFamily(name string) string {
	switch {
	case strings.HasPrefix(name, "chrome"):
		return "Chrome"
	case strings.HasPrefix(name, "firefox"):
		return "Firefox"
	case strings.HasPrefix(name, "safari"):
		return "Safari"
	case strings.HasPrefix(name, "opera"):
		return "Opera"
	case strings.HasPrefix(name, "edge") || strings.HasPrefix(name, "ms_edge"):
		return "Edge"
	case strings.HasPrefix(name, "brave"):
		return "Brave"
	case strings.HasPrefix(name, "okhttp") || strings.HasPrefix(name, "zalando") ||
		strings.HasPrefix(name, "nike") || strings.HasPrefix(name, "cloudscraper") ||
		strings.HasPrefix(name, "mms") || strings.HasPrefix(name, "mesh") ||
		strings.HasPrefix(name, "confirmed"):
		return "Mobile apps"
	}
	return "Other"
}

type profileOrder []string

func (p profileOrder) Len() int      { return len(p) }
func (p profileOrder) Swap(i, j int) { p[i], p[j] = p[j], p[i] }
func (p profileOrder) Less(i, j int) bool {
	a, b := versionOf(p[i]), versionOf(p[j])
	if a != b {
		return a > b
	}
	return p[i] < p[j]
}

func versionOf(name string) int {
	digits := []rune{}
	for _, r := range name {
		if r >= '0' && r <= '9' {
			digits = append(digits, r)
		} else if len(digits) > 0 {
			break
		}
	}
	n, _ := strconv.Atoi(string(digits))
	return n
}

func cookiesFor(jar fhttp.CookieJar, u *url.URL) []JarCookie {
	var out []JarCookie
	for _, c := range jar.Cookies(u) {
		out = append(out, JarCookie{Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path})
	}
	return out
}

func cookieHeader(cs []JarCookie) string {
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

func toFhttpCookies(h http.Header) []*fhttp.Cookie {
	res := http.Response{Header: h}
	var out []*fhttp.Cookie
	for _, c := range res.Cookies() {
		out = append(out, &fhttp.Cookie{Name: c.Name, Value: c.Value, Path: c.Path, Domain: c.Domain,
			Expires: c.Expires, MaxAge: c.MaxAge, Secure: c.Secure, HttpOnly: c.HttpOnly})
	}
	return out
}

func jarContents(jar fhttp.CookieJar, target string) []JarCookie {
	u, err := url.Parse(target)
	if err != nil {
		return nil
	}
	var out []JarCookie
	for _, c := range jar.Cookies(u) {
		out = append(out, JarCookie{Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path})
	}
	return out
}

func (r *Route) withProfile(name string) *Route {
	if name == "" || name == r.Profile {
		return r
	}
	c := *r
	if name == "none" {
		c.Profile = ""
	} else {
		c.Profile = name
	}
	return &c
}

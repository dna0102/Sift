package sender

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	tlsclient "github.com/bogdanfinn/tls-client"

	"sift/internal/core"
)

const (
	maxJarHops = 12
	maxJarBody = 4 << 20
)

type JarRequest struct {
	URL     string
	Raw     string
	Route   string
	Profile string
	Pattern string
	Regex   bool
	Follow  bool
}

type JarHop struct {
	N        int         `json:"n"`
	Method   string      `json:"method"`
	URL      string      `json:"url"`
	Status   int         `json:"status"`
	Reason   string      `json:"reason"`
	Dur      int64       `json:"dur"`
	Size     int64       `json:"size"`
	Flow     int64       `json:"flow"`
	ReqHead  [][2]string `json:"reqHead"`
	ResHead  [][2]string `json:"resHead"`
	Sent     []JarCookie `json:"sent"`
	Received []JarCookie `json:"received"`
	Err      string      `json:"err,omitempty"`
}

type JarCookie struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Domain  string `json:"domain,omitempty"`
	Path    string `json:"path,omitempty"`
	Expires string `json:"expires,omitempty"`
	Secure  bool   `json:"secure,omitempty"`
	HTTP    bool   `json:"httpOnly,omitempty"`
	Hop     int    `json:"hop"`
}

type JarMatch struct {
	Where string `json:"where"`
	Name  string `json:"name"`
	Value string `json:"value"`
	Hop   int    `json:"hop"`
}

type JarResult struct {
	Target  string      `json:"target"`
	Route   string      `json:"route"`
	Profile string      `json:"profile,omitempty"`
	Hops    []JarHop    `json:"hops"`
	Jar     []JarCookie `json:"jar"`
	Matches []JarMatch  `json:"matches"`
	Error   string      `json:"error,omitempty"`
}

func (s *Sender) Analyse(ctx context.Context, in JarRequest) (*JarResult, error) {
	rt := s.route(in.Route).withProfile(in.Profile)
	raw := strings.TrimSpace(in.Raw)
	if raw == "" {
		u := strings.TrimSpace(in.URL)
		if u == "" {
			return nil, errors.New("enter a page to fetch")
		}
		if !strings.Contains(u, "://") {
			u = "https://" + u
		}
		parsed, err := url.Parse(u)
		if err != nil || parsed.Host == "" {
			return nil, errors.New("that doesn't look like a URL")
		}
		raw = "GET " + parsed.RequestURI() + " HTTP/1.1\nHost: " + parsed.Host +
			"\nUser-Agent: " + userAgentFor(rt.Profile) +
			"\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\n" +
			"Accept-Language: en-GB,en;q=0.9\nAccept-Encoding: gzip, deflate, br\n\n"
	}

	p, err := parseRaw(raw)
	if err != nil {
		return nil, err
	}
	scheme, host, port, err := resolveTarget(in.URL, p)
	if err != nil {
		return nil, err
	}

	jar := tlsclient.NewCookieJar()
	res := &JarResult{Target: scheme + "://" + core.HostPort(host, port, scheme) + p.Path,
		Route: rt.Name, Profile: rt.Profile}

	method, path := p.Method, p.Path
	body := p.Body
	for hop := 1; hop <= maxJarHops; hop++ {
		target := scheme + "://" + core.HostPort(host, port, scheme) + path
		hostHeader := core.HostPort(host, port, scheme)

		hp := &parsedRaw{Method: method, Path: path, Proto: "HTTP/1.1", Header: p.Header.Clone(), Order: p.Order, Body: body}
		hp.Header.Set("Host", hostHeader)
		u, _ := url.Parse(target)
		sent := cookiesFor(jar, u)
		if len(sent) > 0 {
			hp.Header.Set("Cookie", cookieHeader(sent))
			if !hasOrder(hp.Order, "Cookie") {
				hp.Order = append(append([]string{}, hp.Order...), "Cookie")
			}
		}

		f := &core.Flow{Kind: "http", Start: time.Now(), State: "pending", Method: method, Scheme: scheme,
			Host: host, Port: port, Path: path, Proto: "HTTP/1.1", App: "Sift",
			Tags: []string{"jar", rt.ID}, ReqHeader: hp.Header.Clone(), MaxBody: s.cfg.Get().MaxBody()}
		f.ReqBody, f.ReqSize = body, int64(len(body))
		s.store.Add(f)

		timeout := time.Duration(portOr(rt.Timeout, 30)) * time.Second
		hctx, cancel := context.WithTimeout(ctx, timeout)
		call := &outgoing{route: rt, parsed: hp, target: target, host: hostHeader, clen: int64(len(body)), flow: f, jar: jar}

		start := time.Now()
		var rr *rawResponse
		if rt.Profile != "" {
			rr, err = s.doImpersonate(hctx, call)
		} else {
			rr, err = s.doStdlib(hctx, call)
		}
		cancel()

		h := JarHop{N: hop, Method: method, URL: target, Flow: f.ID,
			Dur: time.Since(start).Milliseconds(), ReqHead: headerPairs(hp.Header), Sent: sent}
		if err != nil {
			h.Err = s.explain(err, rt, host, port)
			f.Fail(h.Err)
			f.Lock()
			f.End = time.Now()
			f.Unlock()
			s.store.Finished(f)
			res.Hops = append(res.Hops, h)
			res.Error = h.Err
			break
		}

		decoded := rr.Body
		if enc := rr.Header.Get("Content-Encoding"); enc != "" {
			if d, ok := core.DecodeBody(rr.Body, enc); ok {
				decoded = d
			}
		}
		h.Status, h.Reason, h.Size = rr.Status, http.StatusText(rr.Status), int64(len(rr.Body))
		h.ResHead = headerPairs(rr.Header)
		h.Received = setCookies(rr.Header, hop)

		f.Lock()
		f.Status, f.StatusText, f.ResProto = rr.Status, http.StatusText(rr.Status), rr.Proto
		f.ResHeader = rr.Header.Clone()
		f.ResBody = decoded[:min(len(decoded), f.MaxBody)]
		f.ResSize, f.ResTrunc, f.Decoded = int64(len(rr.Body)), len(decoded) > f.MaxBody, true
		f.ResHeader.Del("Content-Encoding")
		f.End, f.State = time.Now(), "done"
		f.Unlock()
		s.store.Finished(f)

		jar.SetCookies(u, toFhttpCookies(rr.Header))
		res.Hops = append(res.Hops, h)

		loc := rr.Header.Get("Location")
		if !in.Follow || loc == "" || rr.Status < 300 || rr.Status > 399 {
			break
		}
		next, err := u.Parse(loc)
		if err != nil || next.Host == "" {
			break
		}
		scheme = strings.ToLower(next.Scheme)
		host, port = core.SplitHostPort(next.Host, core.DefaultPort(scheme))
		path = next.RequestURI()
		if rr.Status == 303 || method == "POST" {
			method, body = "GET", nil
		}
	}

	res.Jar = jarContents(jar, res.Target)
	res.Matches, err = searchJar(res, in.Pattern, in.Regex)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func hasOrder(order []string, name string) bool {
	for _, o := range order {
		if strings.EqualFold(o, name) {
			return true
		}
	}
	return false
}

func userAgentFor(profile string) string {
	switch {
	case strings.HasPrefix(profile, "firefox"):
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"
	case strings.HasPrefix(profile, "safari"):
		return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
	case strings.HasPrefix(profile, "okhttp"):
		return "okhttp/4.12.0"
	}
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
}

func headerPairs(h http.Header) [][2]string {
	rows := core.HeaderRows(h)
	out := make([][2]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, [2]string{r[0], r[1]})
	}
	return out
}

func setCookies(h http.Header, hop int) []JarCookie {
	res := http.Response{Header: h}
	var out []JarCookie
	for _, c := range res.Cookies() {
		jc := JarCookie{Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
			Secure: c.Secure, HTTP: c.HttpOnly, Hop: hop}
		if !c.Expires.IsZero() {
			jc.Expires = c.Expires.UTC().Format(time.RFC3339)
		} else if c.MaxAge > 0 {
			jc.Expires = "in " + strconv.Itoa(c.MaxAge) + "s"
		}
		out = append(out, jc)
	}
	return out
}

func searchJar(res *JarResult, pattern string, isRegex bool) ([]JarMatch, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil, nil
	}
	var re *regexp.Regexp
	var err error
	if isRegex {
		re, err = regexp.Compile(pattern)
		if err != nil {
			return nil, errors.New("that regex doesn't compile: " + err.Error())
		}
	}
	hit := func(name, value string) bool {
		if re != nil {
			return re.MatchString(name) || re.MatchString(value)
		}
		p := strings.ToLower(pattern)
		return strings.Contains(strings.ToLower(name), p) || strings.Contains(strings.ToLower(value), p)
	}
	var out []JarMatch
	for _, c := range res.Jar {
		if hit(c.Name, c.Value) {
			out = append(out, JarMatch{Where: "cookie jar", Name: c.Name, Value: c.Value, Hop: c.Hop})
		}
	}
	for _, h := range res.Hops {
		for _, c := range h.Received {
			if hit(c.Name, c.Value) {
				out = append(out, JarMatch{Where: "set-cookie", Name: c.Name, Value: c.Value, Hop: h.N})
			}
		}
		for _, r := range h.ReqHead {
			if hit(r[0], r[1]) {
				out = append(out, JarMatch{Where: "request header", Name: r[0], Value: r[1], Hop: h.N})
			}
		}
		for _, r := range h.ResHead {
			if hit(r[0], r[1]) {
				out = append(out, JarMatch{Where: "response header", Name: r[0], Value: r[1], Hop: h.N})
			}
		}
	}
	return out, nil
}

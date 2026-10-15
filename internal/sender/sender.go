package sender

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"sift/internal/core"
	"sift/internal/proxy"
)

const (
	maxSenderHistory = 60
	maxSenderBody    = 32 << 20
	MaxSenderShow    = 2 << 20
)

type Route struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	User    string `json:"user"`
	Pass    string `json:"pass"`
	Bind    string `json:"bind"`
	Verify  string `json:"verify"`
	Follow  bool   `json:"follow"`
	Timeout int    `json:"timeout"`
}

func builtinRoutes() []*Route {
	return []*Route{
		{ID: "direct", Name: "Direct — this PC's network", Kind: "direct"},
		{ID: "sift", Name: "Through Sift (applies rules & breakpoints)", Kind: "sift"},
	}
}

type Tab struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Raw    string `json:"raw"`
	Target string `json:"target"`
	Route  string `json:"route"`
}

type Entry struct {
	N      int    `json:"n"`
	At     int64  `json:"at"`
	Status int    `json:"status"`
	Reason string `json:"reason"`
	Dur    int64  `json:"dur"`
	Size   int64  `json:"size"`
	Flow   int64  `json:"flow"`
	Route  string `json:"route"`
	Target string `json:"target"`
	Err    string `json:"err,omitempty"`
	Note   string `json:"note,omitempty"`

	req []byte
	res []byte
}

func (e *Entry) RawRequest() []byte { return e.req }

func (e *Entry) RawResponse() []byte { return e.res }

type Sender struct {
	cfg   *core.Config
	store *core.Store
	port  int
	path  string

	mu     sync.Mutex
	tabs   []*Tab
	routes []*Route
	hist   map[string][]*Entry
	seq    int
	trans  map[string]*http.Transport
	timer  *time.Timer
}

type senderFile struct {
	Tabs   []*Tab   `json:"tabs"`
	Routes []*Route `json:"routes"`
}

func NewSender(home string, cfg *core.Config, store *core.Store, proxyPort int) *Sender {
	s := &Sender{cfg: cfg, store: store, port: proxyPort, path: filepath.Join(home, "sender.json"),
		hist: map[string][]*Entry{}, trans: map[string]*http.Transport{}}
	if data, err := os.ReadFile(s.path); err == nil {
		var f senderFile
		if json.Unmarshal(data, &f) == nil {
			s.tabs, s.routes = f.Tabs, f.Routes
		}
	}
	if len(s.tabs) == 0 {
		s.tabs = []*Tab{newTab("")}
	}
	return s
}

func newTab(raw string) *Tab {
	if raw == "" {
		raw = "GET / HTTP/1.1\nHost: example.com\nUser-Agent: Sift\nAccept: */*\n\n"
	}
	return &Tab{ID: randomID(), Name: "Request", Raw: raw, Target: "https://example.com", Route: "direct"}
}

func randomID() string {
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

func (s *Sender) save() {
	s.mu.Lock()
	data, _ := json.MarshalIndent(senderFile{Tabs: s.tabs, Routes: s.routes}, "", "  ")
	s.mu.Unlock()
	tmp := s.path + ".tmp"
	if os.WriteFile(tmp, data, 0o600) == nil {
		_ = os.Rename(tmp, s.path)
	}
}

func (s *Sender) saveSoon() {
	s.mu.Lock()
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.AfterFunc(400*time.Millisecond, s.save)
	s.mu.Unlock()
}

func (s *Sender) Routes() []*Route {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := builtinRoutes()
	for _, r := range s.routes {
		c := *r
		c.Pass = ""
		out = append(out, &c)
	}
	return out
}

func (s *Sender) Tabs() []*Tab {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*Tab(nil), s.tabs...)
}

func (s *Sender) tab(id string) *Tab {
	for _, t := range s.tabs {
		if t.ID == id {
			return t
		}
	}
	return nil
}

func (s *Sender) NewTab(from *core.Flow) *Tab {
	t := newTab("")
	if from != nil {
		raw, target, name := rawFromFlow(from)
		t.Raw, t.Target, t.Name = raw, target, name
	}
	s.mu.Lock()
	s.tabs = append(s.tabs, t)
	s.mu.Unlock()
	s.saveSoon()
	return t
}

func (s *Sender) SaveTab(id, name, raw, target, route string) {
	s.mu.Lock()
	if t := s.tab(id); t != nil {
		if name != "" {
			t.Name = name
		}
		t.Raw, t.Target, t.Route = raw, target, route
	}
	s.mu.Unlock()
	s.saveSoon()
}

func (s *Sender) CloseTab(id string) {
	s.mu.Lock()
	for i, t := range s.tabs {
		if t.ID == id {
			s.tabs = append(s.tabs[:i], s.tabs[i+1:]...)
			break
		}
	}
	delete(s.hist, id)
	if len(s.tabs) == 0 {
		s.tabs = []*Tab{newTab("")}
	}
	s.mu.Unlock()
	s.save()
}

func (s *Sender) SaveRoute(r *Route) {
	s.mu.Lock()
	if r.ID == "" {
		r.ID = randomID()
	}
	replaced := false
	for i, old := range s.routes {
		if old.ID == r.ID {
			if r.Pass == "" {
				r.Pass = old.Pass
			}
			s.routes[i] = r
			replaced = true
			break
		}
	}
	if !replaced {
		s.routes = append(s.routes, r)
	}
	s.trans = map[string]*http.Transport{}
	s.mu.Unlock()
	s.save()
}

func (s *Sender) DeleteRoute(id string) {
	s.mu.Lock()
	for i, r := range s.routes {
		if r.ID == id {
			s.routes = append(s.routes[:i], s.routes[i+1:]...)
			break
		}
	}
	s.mu.Unlock()
	s.save()
}

func (s *Sender) route(id string) *Route {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range append(builtinRoutes(), s.routes...) {
		if r.ID == id {
			return r
		}
	}
	return &Route{ID: "direct", Name: "Direct", Kind: "direct"}
}

func (s *Sender) History(tabID string) []*Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*Entry(nil), s.hist[tabID]...)
}

func (s *Sender) Entry(tabID string, n int) *Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.hist[tabID] {
		if e.N == n {
			return e
		}
	}
	return nil
}

func rawFromFlow(f *core.Flow) (raw, target, name string) {
	f.Lock()
	defer f.Unlock()
	var b strings.Builder
	proto := f.Proto
	if proto == "" || strings.HasPrefix(proto, "HTTP/2") {
		proto = "HTTP/1.1"
	}
	path := f.Path
	if path == "" {
		path = "/"
	}
	fmt.Fprintf(&b, "%s %s %s\n", f.Method, path, proto)
	if f.ReqHeader.Get("Host") == "" {
		fmt.Fprintf(&b, "Host: %s\n", core.HostPort(f.Host, f.Port, f.Scheme))
	}
	for _, row := range core.HeaderRows(f.ReqHeader) {
		fmt.Fprintf(&b, "%s: %s\n", row[0], row[1])
	}
	b.WriteString("\n")
	if len(f.ReqBody) > 0 && !core.IsBinary(f.ReqBody) {
		b.Write(f.ReqBody)
	}
	target = f.Scheme + "://" + core.HostPort(f.Host, f.Port, f.Scheme)
	name = f.Method + " " + strings.SplitN(path, "?", 2)[0]
	if len(name) > 40 {
		name = name[:40]
	}
	return b.String(), target, name
}

type parsedRaw struct {
	Method, Path, Proto string
	Header              http.Header
	Body                []byte
	Chunked             bool
}

func parseRaw(raw string) (*parsedRaw, error) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	head, body, found := strings.Cut(raw, "\n\n")
	if !found {
		head = strings.TrimRight(raw, "\n")
	}
	lines := strings.Split(head, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return nil, errors.New("the first line must be like: GET /path HTTP/1.1")
	}
	parts := strings.Fields(strings.TrimSpace(lines[0]))
	p := &parsedRaw{Method: "GET", Path: "/", Proto: "HTTP/1.1", Header: http.Header{}}
	switch len(parts) {
	case 1:
		p.Path = parts[0]
	case 2:
		p.Method, p.Path = strings.ToUpper(parts[0]), parts[1]
	default:
		p.Method, p.Path, p.Proto = strings.ToUpper(parts[0]), parts[1], parts[2]
	}
	if p.Path == "" {
		p.Path = "/"
	}
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if k = strings.TrimSpace(k); !ok || k == "" {
			return nil, fmt.Errorf("header line %q needs a colon", line)
		}
		p.Header.Add(k, strings.TrimSpace(v))
	}
	p.Body = []byte(body)
	if strings.Contains(strings.ToLower(p.Header.Get("Transfer-Encoding")), "chunked") {
		p.Chunked = true
	}
	return p, nil
}

func rawRequestText(p *parsedRaw, host string, clen int64) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s %s\r\n", p.Method, p.Path, p.Proto)
	fmt.Fprintf(&b, "Host: %s\r\n", host)
	for _, row := range core.HeaderRows(p.Header) {
		if strings.EqualFold(row[0], "Host") || strings.EqualFold(row[0], "Content-Length") {
			continue
		}
		fmt.Fprintf(&b, "%s: %s\r\n", row[0], row[1])
	}
	if clen >= 0 && (len(p.Body) > 0 || proxy.MethodsWithBody[p.Method]) {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", clen)
	}
	b.WriteString("\r\n")
	b.Write(p.Body)
	return b.Bytes()
}

type SendReq struct {
	Tab      string
	Raw      string
	Target   string
	Route    string
	UpdateCL bool
}

func (s *Sender) Send(ctx context.Context, in SendReq) (*Entry, error) {
	p, err := parseRaw(in.Raw)
	if err != nil {
		return nil, err
	}
	scheme, host, port, err := resolveTarget(in.Target, p)
	if err != nil {
		return nil, err
	}
	rt := s.route(in.Route)

	clen := int64(len(p.Body))
	note := ""
	if !in.UpdateCL {
		if v := p.Header.Get("Content-Length"); v != "" {
			if n, e := strconv.ParseInt(strings.TrimSpace(v), 10, 64); e == nil && n >= 0 {
				if n > clen {
					note = fmt.Sprintf("Content-Length %d is larger than the %d-byte body; sent %d.", n, clen, clen)
				} else {
					clen = n
				}
			}
		}
	}

	hostHeader := p.Header.Get("Host")
	if hostHeader == "" {
		hostHeader = core.HostPort(host, port, scheme)
	}

	f := &core.Flow{Kind: "http", Start: time.Now(), State: "pending", Method: p.Method, Scheme: scheme,
		Host: host, Port: port, Path: p.Path, Proto: p.Proto, App: "Sift",
		Tags: []string{"sender", rt.ID}, ReqHeader: p.Header.Clone(),
		MaxBody: s.cfg.Get().MaxBody()}
	f.ReqHeader.Set("Host", hostHeader)
	f.ReqBody, f.ReqSize = p.Body[:min(len(p.Body), f.MaxBody)], int64(len(p.Body))
	f.ReqTrunc = len(p.Body) > f.MaxBody
	s.store.Add(f)

	s.mu.Lock()
	s.seq++
	n := s.seq
	s.mu.Unlock()

	e := &Entry{N: n, At: time.Now().UnixMilli(), Route: rt.Name, Target: scheme + "://" + core.HostPort(host, port, scheme),
		Flow: f.ID, Note: note, req: rawRequestText(p, hostHeader, clen)}

	target := scheme + "://" + core.HostPort(host, port, scheme) + p.Path
	timeout := time.Duration(rt.Timeout) * time.Second
	if rt.Timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, proxy.NewTrace(f)), p.Method, target, bytes.NewReader(p.Body[:clen]))
	if err != nil {
		s.finish(in.Tab, e, f, "Couldn't build the request: "+err.Error())
		return e, nil
	}
	req.Header = p.Header.Clone()
	req.Header.Del("Host")
	req.Header.Del("Content-Length")
	req.Host = hostHeader
	if p.Chunked {
		req.Header.Del("Transfer-Encoding")
		req.TransferEncoding = []string{"chunked"}
		req.ContentLength = -1
	} else {
		req.ContentLength = clen
		if clen == 0 && !proxy.MethodsWithBody[p.Method] {
			req.Body = http.NoBody
		}
	}

	client, err := s.client(rt)
	if err != nil {
		s.finish(in.Tab, e, f, err.Error())
		return e, nil
	}
	start := time.Now()
	res, err := client.Do(req)
	if err != nil {
		s.finish(in.Tab, e, f, s.explain(err, rt, host, port))
		return e, nil
	}
	defer res.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(res.Body, maxSenderBody))
	e.Dur = time.Since(start).Milliseconds()
	decoded := body
	if enc := res.Header.Get("Content-Encoding"); enc != "" {
		if d, ok := core.DecodeBody(body, enc); ok {
			decoded = d
		}
	}
	e.Status, e.Reason, e.Size = res.StatusCode, http.StatusText(res.StatusCode), int64(len(body))
	e.res = rawResponseText(res, decoded)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		e.Err = "The response was cut short: " + readErr.Error()
	}

	f.Lock()
	f.Status, f.StatusText, f.ResProto = res.StatusCode, http.StatusText(res.StatusCode), res.Proto
	f.ResHeader = res.Header.Clone()
	f.ResBody = decoded[:min(len(decoded), f.MaxBody)]
	f.ResSize, f.ResTrunc, f.Decoded = int64(len(body)), len(decoded) > f.MaxBody, true
	f.ResHeader.Del("Content-Encoding")
	f.End, f.State = time.Now(), "done"
	f.Unlock()
	s.store.Finished(f)

	s.record(in.Tab, e)
	return e, nil
}

func (s *Sender) finish(tabID string, e *Entry, f *core.Flow, msg string) {
	e.Err = msg
	f.Fail(msg)
	f.Lock()
	f.End = time.Now()
	f.Unlock()
	s.store.Finished(f)
	s.record(tabID, e)
}

func (s *Sender) record(tabID string, e *Entry) {
	s.mu.Lock()
	h := append(s.hist[tabID], e)
	if len(h) > maxSenderHistory {
		h = h[len(h)-maxSenderHistory:]
	}
	s.hist[tabID] = h
	s.mu.Unlock()
}

func (s *Sender) explain(err error, rt *Route, host string, port int) string {
	txt := err.Error()
	via := ""
	switch rt.Kind {
	case "sift":
		via = "Sift's own proxy on 127.0.0.1:" + strconv.Itoa(s.port)
	case "http":
		via = "the HTTP proxy " + net.JoinHostPort(rt.Host, strconv.Itoa(portOr(rt.Port, 8080)))
	case "socks5":
		via = "the SOCKS5 proxy " + net.JoinHostPort(rt.Host, strconv.Itoa(portOr(rt.Port, 1080)))
	}
	if via != "" {

		if rt.Bind != "" && strings.Contains(txt, "not valid in its context") {
			return fmt.Sprintf("Can't reach %s while “Send from” is set to %s. Set “Send from” to Any for a proxy on this computer.", via, rt.Bind)
		}
		if strings.Contains(txt, "refused") || strings.Contains(txt, "actively refused") {
			return "Couldn't connect to " + via + " — nothing is listening there."
		}
		if strings.Contains(txt, "SOCKS5") || strings.Contains(txt, "proxyconnect") {
			if i := strings.Index(txt, "SOCKS5"); i >= 0 {
				return txt[i:]
			}
			return "Couldn't use " + via + ": " + txt
		}
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(txt, "timeout") {
			return "Timed out going through " + via + "."
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Sprintf("Timed out after %ds waiting for %s:%d.", portOr(rt.Timeout, 30), host, port)
	}
	return proxy.DescribeErr(err, host, port)
}

func rawResponseText(res *http.Response, body []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %d %s\r\n", res.Proto, res.StatusCode, http.StatusText(res.StatusCode))
	for _, row := range core.HeaderRows(res.Header) {
		fmt.Fprintf(&b, "%s: %s\r\n", row[0], row[1])
	}
	b.WriteString("\r\n")
	b.Write(body)
	return b.Bytes()
}

func resolveTarget(target string, p *parsedRaw) (scheme, host string, port int, err error) {
	if strings.HasPrefix(strings.ToLower(p.Path), "http://") || strings.HasPrefix(strings.ToLower(p.Path), "https://") {
		if u, e := url.Parse(p.Path); e == nil && u.Host != "" {
			p.Path = u.RequestURI()
			h, pt := core.SplitHostPort(u.Host, core.DefaultPort(u.Scheme))
			return strings.ToLower(u.Scheme), h, pt, nil
		}
	}
	t := strings.TrimSpace(target)
	if t == "" {
		t = p.Header.Get("Host")
		if t == "" {
			return "", "", 0, errors.New("set a target, or add a Host header")
		}
	}
	if !strings.Contains(t, "://") {
		t = "https://" + t
	}
	u, e := url.Parse(t)
	if e != nil || u.Host == "" {
		return "", "", 0, errors.New("target should look like https://example.com")
	}
	scheme = strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", 0, errors.New("the target must be http:// or https://")
	}
	host, port = core.SplitHostPort(u.Host, core.DefaultPort(scheme))
	if !strings.HasPrefix(p.Path, "/") && !strings.HasPrefix(p.Path, "*") {
		p.Path = "/" + p.Path
	}
	return scheme, host, port, nil
}

func (s *Sender) client(rt *Route) (*http.Client, error) {
	key := fmt.Sprintf("%s|%s|%d|%s|%s|%s|%v", rt.Kind, rt.Host, rt.Port, rt.Bind, rt.User, rt.Verify, s.cfg.Get().VerifyUpstream)
	s.mu.Lock()
	tr, ok := s.trans[key]
	s.mu.Unlock()
	if !ok {
		var err error
		tr, err = s.transport(rt)
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		s.trans[key] = tr
		s.mu.Unlock()
	}
	c := &http.Client{Transport: tr}
	if !rt.Follow {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return c, nil
}

func (s *Sender) transport(rt *Route) (*http.Transport, error) {
	verify := s.cfg.Get().VerifyUpstream
	switch rt.Verify {
	case "on":
		verify = true
	case "off":
		verify = false
	}
	d := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	if rt.Bind != "" {
		ip := net.ParseIP(strings.TrimSpace(rt.Bind))
		if ip == nil {
			return nil, errors.New("“Send from” must be an IP address of this computer")
		}
		d.LocalAddr = &net.TCPAddr{IP: ip}
	}
	tr := &http.Transport{
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !verify, MinVersion: tls.VersionTLS10,
			CipherSuites: proxy.AllCipherSuites()},
	}
	switch rt.Kind {
	case "direct":
	case "sift":
		u, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(s.port))
		tr.Proxy = http.ProxyURL(u)
		tr.TLSClientConfig.InsecureSkipVerify = true
	case "http":
		if rt.Host == "" {
			return nil, errors.New("the proxy needs a host")
		}
		u := &url.URL{Scheme: "http", Host: net.JoinHostPort(rt.Host, strconv.Itoa(portOr(rt.Port, 8080)))}
		if rt.User != "" {
			u.User = url.UserPassword(rt.User, rt.Pass)
		}
		tr.Proxy = http.ProxyURL(u)
	case "socks5":
		if rt.Host == "" {
			return nil, errors.New("the proxy needs a host")
		}
		px := net.JoinHostPort(rt.Host, strconv.Itoa(portOr(rt.Port, 1080)))
		user, pass := rt.User, rt.Pass
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return socks5Dial(ctx, d, px, user, pass, addr)
		}
	default:
		return nil, errors.New("unknown route type " + rt.Kind)
	}
	return tr, nil
}

func portOr(p, def int) int {
	if p > 0 && p < 65536 {
		return p
	}
	return def
}

func socks5Dial(ctx context.Context, d *net.Dialer, proxy, user, pass, addr string) (net.Conn, error) {
	c, err := d.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 proxy %s: %w", proxy, err)
	}
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()
	if dl, has := ctx.Deadline(); has {
		c.SetDeadline(dl)
	} else {
		c.SetDeadline(time.Now().Add(30 * time.Second))
	}

	methods := []byte{0x00}
	if user != "" {
		methods = []byte{0x02, 0x00}
	}
	if _, err = c.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return nil, fmt.Errorf("SOCKS5 handshake: %w", err)
	}
	r := bufio.NewReader(c)
	reply := make([]byte, 2)
	if _, err = io.ReadFull(r, reply); err != nil {
		return nil, fmt.Errorf("SOCKS5 handshake: %w", err)
	}
	if reply[0] != 0x05 {
		return nil, fmt.Errorf("%s doesn't speak SOCKS5", proxy)
	}
	switch reply[1] {
	case 0x00:
	case 0x02:
		if user == "" {
			return nil, fmt.Errorf("SOCKS5 proxy %s wants a username and password", proxy)
		}
		if len(user) > 255 || len(pass) > 255 {
			return nil, errors.New("SOCKS5 username and password must be under 256 characters")
		}
		msg := []byte{0x01, byte(len(user))}
		msg = append(msg, user...)
		msg = append(msg, byte(len(pass)))
		msg = append(msg, pass...)
		if _, err = c.Write(msg); err != nil {
			return nil, fmt.Errorf("SOCKS5 login: %w", err)
		}
		if _, err = io.ReadFull(r, reply); err != nil {
			return nil, fmt.Errorf("SOCKS5 login: %w", err)
		}
		if reply[1] != 0x00 {
			return nil, fmt.Errorf("SOCKS5 proxy %s rejected the username or password", proxy)
		}
	case 0xff:
		return nil, fmt.Errorf("SOCKS5 proxy %s refused every authentication method", proxy)
	default:
		return nil, fmt.Errorf("SOCKS5 proxy %s asked for an unsupported authentication method", proxy)
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("host name too long for SOCKS5")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err = c.Write(req); err != nil {
		return nil, fmt.Errorf("SOCKS5 connect: %w", err)
	}

	head := make([]byte, 4)
	if _, err = io.ReadFull(r, head); err != nil {
		return nil, fmt.Errorf("SOCKS5 connect: %w", err)
	}
	if head[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 proxy couldn't reach %s: %s", addr, socks5Error(head[1]))
	}

	switch head[3] {
	case 0x01:
		_, err = io.CopyN(io.Discard, r, 4+2)
	case 0x04:
		_, err = io.CopyN(io.Discard, r, 16+2)
	case 0x03:
		var l byte
		if l, err = r.ReadByte(); err == nil {
			_, err = io.CopyN(io.Discard, r, int64(l)+2)
		}
	default:
		err = errors.New("unexpected address type in the SOCKS5 reply")
	}
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 connect: %w", err)
	}
	c.SetDeadline(time.Time{})
	ok = true

	return &bufConn{Conn: c, r: r}, nil
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func socks5Error(code byte) string {
	switch code {
	case 0x01:
		return "general failure"
	case 0x02:
		return "not allowed by the proxy's rules"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	}
	return "error " + strconv.Itoa(int(code))
}

type NetIface struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
}

func LocalInterfaces() []NetIface {
	var out []NetIface
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil || ipn.IP.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, NetIface{Name: i.Name, IP: ipn.IP.String()})
		}
	}
	return out
}

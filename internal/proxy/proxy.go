package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"sift/internal/ca"
	"sift/internal/core"
	"sift/internal/sysproxy"
)

type clientInfo struct {
	addr      string
	port      int
	proxyPort int
	emuApp    string
	once      sync.Once
	app       string
}

func (c *clientInfo) App() string {
	c.once.Do(func() {
		if strings.HasPrefix(c.addr, "127.") || strings.HasPrefix(c.addr, "[::1]") {
			name := prettyApp(sysproxy.AppForConn(c.port, c.proxyPort))

			if isEmulatorProcess(name) && c.emuApp != "" {
				name = c.emuApp + " (emulator)"
			}
			c.app = name
		}
	})
	return c.app
}

func isEmulatorProcess(name string) bool {
	n := strings.ToLower(name)

	return n == "" || strings.HasPrefix(n, "adb") || strings.Contains(n, "qemu") ||
		strings.Contains(n, "emulator") || strings.Contains(n, "crosvm") || strings.Contains(n, "goldfish")
}

type connInfo struct {
	client *clientInfo
	host   string
	sni    string
	port   int
	scheme string
}

type ctxKey struct{}

func infoFrom(ctx context.Context) *connInfo {
	if ci, ok := ctx.Value(ctxKey{}).(*connInfo); ok {
		return ci
	}
	return &connInfo{client: &clientInfo{}}
}

type chanListener struct {
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newChanListener() *chanListener {
	return &chanListener{ch: make(chan net.Conn), done: make(chan struct{})}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *chanListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *chanListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (l *chanListener) push(c net.Conn) {
	select {
	case l.ch <- c:
	case <-l.done:
		c.Close()
	}
}

type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekConn) Read(b []byte) (int, error) { return c.r.Read(b) }

type Proxy struct {
	cfg    *core.Config
	store  *core.Store
	ca     *ca.CA
	bps    *core.Breakpoints
	port   int
	uiPort int

	EmulatorApp func() (name, serial string, ok bool)

	srv      *http.Server
	ln       net.Listener
	lnMu     sync.Mutex
	mitm     *chanListener
	plain    *chanListener
	infos    sync.Map
	up       *Upstream
	Pins     *PinTracker
	tlsBase  *tls.Config
	dialer   *net.Dialer
	tlsFails sync.Map
	bufs     sync.Pool
}

var QuietLog = log.New(io.Discard, "", 0)

var debugLog = func() *log.Logger {
	if os.Getenv("SIFT_DEBUG") != "" {
		return log.New(os.Stderr, "debug ", log.Ltime|log.Lmicroseconds)
	}
	return nil
}()

func Debugf(format string, args ...any) {
	if debugLog != nil {
		debugLog.Printf(format, args...)
	}
}

func NewProxy(cfg *core.Config, store *core.Store, root *ca.CA, bps *core.Breakpoints, port, uiPort int) *Proxy {
	p := &Proxy{cfg: cfg, store: store, ca: root, bps: bps, port: port, uiPort: uiPort,
		mitm: newChanListener(), plain: newChanListener(), Pins: NewPinTracker()}
	p.dialer = &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	p.up = NewUpstream(cfg)
	p.bufs.New = func() any { b := make([]byte, 32<<10); return &b }

	p.tlsBase = &tls.Config{NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS10, CipherSuites: AllCipherSuites()}

	p.srv = &http.Server{
		Handler:           http.HandlerFunc(p.serveMain),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          QuietLog,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			ci := &clientInfo{addr: c.RemoteAddr().String(), proxyPort: p.port}
			if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
				ci.port = a.Port
			}
			if p.EmulatorApp != nil {
				if name, _, ok := p.EmulatorApp(); ok {
					ci.emuApp = name
				}
			}
			return context.WithValue(ctx, ctxKey{}, &connInfo{client: ci})
		},
	}
	inner := func() *http.Server {
		return &http.Server{
			Handler:     http.HandlerFunc(p.serveTunneled),
			IdleTimeout: 2 * time.Minute,
			ErrorLog:    QuietLog,
			ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				if ci, ok := p.infos.LoadAndDelete(c); ok {
					return context.WithValue(ctx, ctxKey{}, ci)
				}
				return ctx
			},
		}
	}

	go inner().Serve(p.mitm)
	plain := inner()
	plain.Protocols = new(http.Protocols)
	plain.Protocols.SetHTTP1(true)
	plain.Protocols.SetUnencryptedHTTP2(true)
	go plain.Serve(p.plain)
	return p
}

func (p *Proxy) Listen(host string, port int) error {
	ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	p.lnMu.Lock()
	old := p.ln
	p.ln = ln
	p.lnMu.Unlock()
	if old != nil {
		old.Close()
	}
	go p.srv.Serve(ln)
	return nil
}

func (p *Proxy) Relisten(lan bool) error {
	host := "127.0.0.1"
	if lan {
		host = "0.0.0.0"
	}
	p.lnMu.Lock()
	old := p.ln
	p.ln = nil
	p.lnMu.Unlock()
	if old != nil {
		old.Close()
	}
	return p.Listen(host, p.port)
}

func (p *Proxy) serveMain(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	if !r.URL.IsAbs() {
		p.serveCertPage(w, r)
		return
	}
	scheme := strings.ToLower(r.URL.Scheme)
	host, port := core.SplitHostPort(r.URL.Host, core.DefaultPort(scheme))
	p.handle(w, r, infoFrom(r.Context()), scheme, host, port)
}

func (p *Proxy) serveTunneled(w http.ResponseWriter, r *http.Request) {
	ci := infoFrom(r.Context())
	host, port := ci.host, ci.port
	if r.Host != "" {
		host, port = core.SplitHostPort(r.Host, ci.port)
	}
	p.handle(w, r, ci, ci.scheme, host, port)
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	parent := infoFrom(r.Context())
	host, port := core.SplitHostPort(r.Host, 443)
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "CONNECT not supported here", http.StatusMethodNotAllowed)
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	s := p.cfg.Get()
	ci := &connInfo{client: parent.client, host: host, port: port}
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		conn.Close()
		return
	}

	br := bufio.NewReaderSize(brw.Reader, 20<<10)
	pc := &peekConn{Conn: conn, r: br}
	if port != 443 {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	}
	first, err := br.Peek(1)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			p.tunnel(pc, ci, &s, "the app waits for the server to speak first (not HTTP)")
		} else {
			conn.Close()
		}
		return
	}
	if first[0] == 0x16 {
		hello := readHello(br, conn)
		if hello.SNI != "" {
			ci.sni = strings.ToLower(hello.SNI)
		}
		reason := p.passReason(&s, ci, hello)
		Debugf("CONNECT %s:%d sni=%q alpn=%v app=%q pass=%q", host, port, hello.SNI, hello.ALPN, ci.client.App(), reason)
		if reason != "" {
			p.tunnel(pc, ci, &s, reason)
			return
		}
		p.mitmTLS(pc, ci)
		return
	}
	if !peekHTTP(br, conn) {
		p.tunnel(pc, ci, &s, "not HTTP")
		return
	}
	ci.scheme = "http"
	p.infos.Store(net.Conn(pc), ci)
	p.plain.push(pc)
}

func readHello(br *bufio.Reader, conn net.Conn) clientHello {
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	hdr, err := br.Peek(5)
	if err != nil {
		return clientHello{}
	}
	n := min(int(binary.BigEndian.Uint16(hdr[3:5])), 16384)
	rec, err := br.Peek(5 + n)
	if err != nil {
		return clientHello{}
	}
	h, _ := parseClientHello(rec)
	return h
}

func peekHTTP(br *bufio.Reader, conn net.Conn) bool {
	b, _ := br.Peek(min(br.Buffered(), 16))
	if len(b) < 8 {
		conn.SetReadDeadline(time.Now().Add(time.Second))
		b, _ = br.Peek(8)
		conn.SetReadDeadline(time.Time{})
	}
	return looksLikeHTTP(b)
}

func (ci *connInfo) name() string {
	if ci.sni != "" && net.ParseIP(ci.sni) == nil {
		return ci.sni
	}
	return ci.host
}

func (p *Proxy) passReason(s *core.Settings, ci *connInfo, hello clientHello) string {
	name, port := ci.name(), ci.port
	if isCertHost(name) {
		return ""
	}
	switch {
	case s.SSLMode == "off":
		return "HTTPS decryption is off"
	case core.HostMatches(s.SSLExclude, name, port):
		return "host excluded from decryption"
	case s.SSLMode == "list" && !core.HostMatches(s.SSLInclude, name, port):
		return "host not in the decrypt list"
	}
	if app := ci.client.App(); app != "" && contains(s.SSLExcludeApps, app) {
		return app + " is excluded from decryption"
	}
	if s.AutoPassPinned {
		if r := p.Pins.Reason(name); r != "" {
			return r
		}
		if contains(s.LearnedPins, name) {
			return "app rejected the certificate (pinning)"
		}
	}
	if s.SkipKnown && core.HostMatches(KnownPinned, name, port) {
		return "known to pin certificates"
	}
	if !hello.speaksHTTP() {
		return "not HTTP (" + strings.Join(hello.ALPN, ", ") + ")"
	}
	return ""
}

func (p *Proxy) mitmTLS(conn net.Conn, ci *connInfo) {
	cfg := p.tlsBase.Clone()
	cfg.GetCertificate = func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		name := h.ServerName
		if name == "" {
			name = ci.host
		}
		return p.ca.LeafFor(h, name)
	}
	tc := tls.Server(conn, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		p.handshakeFailed(ci, err)
		tc.Close()
		return
	}
	ci.scheme = "https"
	if proto := tc.ConnectionState().NegotiatedProtocol; proto == "h2" || proto == "http/1.1" {
		p.infos.Store(net.Conn(tc), ci)
		p.mitm.push(tc)
		return
	}

	br := bufio.NewReaderSize(tc, 16<<10)
	pc := &peekConn{Conn: tc, r: br}
	tc.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := br.Peek(1)
	tc.SetReadDeadline(time.Time{})
	if err == nil && peekHTTP(br, tc) {
		p.infos.Store(net.Conn(pc), ci)
		p.plain.push(pc)
		return
	}
	p.relayTLS(pc, ci)
}

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request, ci *connInfo, scheme, host string, port int) {
	if isCertHost(host) {
		p.serveCertPage(w, r)
		return
	}
	s := p.cfg.Get()
	if isWebSocket(r) {
		p.handleWebSocket(w, r, ci, scheme, host, port, &s)
		return
	}
	f := &core.Flow{Kind: "http", Start: time.Now(), State: "pending", Method: r.Method, Scheme: scheme, Host: host,
		Port: port, Path: r.URL.RequestURI(), Proto: r.Proto, Client: ci.client.addr, App: ci.client.App(), MaxBody: s.MaxBody()}
	f.ReqHeader = r.Header.Clone()
	f.ReqHeader.Set("Host", r.Host)
	if len(r.TransferEncoding) > 0 {
		f.ReqHeader.Set("Transfer-Encoding", strings.Join(r.TransferEncoding, ", "))
	}
	m := core.MatchRules(s.Rules, f.Method, f.URL(), host, port)
	if s.Recording && !(m.AllowActive && !m.Allowed) && !p.isOwnUI(host, port) {
		p.store.Add(f)
	}
	ctx := r.Context()
	if r.ProtoMajor == 2 && r.TLS == nil && scheme == "http" {
		ctx = context.WithValue(ctx, ctxH2C{}, true)
	}
	p.Exchange(w, ctx, f, r.Body, r.ContentLength, m, &s)
}

func (p *Proxy) isOwnUI(host string, port int) bool {
	return port == p.uiPort && (host == "127.0.0.1" || host == "localhost" || host == "::1")
}

func (p *Proxy) finish(f *core.Flow) {
	f.Lock()
	if f.End.IsZero() {
		f.End = time.Now()
	}
	if f.State != "error" {
		f.State = "done"
	}
	f.Unlock()
	p.store.Finished(f)
}

var MethodsWithBody = map[string]bool{"POST": true, "PUT": true, "PATCH": true}

func (p *Proxy) Exchange(w http.ResponseWriter, ctx context.Context, f *core.Flow, body io.Reader, clen int64, m *core.Matched, s *core.Settings) {
	defer p.finish(f)
	store := p.store

	if m.Block != nil {
		f.Tag("blocked")
		if body != nil {
			io.Copy(io.Discard, io.LimitReader(body, 1<<20))
		}
		if m.Block.Action == "drop" {
			f.Fail("Blocked by rule (connection dropped)")
			panic(http.ErrAbortHandler)
		}
		name := m.Block.Name
		if name == "" {
			name = m.Block.Pattern
		}
		p.deliver(w, ctx, f, m, s, 403, http.Header{"Content-Type": {"text/plain; charset=utf-8"}, "X-Sift": {"blocked"}}, nil, []byte("Blocked by Sift rule: "+name+"\n"), nil, 0)
		return
	}

	var reqBody []byte
	buffered := true
	if body != nil && body != http.NoBody {
		if m.NeedsFullRequest() || (clen >= 0 && clen <= int64(f.MaxBody)) {
			b, err := io.ReadAll(io.LimitReader(body, 256<<20))
			if err != nil {
				f.Fail("The app closed the connection while sending the body")
				return
			}
			reqBody = b
			f.Lock()
			f.ReqSize = int64(len(b))
			f.ReqBody = b[:min(len(b), f.MaxBody)]
			f.ReqTrunc = len(b) > f.MaxBody
			f.Unlock()
		} else {
			buffered = false
		}
	}

	f.Lock()
	if s.NoCache {
		f.ReqHeader.Del("If-None-Match")
		f.ReqHeader.Del("If-Modified-Since")
		f.ReqHeader.Set("Cache-Control", "no-cache")
		f.ReqHeader.Set("Pragma", "no-cache")
	}
	for _, rw := range m.Rewrites {
		if rw.Target == "request" {
			if rw.Op == "replace_body" && !buffered {
				continue
			}
			applyRewrite(rw, f.ReqHeader, &reqBody, nil)
			f.Tags = core.AppendTag(f.Tags, "rewrite")
		}
	}
	if m.MapRemote != nil && applyMapRemote(f, m.MapRemote) {
		f.Tags = core.AppendTag(f.Tags, "map remote")
	}
	f.Unlock()
	store.Touch(f)

	if m.BpRequest != nil {
		d := p.bps.Pause(ctx, p.store, f, "request", m.BpRequest, reqBody)
		if d.Action == "abort" {
			f.Fail("Aborted at breakpoint")
			panic(http.ErrAbortHandler)
		}
		if d.Action == "execute" {
			applyRequestEdits(f, d, &reqBody)
			buffered = true
		}
	}

	if m.MapLocal != nil {
		f.Tag("map local")
		status, hdr, data := buildMapLocal(m.MapLocal, f.Path)
		p.deliver(w, ctx, f, m, s, status, hdr, nil, data, nil, 0)
		return
	}

	latency, down, up, throttled := s.ThrottleProfile()
	if throttled {
		if hosts := strings.Fields(strings.ReplaceAll(s.Throttle.Hosts, ",", " ")); len(hosts) > 0 && !core.HostMatches(hosts, f.Host, f.Port) {
			throttled = false
		}
	}
	if throttled {
		f.Tag("throttled")
		if !sleepCtx(ctx, latency) {
			f.Fail("The app closed the connection")
			return
		}
	} else {
		down, up = 0, 0
	}

	f.Lock()
	method, scheme, path := f.Method, f.Scheme, f.Path
	target := scheme + "://" + core.HostPort(f.Host, f.Port, scheme) + path
	hdr := f.ReqHeader.Clone()
	f.Unlock()
	hostHeader := hdr.Get("Host")
	hdr.Del("Host")
	removeHopHeaders(hdr)

	var rd io.Reader
	length := int64(0)
	if buffered {
		if len(reqBody) > 0 || MethodsWithBody[method] {
			rd, length = bytes.NewReader(reqBody), int64(len(reqBody))
			hdr.Del("Expect")
		}
	} else {
		rd, length = &captureReader{r: body, f: f, store: store}, clen
	}
	if rd != nil && up > 0 {
		rd = &rateReader{ctx: ctx, r: rd, bps: up, start: time.Now()}
	}
	traceCtx := httptrace.WithClientTrace(ctx, NewTrace(f))
	req, err := http.NewRequestWithContext(traceCtx, method, target, rd)
	if err != nil {
		f.Fail("Invalid request URL: " + err.Error())
		http.Error(w, "Sift: invalid request URL", http.StatusBadRequest)
		return
	}
	req.Header = hdr
	req.ContentLength = length
	if rd == nil {
		req.Body = http.NoBody
	}
	if hostHeader != "" {
		req.Host = hostHeader
	}

	resp, err := p.up.RoundTrip(req)
	if err != nil {
		if ctx.Err() != nil {
			f.Fail("The app closed the connection")
			return
		}
		msg := DescribeErr(err, f.Host, f.Port)
		f.Fail(msg)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Sift-Error", "1")
		w.WriteHeader(http.StatusBadGateway)
		io.WriteString(w, "Sift: "+msg+"\n")
		return
	}
	f.Lock()
	f.ResProto = resp.Proto
	f.Unlock()
	p.deliver(w, ctx, f, m, s, resp.StatusCode, resp.Header, resp.Body, nil, resp.Trailer, down)
}

func (p *Proxy) deliver(w http.ResponseWriter, ctx context.Context, f *core.Flow, m *core.Matched, s *core.Settings,
	status int, hdr http.Header, body io.ReadCloser, full []byte, trailer http.Header, down int) {
	if body != nil {
		defer body.Close()
	}
	if hdr == nil {
		hdr = http.Header{}
	}
	if s.NoCache {
		hdr.Del("ETag")
		hdr.Del("Last-Modified")
		hdr.Del("Expires")
		hdr.Set("Cache-Control", "no-store")
	}
	for _, rw := range m.Rewrites {
		if rw.Target == "response" && rw.Op != "replace_body" {
			applyRewrite(rw, hdr, nil, &status)
			f.Tag("rewrite")
		}
	}
	noBody := f.Method == "HEAD" || status == 204 || status == 304 || status < 200

	if !noBody && full == nil && body != nil && m.NeedsFullResponse() {
		b, _ := io.ReadAll(io.LimitReader(body, 256<<20))
		body.Close()
		body = nil
		if enc := hdr.Get("Content-Encoding"); enc != "" {
			if dec, ok := core.DecodeBody(b, enc); ok {
				b = dec
				hdr.Del("Content-Encoding")
			}
		}
		for _, rw := range m.Rewrites {
			if rw.Target == "response" && rw.Op == "replace_body" {
				applyRewrite(rw, hdr, &b, nil)
				f.Tag("rewrite")
			}
		}
		full = b
		if m.BpResponse != nil {
			f.Lock()
			f.Status, f.ResHeader = status, hdr.Clone()
			f.Unlock()
			d := p.bps.Pause(ctx, p.store, f, "response", m.BpResponse, full)
			if d.Action == "abort" {
				f.Fail("Aborted at breakpoint")
				panic(http.ErrAbortHandler)
			}
			if d.Action == "execute" {
				if d.Status >= 100 && d.Status <= 999 {
					status = d.Status
				}
				hdr = ParseHeaderText(d.Headers)
				if d.EditBody {
					full = []byte(fixNewlines(d.Body, full))
				}
			}
		}
	}
	if full != nil && !noBody {
		hdr.Set("Content-Length", strconv.Itoa(len(full)))
		hdr.Del("Transfer-Encoding")
	}
	if status < 100 || status > 999 {
		status = 502
	}

	f.Lock()
	f.Status = status
	f.StatusText = http.StatusText(status)
	f.ResHeader = hdr.Clone()
	if f.ResProto == "" {
		f.ResProto = "HTTP/1.1"
	}
	f.State = "receiving"
	if full != nil && body == nil && hdr.Get("Content-Encoding") == "" {
		f.Decoded = true
	}
	f.Unlock()
	p.store.Touch(f)

	out := w.Header()
	for k, vv := range hdr {
		if !isHopHeader(k) {
			out[k] = vv
		}
	}
	for k := range trailer {
		out.Add("Trailer", k)
	}
	w.WriteHeader(status)
	if noBody {
		return
	}

	var src io.Reader
	if full != nil {
		src = bytes.NewReader(full)
	} else if body != nil {
		src = body
	} else {
		return
	}
	if down > 0 {
		src = &rateReader{ctx: ctx, r: src, bps: down, start: time.Now()}
	}
	rc := http.NewResponseController(w)
	bufp := p.bufs.Get().(*[]byte)
	defer p.bufs.Put(bufp)
	buf := *bufp
	recvStart := time.Now()
	defer func() {
		d := time.Since(recvStart)
		f.Lock()
		f.Timing.Receive = d
		f.Unlock()
	}()
	for {
		n, err := src.Read(buf)
		if n > 0 {
			f.Capture(true, buf[:n])
			p.store.Touch(f)
			if _, werr := w.Write(buf[:n]); werr != nil {
				f.Fail("The app closed the connection before the response finished")
				return
			}
			_ = rc.Flush()
		}
		if err != nil {
			if err != io.EOF {
				if ctx.Err() != nil {
					f.Fail("The app closed the connection before the response finished")
				} else {
					f.Fail("The server closed the connection early: " + err.Error())
				}
			}
			break
		}
	}
	for k, vv := range trailer {
		out[k] = vv
		f.Lock()
		if f.ResTrailer == nil {
			f.ResTrailer = http.Header{}
		}
		f.ResTrailer[k] = vv
		f.Unlock()
	}
}

var hopHeaders = map[string]bool{
	"Connection": true, "Proxy-Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
	"Proxy-Authorization": true, "Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true,
}

func isHopHeader(k string) bool { return hopHeaders[http.CanonicalHeaderKey(k)] }

func removeHopHeaders(h http.Header) {
	te := h.Get("Te")
	for _, f := range h.Values("Connection") {
		for _, name := range strings.Split(f, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for k := range hopHeaders {
		h.Del(k)
	}
	if strings.Contains(strings.ToLower(te), "trailers") {
		h.Set("Te", "trailers")
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

type captureReader struct {
	r     io.Reader
	f     *core.Flow
	store *core.Store
}

func (c *captureReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	if n > 0 {
		c.f.Capture(false, b[:n])
		c.store.Touch(c.f)
	}
	return n, err
}

type rateReader struct {
	ctx   context.Context
	r     io.Reader
	bps   int
	start time.Time
	n     int64
}

func (rr *rateReader) Read(b []byte) (int, error) {
	if len(b) > 16<<10 {
		b = b[:16<<10]
	}
	n, err := rr.r.Read(b)
	rr.n += int64(n)
	want := time.Duration(float64(rr.n) / float64(rr.bps) * float64(time.Second))
	if !sleepCtx(rr.ctx, want-time.Since(rr.start)) {
		return n, context.Canceled
	}
	return n, err
}

func NewTrace(f *core.Flow) *httptrace.ClientTrace {
	var mu sync.Mutex
	var dns, conn, tlsT, got, wrote time.Time
	set := func(fn func(t *core.Timing)) { f.Lock(); fn(&f.Timing); f.Unlock() }
	return &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { mu.Lock(); dns = time.Now(); mu.Unlock() },
		DNSDone: func(httptrace.DNSDoneInfo) {
			mu.Lock()
			d := time.Since(dns)
			mu.Unlock()
			set(func(t *core.Timing) { t.DNS = d })
		},
		ConnectStart: func(string, string) { mu.Lock(); conn = time.Now(); mu.Unlock() },
		ConnectDone: func(_, _ string, err error) {
			mu.Lock()
			d := time.Since(conn)
			mu.Unlock()
			if err == nil {
				set(func(t *core.Timing) { t.Connect = d })
			}
		},
		TLSHandshakeStart: func() { mu.Lock(); tlsT = time.Now(); mu.Unlock() },
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			mu.Lock()
			d := time.Since(tlsT)
			mu.Unlock()
			set(func(t *core.Timing) { t.TLS = d })
		},
		GotConn: func(info httptrace.GotConnInfo) {
			mu.Lock()
			got = time.Now()
			mu.Unlock()
			f.Lock()
			f.Timing.Reused = info.Reused
			f.Server = info.Conn.RemoteAddr().String()
			f.Unlock()
		},
		WroteRequest: func(httptrace.WroteRequestInfo) {
			mu.Lock()
			wrote = time.Now()
			d := wrote.Sub(got)
			mu.Unlock()
			set(func(t *core.Timing) { t.Send = d })
		},
		GotFirstResponseByte: func() {
			mu.Lock()
			d := time.Since(wrote)
			mu.Unlock()
			set(func(t *core.Timing) { t.Wait = d })
		},
	}
}

func DescribeErr(err error, host string, port int) string {
	var dnsErr *net.DNSError
	var unknownCA x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invalid x509.CertificateInvalidError
	var verifyErr *tls.CertificateVerificationError
	switch {
	case errors.As(err, &dnsErr):
		return "DNS lookup failed for " + host
	case errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(err.Error(), "actively refused"):
		return fmt.Sprintf("Connection refused by %s:%d", host, port)
	case errors.As(err, &unknownCA), errors.As(err, &hostErr), errors.As(err, &invalid), errors.As(err, &verifyErr):
		return "The server's certificate isn't valid (" + err.Error() + "). Turn off \"Verify server certificates\" in core.Settings to allow it."
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "timeout"):
		return fmt.Sprintf("Timed out connecting to %s:%d", host, port)
	}
	return err.Error()
}

func ParseHeaderText(text string) http.Header {
	h := http.Header{}
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if k = strings.TrimSpace(k); ok && k != "" {
			h.Add(k, strings.TrimSpace(v))
		}
	}
	return h
}

func fixNewlines(edited string, original []byte) string {
	if !bytes.Contains(original, []byte("\r\n")) {
		return strings.ReplaceAll(edited, "\r\n", "\n")
	}
	return edited
}

func applyRewrite(r *core.Rule, h http.Header, body *[]byte, status *int) {
	key := strings.TrimSpace(r.Key)
	switch r.Op {
	case "set_header":
		if key != "" {
			h.Set(key, r.Value)
		}
	case "remove_header":
		if key != "" {
			h.Del(key)
		}
	case "set_status":
		if n, err := strconv.Atoi(strings.TrimSpace(r.Value)); err == nil && status != nil && n >= 100 && n <= 999 {
			*status = n
		}
	case "replace_body":
		if body == nil || *body == nil || r.Find == "" {
			return
		}
		if r.FindRegex {
			if rx, err := regexp.Compile(r.Find); err == nil {
				*body = rx.ReplaceAll(*body, []byte(r.Replace))
			}
		} else {
			*body = bytes.ReplaceAll(*body, []byte(r.Find), []byte(r.Replace))
		}
		h.Del("Content-Length")
	}
}

func applyMapRemote(f *core.Flow, r *core.Rule) bool {
	to := strings.TrimSpace(r.To)
	if to == "" {
		return false
	}
	if !strings.Contains(to, "://") {
		to = "http://" + to
	}
	u, err := url.Parse(to)
	if err != nil || u.Hostname() == "" {
		return false
	}
	f.MappedFrom = f.URL()
	_, query, _ := strings.Cut(f.Path, "?")
	f.Scheme = strings.ToLower(u.Scheme)
	f.Host = strings.ToLower(u.Hostname())
	f.Port = core.DefaultPort(f.Scheme)
	if u.Port() != "" {
		f.Port, _ = strconv.Atoi(u.Port())
	}
	if u.Path != "" && u.Path != "/" {
		q := u.RawQuery
		if q == "" {
			q = query
		}
		f.Path = u.EscapedPath()
		if q != "" {
			f.Path += "?" + q
		}
	}
	if !r.PreserveHost {
		f.ReqHeader.Set("Host", core.HostPort(f.Host, f.Port, f.Scheme))
	}
	return true
}

func applyRequestEdits(f *core.Flow, d core.Decision, body *[]byte) {
	f.Lock()
	defer f.Unlock()
	if m := strings.ToUpper(strings.TrimSpace(d.Method)); m != "" {
		f.Method = m
	}
	if u, err := url.Parse(strings.TrimSpace(d.URL)); err == nil && u.Host != "" {
		f.Scheme = strings.ToLower(u.Scheme)
		f.Host, f.Port = core.SplitHostPort(u.Host, core.DefaultPort(f.Scheme))
		f.Path = u.RequestURI()
	}
	f.ReqHeader = ParseHeaderText(d.Headers)
	if f.ReqHeader.Get("Host") == "" {
		f.ReqHeader.Set("Host", core.HostPort(f.Host, f.Port, f.Scheme))
	}
	if d.EditBody {
		*body = []byte(fixNewlines(d.Body, *body))
		f.ReqBody = *body
		f.ReqSize = int64(len(*body))
	}
}

func buildMapLocal(r *core.Rule, reqPath string) (int, http.Header, []byte) {
	status := r.Status
	if status < 100 || status > 999 {
		status = 200
	}
	hdr := ParseHeaderText(r.Headers)
	data := []byte(r.Body)
	ctype := ""
	if file := strings.Trim(strings.TrimSpace(r.File), `"`); file != "" {
		path := file
		if st, err := os.Stat(path); err == nil && st.IsDir() {
			p, _, _ := strings.Cut(reqPath, "?")
			p, _ = url.PathUnescape(p)
			path = filepath.Join(file, filepath.FromSlash(p))
			if st, err := os.Stat(path); err == nil && st.IsDir() {
				path = filepath.Join(path, "index.html")
			}
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return 404, http.Header{"Content-Type": {"text/plain; charset=utf-8"}}, []byte("Sift Map Local: can't read " + path + "\n")
		}
		data = b
		ctype = mime.TypeByExtension(filepath.Ext(path))
	}
	if hdr.Get("Content-Type") == "" {
		if ctype == "" {
			t := bytes.TrimSpace(data)
			switch {
			case len(t) > 0 && (t[0] == '{' || t[0] == '['):
				ctype = "application/json; charset=utf-8"
			case len(t) > 0 && t[0] == '<':
				ctype = "text/html; charset=utf-8"
			default:
				ctype = "text/plain; charset=utf-8"
			}
		}
		hdr.Set("Content-Type", ctype)
	}
	hdr.Set("X-Sift", "map-local")
	return status, hdr, data
}

type countWriter struct {
	w     io.Writer
	n     interface{ Add(int64) int64 }
	f     *core.Flow
	store *core.Store
}

func (c *countWriter) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	c.n.Add(int64(n))
	c.store.Touch(c.f)
	return n, err
}

func (p *Proxy) tunnel(conn net.Conn, ci *connInfo, s *core.Settings, reason string) {
	f := p.tunnelFlow(ci, s, reason)
	up, err := p.dialer.Dial("tcp", net.JoinHostPort(ci.host, strconv.Itoa(ci.port)))
	if err != nil {
		conn.Close()
		f.Fail(DescribeErr(err, ci.host, ci.port))
		p.finish(f)
		return
	}
	p.pipe(f, conn, up)
}

func (p *Proxy) relayTLS(conn net.Conn, ci *connInfo) {
	s := p.cfg.Get()
	f := p.tunnelFlow(ci, &s, "decrypted, but not HTTP: relayed as raw TLS")
	up, err := tls.DialWithDialer(p.dialer, "tcp", net.JoinHostPort(ci.host, strconv.Itoa(ci.port)),
		&tls.Config{ServerName: ci.name(), InsecureSkipVerify: !s.VerifyUpstream, MinVersion: tls.VersionTLS10, CipherSuites: AllCipherSuites()})
	if err != nil {
		conn.Close()
		f.Fail(DescribeErr(err, ci.host, ci.port))
		p.finish(f)
		return
	}
	p.pipe(f, conn, up)
}

func (p *Proxy) tunnelFlow(ci *connInfo, s *core.Settings, reason string) *core.Flow {
	f := &core.Flow{Kind: "tunnel", Start: time.Now(), State: "open", Method: "CONNECT", Scheme: "https", Host: ci.name(),
		Port: ci.port, Client: ci.client.addr, App: ci.client.App(), Note: reason}
	if s.Recording && s.ShowTunnels {
		p.store.Add(f)
	}
	return f
}

func (p *Proxy) pipe(f *core.Flow, conn, up net.Conn) {
	f.Lock()
	f.Server = up.RemoteAddr().String()
	f.Unlock()
	done := make(chan struct{})
	go func() {
		io.Copy(&countWriter{up, &f.BytesUp, f, p.store}, conn)
		up.Close()
		conn.Close()
		close(done)
	}()
	io.Copy(&countWriter{conn, &f.BytesDown, f, p.store}, up)
	up.Close()
	conn.Close()
	<-done
	p.finish(f)
}

func (p *Proxy) handshakeFailed(ci *connInfo, err error) {
	Debugf("TLS handshake with app failed for %s: %v", ci.name(), err)
	s := p.cfg.Get()
	msg := strings.ToLower(err.Error())

	alert := strings.Contains(msg, "remote error") || strings.Contains(msg, "bad record mac") ||
		strings.Contains(msg, "decryption failed")
	hungUp := strings.Contains(msg, "eof") || strings.Contains(msg, "reset") || strings.Contains(msg, "closed") ||
		strings.Contains(msg, "forcibly") || strings.Contains(msg, "aborted")
	if !alert && !hungUp {
		return
	}
	name := ci.name()
	trusted := p.ca.Trusted() == 1
	passed := s.AutoPassPinned && p.Pins.Failed(name, alert, trusted)
	if passed {
		if alert && trusted && !contains(s.LearnedPins, name) {
			p.cfg.Update(func(s *core.Settings) { s.LearnedPins = append(s.LearnedPins, name) })
		}
		p.store.Hub.StateChanged()
	}
	if !s.Recording {
		return
	}
	if last, ok := p.tlsFails.Load(name); ok && time.Since(last.(time.Time)) < 30*time.Second && !passed {
		return
	}
	p.tlsFails.Store(name, time.Now())
	text := "The app rejected Sift's certificate."
	switch {
	case !trusted:
		text = "The app rejected Sift's certificate because it isn't trusted yet. Install it from the Certificate dialog."
	case alert:
		text = "The app rejected Sift's certificate: it pins its server's real certificate."
	}
	if passed {
		text += " Sift now lets this host through untouched, so the app keeps working."
	}
	now := time.Now()
	f := &core.Flow{Kind: "tls", Start: now, End: now, State: "error", Method: "TLS", Scheme: "https", Host: name,
		Port: ci.port, Client: ci.client.addr, App: ci.client.App(), Err: text}
	p.store.Add(f)
	p.store.Finished(f)
}

func isCertHost(h string) bool {
	return h == "sift.cert" || h == "cert.sift" || h == "sift.local"
}

func (p *Proxy) serveCertPage(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasSuffix(r.URL.Path, ".pac"):

		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		fmt.Fprintf(w, `function FindProxyForURL(url, host) {
  if (isPlainHostName(host) || host == "localhost" || shExpMatch(host, "127.*")) return "DIRECT";
  return "PROXY %s; DIRECT";
}
`, r.Host)
		return
	case strings.HasSuffix(r.URL.Path, ".pem"):
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="sift-ca.pem"`)
		w.Write(p.ca.PEM())
	case strings.HasSuffix(r.URL.Path, ".cer") || strings.HasSuffix(r.URL.Path, ".crt"):
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", `attachment; filename="sift-ca.cer"`)
		w.Write(p.ca.DER())
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><meta name="viewport" content="width=device-width"><title>Sift</title>
<body style="font:15px system-ui;max-width:520px;margin:40px auto;padding:0 16px;line-height:1.5">
<h2>Sift proxy</h2><p>Install the Sift certificate on this device to inspect its HTTPS traffic.</p>
<p><a href="/sift-ca.cer">Download sift-ca.cer</a> (Windows, Android)<br><a href="/sift-ca.pem">Download sift-ca.pem</a> (macOS, iOS, Linux, Firefox)</p>
<p>On iOS, also enable it under Settings → General → About → Certificate Trust Settings.</p></body>`)
	}
}

func prettyApp(exe string) string {
	if exe == "" {
		return ""
	}
	base := strings.TrimSuffix(exe, filepath.Ext(exe))
	known := map[string]string{
		"chrome": "Chrome", "msedge": "Edge", "firefox": "Firefox", "brave": "Brave", "opera": "Opera",
		"python": "Python", "pythonw": "Python", "py": "Python", "node": "Node.js", "curl": "curl", "discord": "Discord",
		"spotify": "Spotify", "code": "VS Code", "powershell": "PowerShell", "pwsh": "PowerShell", "slack": "Slack",
		"ms-teams": "Teams", "steam": "Steam", "steamwebhelper": "Steam", "go": "Go", "java": "Java", "javaw": "Java",
	}
	if v, ok := known[strings.ToLower(base)]; ok {
		return v
	}
	return base
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

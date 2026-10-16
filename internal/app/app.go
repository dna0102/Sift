package app

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"sift/internal/ai"
	"sift/internal/apk"
	"sift/internal/ca"
	"sift/internal/core"
	"sift/internal/emulator"
	"sift/internal/mcp"
	"sift/internal/proxy"
	"sift/internal/scan"
	"sift/internal/sender"
	"sift/internal/sysproxy"
)

const Version = "2.2.2"

type App struct {
	Cfg       *core.Config
	Store     *core.Store
	CA        *ca.CA
	Sys       *sysproxy.SystemProxy
	Bps       *core.Breakpoints
	Proxy     *proxy.Proxy
	Tools     *apk.Tools
	Mobile    *apk.MobileStore
	Analyser  *apk.Analyser
	Emulator  *emulator.Emulator
	Sender    *sender.Sender
	Scanner   *scan.Engine
	AI        *ai.Manager
	MCP       *mcp.Server
	ProxyPort int
	UIPort    int
	Home      string
}

type State struct {
	Version      string   `json:"version"`
	Recording    bool     `json:"recording"`
	SystemProxy  bool     `json:"systemProxy"`
	SSLMode      string   `json:"sslMode"`
	Throttle     string   `json:"throttle"`
	NoCache      bool     `json:"noCache"`
	Theme        string   `json:"theme"`
	Trusted      int      `json:"trusted"`
	ProxyPort    int      `json:"proxyPort"`
	LAN          bool     `json:"lan"`
	Paused       int      `json:"paused"`
	Pinned       []string `json:"pinned"`
	Rules        int      `json:"rules"`
	PassedHosts  int      `json:"passedHosts"`
	ExcludedApps []string `json:"excludedApps"`
}

func (a *App) State() State {
	s := a.Cfg.Get()
	rules := 0
	for _, r := range s.Rules {
		if r.Enabled {
			rules++
		}
	}
	pinned := s.Pinned
	if pinned == nil {
		pinned = []string{}
	}
	return State{Version: Version, Recording: s.Recording, SystemProxy: s.SystemProxy, SSLMode: s.SSLMode, Throttle: s.Throttle.Preset,
		NoCache: s.NoCache, Theme: s.Theme, Trusted: a.CA.Trusted(), ProxyPort: a.ProxyPort, LAN: s.AllowLAN,
		Paused: a.Bps.Count(), Pinned: pinned, Rules: rules,
		PassedHosts: len(a.PassedHosts()), ExcludedApps: append([]string{}, s.SSLExcludeApps...)}
}

func (a *App) PassedHosts() []proxy.PinInfo {
	if a.Proxy == nil {
		return nil
	}
	list := a.Proxy.Pins.List()
	seen := map[string]bool{}
	for _, p := range list {
		seen[p.Host] = true
	}
	for _, h := range a.Cfg.Get().LearnedPins {
		if !seen[h] {
			list = append(list, proxy.PinInfo{Host: h, Reason: "app rejected the certificate (remembered)"})
		}
	}
	return list
}

func (a *App) SetSystemProxy(on bool) error {
	var err error
	if on {
		err = a.Sys.Enable(a.ProxyPort, a.Cfg.Get().Bypass)
	} else {
		a.Sys.Disable()
	}
	if err == nil {
		a.Cfg.Update(func(s *core.Settings) { s.SystemProxy = on })
	}
	a.Store.Hub.StateChanged()
	return err
}

type discardWriter struct{ h http.Header }

func (d *discardWriter) Header() http.Header         { return d.h }
func (d *discardWriter) Write(b []byte) (int, error) { return len(b), nil }
func (d *discardWriter) WriteHeader(int)             {}

func (a *App) send(f *core.Flow, body []byte) {
	s := a.Cfg.Get()
	f.MaxBody = s.MaxBody()
	a.Store.Add(f)
	m := core.MatchRules(s.Rules, f.Method, f.URL(), f.Host, f.Port)
	go func() {
		defer func() { recover() }()
		a.Proxy.Exchange(&discardWriter{h: http.Header{}}, context.Background(), f, bytes.NewReader(body), int64(len(body)), m, &s)
	}()
}

func (a *App) Replay(src *core.Flow) error {
	src.Lock()
	if src.Kind != "http" {
		src.Unlock()
		return fmt.Errorf("only HTTP requests can be replayed")
	}
	if src.ReqTrunc {
		src.Unlock()
		return fmt.Errorf("the request body was too large to keep, so it can't be replayed")
	}
	f := &core.Flow{Kind: "http", Start: time.Now(), State: "pending", Method: src.Method, Scheme: src.Scheme, Host: src.Host,
		Port: src.Port, Path: src.Path, Proto: src.Proto, App: "Sift", Tags: []string{"replay"}, ReqHeader: src.ReqHeader.Clone()}
	body := append([]byte(nil), src.ReqBody...)
	src.Unlock()
	a.send(f, body)
	return nil
}

func (a *App) Compose(method, rawURL, headers, body string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("enter a full http:// or https:// URL")
	}
	scheme := strings.ToLower(u.Scheme)
	host, port := core.SplitHostPort(u.Host, core.DefaultPort(scheme))
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	f := &core.Flow{Kind: "http", Start: time.Now(), State: "pending", Method: method, Scheme: scheme, Host: host, Port: port,
		Path: u.RequestURI(), Proto: "HTTP/1.1", App: "Sift", Tags: []string{"composed"}, ReqHeader: proxy.ParseHeaderText(headers)}
	if f.ReqHeader.Get("Host") == "" {
		f.ReqHeader.Set("Host", u.Host)
	}
	body = strings.ReplaceAll(body, "\r\n", "\n")
	if body != "" {
		f.ReqBody, f.ReqSize = []byte(body), int64(len(body))
	}
	a.send(f, []byte(body))
	return nil
}

type scanRequester struct{ s *sender.Sender }

func NewScanRequester(s *sender.Sender) scan.Requester { return scanRequester{s} }

func (a scanRequester) Do(ctx context.Context, r *scan.Request) (*scan.Response, error) {
	res, err := a.s.Probe(ctx, sender.ProbeReq{Method: r.Method, URL: r.URL, Header: r.Header,
		Body: r.Body, Route: r.Route, Profile: r.Profile, Tag: r.Tag})
	if err != nil {
		return nil, err
	}
	return &scan.Response{Status: res.Status, Header: res.Header, Body: res.Body, Proto: res.Proto,
		Duration: res.Duration, FlowID: res.FlowID, Err: res.Err}, nil
}

func LANAddresses() []string {
	var out []string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
			out = append(out, ipn.IP.String())
		}
	}
	return out
}

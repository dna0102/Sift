// Sift: local HTTP/HTTPS traffic capture and inspection dashboard.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof" // only served when SIFT_PPROF is set
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const Version = "2.0.0"

// App holds everything the proxy and dashboard share.
type App struct {
	cfg       *Config
	store     *Store
	ca        *CA
	sys       *SystemProxy
	bps       *Breakpoints
	proxy     *Proxy
	tools     *Tools
	mobile    *MobileStore
	analyser  *Analyser
	emulator  *Emulator
	proxyPort int
	uiPort    int
	home      string
}

func main() {
	port := flag.Int("port", 0, "proxy port (default 9090)")
	uiPort := flag.Int("ui-port", 0, "dashboard port (default 9091)")
	lan := flag.Bool("lan", false, "let other devices on your network use the proxy")
	sysOn := flag.Bool("system-proxy", false, "route this computer's traffic through Sift on start")
	sysOff := flag.Bool("no-system-proxy", false, "don't turn on the system proxy on start")
	noOpen := flag.Bool("no-open", false, "don't open the dashboard in a browser")
	reset := flag.Bool("reset-proxy", false, "restore the computer's proxy settings and exit")
	guard := flag.Int("guard", 0, "internal: restore proxy settings when this process exits")
	flag.Parse()

	if os.Getenv("SIFT_PPROF") != "" { // performance profiling, for development only
		go http.ListenAndServe("127.0.0.1:6060", nil)
	}
	home := siftHome()
	if *guard > 0 {
		RunGuard(*guard, home)
		return
	}
	sys := NewSystemProxy(home)
	if *reset {
		if sys.Disable() || platformForceOff() {
			fmt.Println("Proxy settings restored.")
		} else {
			fmt.Println("Nothing to restore: Sift wasn't controlling the system proxy.")
		}
		return
	}
	if sys.Disable() {
		fmt.Println("  Restored your proxy settings from a Sift session that didn't close cleanly.")
	}

	cfg := LoadConfig(home)
	s := cfg.Get()
	// Flags apply to this run only; they aren't saved.
	if *port > 0 {
		s.ProxyPort = *port
	}
	if *uiPort > 0 {
		s.UIPort = *uiPort
	}
	if *lan {
		s.AllowLAN = true
	}
	if *sysOn {
		s.SystemProxy = true
	}
	if *sysOff {
		s.SystemProxy = false
	}

	ca, err := LoadCA(home)
	if err != nil {
		fatal("Couldn't create the certificate: " + err.Error())
	}
	app := &App{cfg: cfg, ca: ca, sys: sys, bps: NewBreakpoints(), home: home}
	app.store = NewStore(cfg)
	app.store.hub.StateFn = func() any { return app.State() }
	app.tools = NewTools(home)
	app.mobile = NewMobileStore()
	app.analyser = NewAnalyser(app)
	app.emulator = NewEmulator(app)

	listenHost := "127.0.0.1"
	if s.AllowLAN {
		listenHost = "0.0.0.0"
	}
	app.proxyPort = freePort(listenHost, s.ProxyPort)
	app.uiPort = freePort("127.0.0.1", s.UIPort)
	if app.uiPort == app.proxyPort {
		app.uiPort = freePort("127.0.0.1", app.proxyPort+1)
	}

	app.proxy = NewProxy(app)
	if err := app.proxy.Listen(listenHost, app.proxyPort); err != nil {
		fatal("Couldn't start the proxy: " + err.Error())
	}
	uiLn, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(app.uiPort))
	if err != nil {
		fatal("Couldn't start the dashboard: " + err.Error())
	}
	go (&http.Server{Handler: NewUI(app), ErrorLog: quietLog}).Serve(uiLn)
	go func() {
		ca.CheckTrusted()
		app.store.hub.StateChanged()
	}()

	StartGuard() // restores the proxy settings even if Sift is killed or crashes
	if s.SystemProxy {
		if err := app.SetSystemProxy(true); err != nil {
			fmt.Println("  Couldn't turn on the system proxy:", err)
		}
	}

	dashboard := "http://127.0.0.1:" + strconv.Itoa(app.uiPort)
	sysText := "off (turn it on in the dashboard)"
	if s.SystemProxy {
		sysText = "on: this PC's traffic goes through Sift"
	}
	fmt.Printf("\n  Sift %s\n\n  Dashboard     %s\n  Proxy         %s:%d\n  System proxy  %s\n\n  Ctrl+C to quit. Network settings are restored automatically.\n\n",
		Version, dashboard, listenHost, app.proxyPort, sysText)
	if !*noOpen {
		go func() { time.Sleep(300 * time.Millisecond); openBrowser(dashboard) }()
	}

	// Ctrl+C, closing the console window, logoff and shutdown all arrive here on Windows.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	sys.Disable()
	cfg.Save()
	fmt.Println("  Sift stopped. Network settings restored.")
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "  "+msg)
	os.Exit(1)
}

func siftHome() string {
	if h := os.Getenv("SIFT_HOME"); h != "" {
		os.MkdirAll(h, 0o755)
		return h
	}
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".sift")
	os.MkdirAll(dir, 0o755)
	return dir
}

func freePort(host string, start int) int {
	for p := start; p < start+50; p++ {
		if ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(p))); err == nil {
			ln.Close()
			return p
		}
	}
	fatal(fmt.Sprintf("No free port near %d", start))
	return 0
}

func openBrowser(u string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	case "darwin":
		cmd = exec.Command("open", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	cmd.Start()
}

func lanAddresses() []string {
	var out []string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
			out = append(out, ipn.IP.String())
		}
	}
	return out
}

// ---------------------------------------------------------------- app actions

type State struct {
	Version     string   `json:"version"`
	Recording   bool     `json:"recording"`
	SystemProxy bool     `json:"systemProxy"`
	SSLMode     string   `json:"sslMode"`
	Throttle    string   `json:"throttle"`
	NoCache     bool     `json:"noCache"`
	Theme       string   `json:"theme"`
	Trusted     int      `json:"trusted"`
	ProxyPort   int      `json:"proxyPort"`
	LAN         bool     `json:"lan"`
	Paused      int      `json:"paused"`
	Pinned      []string `json:"pinned"`
	Rules       int      `json:"rules"`
	PassedHosts int      `json:"passedHosts"` // hosts passed through because the app rejects the certificate
	ExcludedApps []string `json:"excludedApps"`
}

func (a *App) State() State {
	s := a.cfg.Get()
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
		NoCache: s.NoCache, Theme: s.Theme, Trusted: a.ca.Trusted(), ProxyPort: a.proxyPort, LAN: s.AllowLAN,
		Paused: a.bps.Count(), Pinned: pinned, Rules: rules,
		PassedHosts: len(a.PassedHosts()), ExcludedApps: append([]string{}, s.SSLExcludeApps...)}
}

// PassedHosts lists hosts passed through because their apps reject Sift's certificate:
// detected this session plus the ones remembered from earlier sessions.
func (a *App) PassedHosts() []PinInfo {
	if a.proxy == nil {
		return nil
	}
	list := a.proxy.pins.List()
	seen := map[string]bool{}
	for _, p := range list {
		seen[p.Host] = true
	}
	for _, h := range a.cfg.Get().LearnedPins {
		if !seen[h] {
			list = append(list, PinInfo{Host: h, Reason: "app rejected the certificate (remembered)"})
		}
	}
	return list
}

func (a *App) SetSystemProxy(on bool) error {
	var err error
	if on {
		err = a.sys.Enable(a.proxyPort, a.cfg.Get().Bypass)
	} else {
		a.sys.Disable()
	}
	if err == nil {
		a.cfg.Update(func(s *Settings) { s.SystemProxy = on })
	}
	a.store.hub.StateChanged()
	return err
}

// discardWriter receives the response for requests Sift sends itself (replay, compose).
type discardWriter struct{ h http.Header }

func (d *discardWriter) Header() http.Header         { return d.h }
func (d *discardWriter) Write(b []byte) (int, error) { return len(b), nil }
func (d *discardWriter) WriteHeader(int)             {}

// send runs a request Sift created itself through the normal pipeline.
func (a *App) send(f *Flow, body []byte) {
	s := a.cfg.Get()
	f.maxBody = s.MaxBody()
	a.store.Add(f)
	m := matchRules(s.Rules, f.Method, f.URL(), f.Host, f.Port)
	go func() {
		defer func() { recover() }() // a "drop connection" rule aborts with a panic
		a.proxy.exchange(&discardWriter{h: http.Header{}}, context.Background(), f, bytes.NewReader(body), int64(len(body)), m, &s)
	}()
}

func (a *App) Replay(src *Flow) error {
	src.mu.Lock()
	if src.Kind != "http" {
		src.mu.Unlock()
		return fmt.Errorf("only HTTP requests can be replayed")
	}
	if src.ReqTrunc {
		src.mu.Unlock()
		return fmt.Errorf("the request body was too large to keep, so it can't be replayed")
	}
	f := &Flow{Kind: "http", Start: time.Now(), State: "pending", Method: src.Method, Scheme: src.Scheme, Host: src.Host,
		Port: src.Port, Path: src.Path, Proto: src.Proto, App: "Sift", Tags: []string{"replay"}, ReqHeader: src.ReqHeader.Clone()}
	body := append([]byte(nil), src.ReqBody...)
	src.mu.Unlock()
	a.send(f, body)
	return nil
}

func (a *App) Compose(method, rawURL, headers, body string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("enter a full http:// or https:// URL")
	}
	scheme := strings.ToLower(u.Scheme)
	host, port := splitHostPort(u.Host, defaultPort(scheme))
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	f := &Flow{Kind: "http", Start: time.Now(), State: "pending", Method: method, Scheme: scheme, Host: host, Port: port,
		Path: u.RequestURI(), Proto: "HTTP/1.1", App: "Sift", Tags: []string{"composed"}, ReqHeader: parseHeaderText(headers)}
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

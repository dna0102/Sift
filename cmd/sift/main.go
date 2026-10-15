package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"sift/internal/apk"
	"sift/internal/app"
	"sift/internal/ca"
	"sift/internal/core"
	"sift/internal/emulator"
	"sift/internal/proxy"
	"sift/internal/sender"
	"sift/internal/sysproxy"
	"sift/internal/ui"
)

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

	if os.Getenv("SIFT_PPROF") != "" {
		go http.ListenAndServe("127.0.0.1:6060", nil)
	}
	home := siftHome()
	if *guard > 0 {
		sysproxy.RunGuard(*guard, home)
		return
	}
	sys := sysproxy.NewSystemProxy(home)
	if *reset {
		if sys.Disable() || sysproxy.ForceOff() {
			fmt.Println("Proxy settings restored.")
		} else {
			fmt.Println("Nothing to restore: Sift wasn't controlling the system proxy.")
		}
		return
	}
	if sys.Disable() {
		fmt.Println("  Restored your proxy settings from a Sift session that didn't close cleanly.")
	}

	cfg := core.LoadConfig(home)
	s := cfg.Get()

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

	ca, err := ca.LoadCA(home)
	if err != nil {
		fatal("Couldn't create the certificate: " + err.Error())
	}
	sift := &app.App{Cfg: cfg, CA: ca, Sys: sys, Bps: core.NewBreakpoints(), Home: home}
	sift.Store = core.NewStore(cfg)
	sift.Store.Hub.StateFn = func() any { return sift.State() }
	sift.Tools = apk.NewTools(home)
	sift.Mobile = apk.NewMobileStore()
	sift.Analyser = apk.NewAnalyser(home, sift.Mobile, sift.Tools)

	listenHost := "127.0.0.1"
	if s.AllowLAN {
		listenHost = "0.0.0.0"
	}
	sift.ProxyPort = freePort(listenHost, s.ProxyPort)
	sift.UIPort = freePort("127.0.0.1", s.UIPort)
	if sift.UIPort == sift.ProxyPort {
		sift.UIPort = freePort("127.0.0.1", sift.ProxyPort+1)
	}

	sift.Emulator = emulator.NewEmulator(sift.Store, sift.Mobile, ca, sift.ProxyPort)
	sift.Sender = sender.NewSender(home, cfg, sift.Store, sift.ProxyPort)

	sift.Proxy = proxy.NewProxy(cfg, sift.Store, ca, sift.Bps, sift.ProxyPort, sift.UIPort)
	sift.Proxy.EmulatorApp = sift.Emulator.EmulatorApp
	if err := sift.Proxy.Listen(listenHost, sift.ProxyPort); err != nil {
		fatal("Couldn't start the proxy: " + err.Error())
	}
	uiLn, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(sift.UIPort))
	if err != nil {
		fatal("Couldn't start the dashboard: " + err.Error())
	}
	go (&http.Server{Handler: ui.NewUI(sift), ErrorLog: proxy.QuietLog}).Serve(uiLn)
	go func() {
		ca.CheckTrusted()
		sift.Store.Hub.StateChanged()
	}()

	sysproxy.StartGuard()
	if s.SystemProxy {
		if err := sift.SetSystemProxy(true); err != nil {
			fmt.Println("  Couldn't turn on the system proxy:", err)
		}
	}

	dashboard := "http://127.0.0.1:" + strconv.Itoa(sift.UIPort)
	sysText := "off (turn it on in the dashboard)"
	if s.SystemProxy {
		sysText = "on: this PC's traffic goes through Sift"
	}
	fmt.Printf("\n  Sift %s\n\n  Dashboard     %s\n  Proxy         %s:%d\n  System proxy  %s\n\n  Ctrl+C to quit. Network settings are restored automatically.\n\n",
		app.Version, dashboard, listenHost, sift.ProxyPort, sysText)
	if !*noOpen {
		go func() { time.Sleep(300 * time.Millisecond); openBrowser(dashboard) }()
	}

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

//go:build !windows

package sysproxy

import (
	"os/exec"
	"runtime"
	"strings"
)

func HideWindow(cmd *exec.Cmd) {}

func AvailableCommitMB() int { return 0 }

func AppForConn(clientPort, proxyPort int) string { return "" }

func readProxySettings() map[string]any {
	out := map[string]any{}
	if runtime.GOOS == "darwin" {
		for _, svc := range macServices() {
			o, _ := exec.Command("networksetup", "-getwebproxy", svc).Output()
			out[svc] = strings.Contains(string(o), "Enabled: Yes")
		}
	} else {
		o, _ := exec.Command("gsettings", "get", "org.gnome.system.proxy", "mode").Output()
		out["mode"] = strings.Trim(strings.TrimSpace(string(o)), "'")
	}
	return out
}

func macServices() []string {
	o, _ := exec.Command("networksetup", "-listallnetworkservices").Output()
	var out []string
	for i, l := range strings.Split(string(o), "\n") {
		if i > 0 && l != "" && !strings.HasPrefix(l, "*") {
			out = append(out, l)
		}
	}
	return out
}

func platformEnableProxy(host string, port int, bypass string) error {
	p := itoa(port)
	if runtime.GOOS == "darwin" {
		for _, svc := range macServices() {
			exec.Command("networksetup", "-setwebproxy", svc, host, p).Run()
			exec.Command("networksetup", "-setsecurewebproxy", svc, host, p).Run()
		}
		return nil
	}
	for _, proto := range []string{"http", "https"} {
		exec.Command("gsettings", "set", "org.gnome.system.proxy."+proto, "host", host).Run()
		exec.Command("gsettings", "set", "org.gnome.system.proxy."+proto, "port", p).Run()
	}
	return exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "manual").Run()
}

func platformRestoreProxy(prev map[string]any) error {
	if runtime.GOOS == "darwin" {
		for _, svc := range macServices() {
			if on, _ := prev[svc].(bool); !on {
				exec.Command("networksetup", "-setwebproxystate", svc, "off").Run()
				exec.Command("networksetup", "-setsecurewebproxystate", svc, "off").Run()
			}
		}
		return nil
	}
	mode, _ := prev["mode"].(string)
	if mode == "" {
		mode = "none"
	}
	return exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", mode).Run()
}

func ForceOff() bool { return false }

func LoopbackStatus() (exempt, total int)    { return 0, 0 }
func SetLoopback(home string, on bool) error { return nil }
func FirewallAllowed() bool                  { return true }
func AllowFirewall() error                   { return nil }
func StartGuard()                            {}
func RunGuard(pid int, home string)          {}

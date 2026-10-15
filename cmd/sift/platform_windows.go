//go:build windows

package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}

// availableCommitMB reports how much memory the OS could still commit (free RAM + free page
// file). This is the real ceiling for a Java heap reservation on Windows.
func availableCommitMB() int {
	type memoryStatusEx struct {
		length               uint32
		memoryLoad           uint32
		totalPhys            uint64
		availPhys            uint64
		totalPageFile        uint64
		availPageFile        uint64
		totalVirtual         uint64
		availVirtual         uint64
		availExtendedVirtual uint64
	}
	var m memoryStatusEx
	m.length = uint32(unsafe.Sizeof(m))
	r, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx").Call(uintptr(unsafe.Pointer(&m)))
	if r == 0 {
		return 0
	}
	// availPageFile already includes available physical memory on Windows.
	return int(m.availPageFile / (1024 * 1024))
}

// ---------------------------------------------------------------- system proxy

const inetKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

func readProxySettings() map[string]any {
	out := map[string]any{"ProxyEnable": 0, "ProxyServer": nil, "ProxyOverride": nil, "AutoConfigURL": nil}
	k, err := registry.OpenKey(registry.CURRENT_USER, inetKey, registry.QUERY_VALUE)
	if err != nil {
		return out
	}
	defer k.Close()
	if v, _, err := k.GetIntegerValue("ProxyEnable"); err == nil {
		out["ProxyEnable"] = int(v)
	}
	for _, name := range []string{"ProxyServer", "ProxyOverride", "AutoConfigURL"} {
		if v, _, err := k.GetStringValue(name); err == nil {
			out[name] = v
		}
	}
	return out
}

func writeProxySettings(enable int, server, override, pac *string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, inetKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetDWordValue("ProxyEnable", uint32(enable)); err != nil {
		return err
	}
	for name, v := range map[string]*string{"ProxyServer": server, "ProxyOverride": override, "AutoConfigURL": pac} {
		if v == nil {
			_ = k.DeleteValue(name)
		} else {
			_ = k.SetStringValue(name, *v)
		}
	}
	refreshInternetSettings()
	return nil
}

var (
	wininet           = windows.NewLazySystemDLL("wininet.dll")
	internetSetOption = wininet.NewProc("InternetSetOptionW")
)

// refreshInternetSettings tells running apps that the proxy settings changed.
func refreshInternetSettings() {
	const settingsChanged, refresh = 39, 37
	internetSetOption.Call(0, settingsChanged, 0, 0)
	internetSetOption.Call(0, refresh, 0, 0)
}

func platformEnableProxy(host string, port int, bypass string) error {
	server := net.JoinHostPort(host, itoa(port))
	return writeProxySettings(1, &server, &bypass, nil)
}

func platformRestoreProxy(prev map[string]any) error {
	enable := 0
	if v, ok := prev["ProxyEnable"].(float64); ok {
		enable = int(v)
	} else if v, ok := prev["ProxyEnable"].(int); ok {
		enable = v
	}
	str := func(k string) *string {
		if s, ok := prev[k].(string); ok {
			return &s
		}
		return nil
	}
	return writeProxySettings(enable, str("ProxyServer"), str("ProxyOverride"), str("AutoConfigURL"))
}

// platformForceOff turns the proxy off if it still points at a local Sift port.
func platformForceOff() bool {
	cur := readProxySettings()
	s, _ := cur["ProxyServer"].(string)
	if cur["ProxyEnable"] == 1 && len(s) > 10 && s[:10] == "127.0.0.1:" {
		str := func(k string) *string {
			if v, ok := cur[k].(string); ok {
				return &v
			}
			return nil
		}
		return writeProxySettings(0, &s, str("ProxyOverride"), str("AutoConfigURL")) == nil
	}
	return false
}

// ---------------------------------------------------------------- which app opened a connection

var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	getExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	appNames            sync.Map // pid -> string
)

// The TCP table lists every connection on the machine, so reading it is not free.
// One snapshot (client port -> PID, for connections to the proxy) answers many lookups;
// it is refreshed only when a port isn't in it, at most every 10 ms.
var tcpSnap struct {
	sync.Mutex
	at   time.Time
	pids map[int]uint32
}

// appForConn finds the process that owns the client side of a loopback connection.
func appForConn(clientPort, proxyPort int) string {
	tcpSnap.Lock()
	pid, ok := tcpSnap.pids[clientPort]
	if !ok && time.Since(tcpSnap.at) > 10*time.Millisecond {
		tcpSnap.pids = readTCPTable(proxyPort)
		tcpSnap.at = time.Now()
		pid, ok = tcpSnap.pids[clientPort]
	}
	tcpSnap.Unlock()
	if !ok {
		return ""
	}
	return processName(pid)
}

func readTCPTable(proxyPort int) map[int]uint32 {
	out := map[int]uint32{}
	var size uint32
	getExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, 2 /*AF_INET*/, 5 /*OWNER_PID_ALL*/, 0)
	for range 3 {
		size += 8192
		buf := make([]byte, size)
		r, _, _ := getExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, 2, 5, 0)
		if r != 0 {
			continue
		}
		n := int(binary.LittleEndian.Uint32(buf))
		for i := range n {
			row := buf[4+i*24 : 4+(i+1)*24]
			if int(binary.BigEndian.Uint16(row[16:18])) == proxyPort {
				out[int(binary.BigEndian.Uint16(row[8:10]))] = binary.LittleEndian.Uint32(row[20:24])
			}
		}
		break
	}
	return out
}

type procName struct {
	name string
	at   time.Time
}

func processName(pid uint32) string {
	if v, ok := appNames.Load(pid); ok && time.Since(v.(procName).at) < 5*time.Minute { // PIDs get reused
		return v.(procName).name
	}
	name := ""
	if h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid); err == nil {
		buf := make([]uint16, 1024)
		n := uint32(len(buf))
		if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil {
			name = filepath.Base(windows.UTF16ToString(buf[:n]))
		}
		windows.CloseHandle(h)
	}
	appNames.Store(pid, procName{name, time.Now()})
	return name
}

// ---------------------------------------------------------------- admin tasks

// elevate runs commands as administrator. Windows shows its UAC prompt; this waits for
// the commands to finish and fails if the prompt is declined.
func elevate(lines []string) error {
	f, err := os.CreateTemp("", "sift-*.cmd")
	if err != nil {
		return err
	}
	f.WriteString("@echo off\r\n" + strings.Join(lines, "\r\n") + "\r\n")
	f.Close()
	defer os.Remove(f.Name())
	ps := fmt.Sprintf(`Start-Process -FilePath cmd.exe -ArgumentList '/c ""%s""' -Verb RunAs -WindowStyle Hidden -Wait`, f.Name())
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	hideWindow(cmd)
	if out, err := cmd.CombinedOutput(); err != nil {
		if strings.Contains(string(out), "canceled") || strings.Contains(string(out), "cancelled") {
			return fmt.Errorf("the administrator prompt was declined")
		}
		return fmt.Errorf("%v %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Microsoft Store (UWP) apps are not allowed to connect to 127.0.0.1, so with the system
// proxy on they can't reach the internet at all. A loopback exemption per app fixes that
// (the same thing Fiddler's "WinConfig" does).
const containerKey = `Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings`

func appContainers() []string {
	k, err := registry.OpenKey(registry.CURRENT_USER, containerKey, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer k.Close()
	sids, _ := k.ReadSubKeyNames(-1)
	return sids
}

func exemptContainers() map[string]bool {
	cmd := exec.Command("CheckNetIsolation.exe", "LoopbackExempt", "-s")
	hideWindow(cmd)
	out, _ := cmd.Output()
	got := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if _, sid, ok := strings.Cut(line, "SID:"); ok {
			got[strings.ToUpper(strings.TrimSpace(sid))] = true
		}
	}
	return got
}

// LoopbackStatus reports how many Store apps may reach Sift.
func LoopbackStatus() (exempt, total int) {
	have := exemptContainers()
	sids := appContainers()
	for _, s := range sids {
		if have[strings.ToUpper(s)] {
			exempt++
		}
	}
	return exempt, len(sids)
}

// SetLoopback exempts every Store app (on=true), or removes the exemptions Sift added.
func SetLoopback(home string, on bool) error {
	record := filepath.Join(home, "loopback-exempt.json")
	var lines []string
	if on {
		have := exemptContainers()
		var added []string
		for _, s := range appContainers() {
			if !have[strings.ToUpper(s)] {
				lines = append(lines, "CheckNetIsolation.exe LoopbackExempt -a -p="+s+" >nul")
				added = append(added, s)
			}
		}
		if len(lines) == 0 {
			return nil
		}
		if err := elevate(lines); err != nil {
			return err
		}
		var prev []string
		if b, err := os.ReadFile(record); err == nil {
			json.Unmarshal(b, &prev)
		}
		b, _ := json.Marshal(append(prev, added...))
		return os.WriteFile(record, b, 0o644)
	}
	var mine []string
	if b, err := os.ReadFile(record); err == nil {
		json.Unmarshal(b, &mine)
	}
	for _, s := range mine {
		lines = append(lines, "CheckNetIsolation.exe LoopbackExempt -d -p="+s+" >nul")
	}
	if len(lines) == 0 {
		return nil
	}
	if err := elevate(lines); err != nil {
		return err
	}
	return os.Remove(record)
}

// Phones and other devices reach Sift over the network, which Windows Firewall blocks
// unless there's an inbound rule for sift.exe.
const firewallRule = "Sift proxy"

func FirewallAllowed() bool {
	cmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+firewallRule)
	hideWindow(cmd)
	return cmd.Run() == nil
}

func AllowFirewall() error {
	exe, _ := os.Executable()
	return elevate([]string{
		fmt.Sprintf(`netsh advfirewall firewall delete rule name="%s" >nul`, firewallRule),
		fmt.Sprintf(`netsh advfirewall firewall add rule name="%s" dir=in action=allow program="%s" enable=yes profile=any >nul`, firewallRule, exe),
	})
}

// StartGuard launches a tiny detached copy of Sift that waits for this process to exit
// and then restores the proxy settings, even if Sift is killed or crashes.
func StartGuard() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(exe, "-guard", strconv.Itoa(os.Getpid()))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x00000008 | 0x00000200} // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
	cmd.Start()
}

func RunGuard(pid int, home string) {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return
	}
	windows.WaitForSingleObject(h, windows.INFINITE)
	windows.CloseHandle(h)
	NewSystemProxy(home).Disable() // no-op if Sift already restored the settings
}

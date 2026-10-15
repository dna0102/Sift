package emulator

import (
	"bufio"
	"context"
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"sift/internal/sysproxy"
)

//go:embed unpin.js
var unpinScript string

const fridaServerPath = "/data/local/tmp/frida-server"

type FridaStatus struct {
	Available bool   `json:"available"`
	Python    bool   `json:"python"`
	Server    bool   `json:"server"`
	Active    bool   `json:"active"`
	Reason    string `json:"reason,omitempty"`
}

func (e *Emulator) FridaProbe(serial string) FridaStatus {
	st := FridaStatus{}
	if pythonExe() == "" {
		st.Reason = "Python with the frida module isn't installed on this PC. Install it with: pip install frida-tools"
		return st
	}
	st.Python = true
	if serial != "" {
		if out, _ := e.adbCmd(serial, 8*time.Second, "shell", "ls", fridaServerPath); strings.Contains(out, fridaServerPath) {
			st.Server = true
		}
	}
	st.Available = st.Python && st.Server
	if !st.Available && st.Reason == "" {
		st.Reason = "frida-server isn't on this device. Use a rooted AVD with /data/local/tmp/frida-server (e.g. a Frida AVD), or Sift will push one if you provide it."
	}
	return st
}

func pythonExe() string {
	for _, name := range []string{"python", "python3", "py"} {
		if p, err := exec.LookPath(name); err == nil {

			cmd := exec.Command(p, "-c", "import frida")
			sysproxy.HideWindow(cmd)
			if cmd.Run() == nil {
				return p
			}
		}
	}
	return ""
}

func (e *Emulator) startFridaServer(serial string) bool {
	e.adbCmd(serial, 8*time.Second, "root")
	time.Sleep(1 * time.Second)
	e.adbCmd(serial, 8*time.Second, "wait-for-device")
	e.adbCmd(serial, 8*time.Second, "shell", "chmod", "755", fridaServerPath)

	if !e.fridaRunning(serial) {

		cmd := exec.Command(e.adb, "-s", serial, "shell",
			"setsid "+fridaServerPath+" >/dev/null 2>&1 < /dev/null")
		sysproxy.HideWindow(cmd)
		cmd.Start()
		e.mu.Lock()
		e.fridaSrv = cmd
		e.mu.Unlock()
		for i := 0; i < 20; i++ {
			time.Sleep(500 * time.Millisecond)
			if e.fridaRunning(serial) {
				break
			}
		}
	}
	e.adbCmd(serial, 6*time.Second, "forward", "tcp:27042", "tcp:27042")
	return e.fridaRunning(serial)
}

func (e *Emulator) fridaRunning(serial string) bool {
	out, _ := e.adbCmd(serial, 6*time.Second, "shell", "pidof", "frida-server")
	return strings.TrimSpace(out) != ""
}

type fridaResult int

const (
	fridaOK fridaResult = iota
	fridaDied
	fridaFail
)

func (e *Emulator) injectFrida(ctx context.Context, pkg, mode string) fridaResult {
	driver := e.writeFridaDriver()
	scriptPath := filepath.Join(os.TempDir(), "sift-unpin.js")

	native := "false"
	if strings.HasSuffix(mode, "-native") {
		native = "true"
		mode = strings.TrimSuffix(mode, "-native")
	}
	script := strings.Replace(unpinScript, "__SIFT_NATIVE__", native, 1)
	if err := os.WriteFile(scriptPath, []byte(script), 0o644); err != nil {
		return fridaFail
	}
	cmd := exec.CommandContext(ctx, pythonExe(), driver, pkg, scriptPath, mode)
	sysproxy.HideWindow(cmd)
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return fridaFail
	}
	e.mu.Lock()
	e.fridaCmd = cmd
	e.mu.Unlock()

	result := make(chan fridaResult, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		ready := false
		for sc.Scan() {
			line := sc.Text()
			e.log("frida: " + line)
			switch {
			case strings.Contains(line, "SIFT_FRIDA_READY"):
				ready = true
				e.mu.Lock()
				e.fridaActive = true
				e.mu.Unlock()
				e.mobile.Changed(0)
				result <- fridaOK
			case strings.Contains(line, "SIFT_FRIDA_DIED"), strings.Contains(line, "SIFT_FRIDA_NOPROC"):
				if !ready {
					result <- fridaDied
				}
			case strings.Contains(line, "SIFT_FRIDA_DETACHED"):
				e.mu.Lock()
				e.fridaActive = false
				e.mu.Unlock()
			case (strings.Contains(line, "frida.") || strings.Contains(line, "Traceback")) && (strings.Contains(line, "Error") || strings.Contains(line, "Exception")) && !ready:
				result <- fridaFail
			}
		}

		if !ready {
			select {
			case result <- fridaFail:
			default:
			}
		}
	}()

	select {
	case r := <-result:
		return r
	case <-time.After(25 * time.Second):
		if e.fridaActiveNow() {
			return fridaOK
		}
		return fridaFail
	case <-ctx.Done():
		return fridaFail
	}
}

func (e *Emulator) fridaActiveNow() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.fridaActive
}

func (e *Emulator) writeFridaDriver() string {
	path := filepath.Join(os.TempDir(), "sift-frida.py")
	driver := `import sys, time, frida
pkg, script_path, mode = sys.argv[1], sys.argv[2], sys.argv[3]
code = open(script_path, 'r', encoding='utf-8').read()
dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')

def inject(session):
    script = session.create_script(code)
    def on_message(message, data):
        p = message.get('payload') if isinstance(message, dict) else None
        if p: print(p, flush=True)
    script.on('message', on_message)
    script.load()
    return script

gone = {'v': False}
def on_detached(reason, *a):
    gone['v'] = True
    print('SIFT_FRIDA_DETACHED ' + str(reason), flush=True)

if mode == 'attach':
    # wait for the process to exist, then attach
    pid = None
    for _ in range(60):
        try:
            pid = dev.get_process(pkg).pid
            break
        except Exception:
            time.sleep(0.5)
    if pid is None:
        print('SIFT_FRIDA_NOPROC', flush=True); sys.exit(1)
    session = dev.attach(pid)
    session.on('detached', on_detached)
    inject(session)
    print('SIFT_FRIDA_READY pid=%d' % pid, flush=True)
else:
    pid = dev.spawn([pkg])
    session = dev.attach(pid)
    session.on('detached', on_detached)
    inject(session)
    dev.resume(pid)
    print('SIFT_FRIDA_READY pid=%d' % pid, flush=True)
    # if the app self-kills within a few seconds (anti-tamper), report it
    for _ in range(10):
        time.sleep(0.5)
        if gone['v']:
            print('SIFT_FRIDA_DIED', flush=True); sys.exit(2)

try:
    while True:
        time.sleep(1)
        if gone['v']: break
except KeyboardInterrupt:
    pass
`
	os.WriteFile(path, []byte(driver), 0o644)
	return path
}

func (e *Emulator) stopFrida() {
	e.mu.Lock()
	cmd := e.fridaCmd
	e.fridaCmd = nil
	e.fridaActive = false
	e.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		cmd.Process.Kill()
	}
}

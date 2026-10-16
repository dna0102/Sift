package emulator

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/asn1"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"sift/internal/apk"
	"sift/internal/ca"
	"sift/internal/core"
	"sift/internal/proxy"
	"sift/internal/sysproxy"
)

type Emulator struct {
	store  *core.Store
	mobile *apk.MobileStore
	ca     *ca.CA
	port   int
	sdk    string
	adb    string
	emu    string

	mu      sync.Mutex
	state   string
	avd     string
	serial  string
	pkg     string
	appName string
	message string
	logLine string
	cancel  context.CancelFunc
	proc    *exec.Cmd
	exited  chan struct{}

	OnCertInstalled func()

	unpin       bool
	fridaCmd    *exec.Cmd
	fridaSrv    *exec.Cmd
	fridaActive bool
}

func NewEmulator(store *core.Store, mobile *apk.MobileStore, root *ca.CA, proxyPort int) *Emulator {
	e := &Emulator{store: store, mobile: mobile, ca: root, port: proxyPort, state: "idle"}
	e.sdk = findAndroidSDK()
	if e.sdk != "" {
		e.adb = filepath.Join(e.sdk, "platform-tools", exe("adb"))
		e.emu = filepath.Join(e.sdk, "emulator", exe("emulator"))
	}
	return e
}

func exe(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func findAndroidSDK() string {
	for _, env := range []string{"ANDROID_HOME", "ANDROID_SDK_ROOT"} {
		if p := os.Getenv(env); p != "" && dirExists(p) {
			return p
		}
	}
	home, _ := os.UserHomeDir()
	candidates := []string{}
	if runtime.GOOS == "windows" {
		if la := os.Getenv("LOCALAPPDATA"); la != "" {
			candidates = append(candidates, filepath.Join(la, "Android", "Sdk"))
		}
	} else if runtime.GOOS == "darwin" {
		candidates = append(candidates, filepath.Join(home, "Library", "Android", "sdk"))
	} else {
		candidates = append(candidates, filepath.Join(home, "Android", "Sdk"), filepath.Join(home, "Android", "sdk"))
	}
	for _, c := range candidates {
		if apk.FileExists(filepath.Join(c, "platform-tools", exe("adb"))) {
			return c
		}
	}
	return ""
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func (e *Emulator) Available() bool {
	return e.sdk != "" && apk.FileExists(e.adb) && apk.FileExists(e.emu)
}

type EmulatorStatus struct {
	Available bool     `json:"available"`
	SDK       string   `json:"sdk,omitempty"`
	State     string   `json:"state"`
	AVD       string   `json:"avd,omitempty"`
	Serial    string   `json:"serial,omitempty"`
	Package   string   `json:"package,omitempty"`
	AppName   string   `json:"appName,omitempty"`
	Message   string   `json:"message,omitempty"`
	Log       string   `json:"log,omitempty"`
	AVDs      []string `json:"avds,omitempty"`
	Running   []string `json:"running,omitempty"`
	Reason    string   `json:"reason,omitempty"`
	Unpin     bool     `json:"unpin"`
	FridaOn   bool     `json:"fridaOn"`
}

func (e *Emulator) Status() EmulatorStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := EmulatorStatus{Available: e.Available(), SDK: e.sdk, State: e.state, AVD: e.avd,
		Serial: e.serial, Package: e.pkg, AppName: e.appName, Message: e.message, Log: e.logLine,
		Unpin: e.unpin, FridaOn: e.fridaActive}
	if !s.Available {
		s.Reason = "Android SDK not found. Install Android Studio (or the command-line tools) so the emulator and adb are available, then reopen Sift."
	}
	return s
}

func (e *Emulator) ListDevices() ([]string, []string) {
	avds := []string{}
	if out, err := e.run(8*time.Second, e.emu, "-list-avds"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			if l := strings.TrimSpace(line); l != "" && !strings.HasPrefix(l, "INFO") {
				avds = append(avds, l)
			}
		}
	}
	running := []string{}
	if out, err := e.run(8*time.Second, e.adb, "devices"); err == nil {
		for _, line := range strings.Split(out, "\n")[1:] {
			f := strings.Fields(line)
			if len(f) >= 2 && f[1] == "device" {
				running = append(running, f[0])
			}
		}
	}
	return avds, running
}

func (e *Emulator) setState(state, msg string) {
	e.mu.Lock()
	e.state = state
	if msg != "" {
		e.message = msg
	}
	e.mu.Unlock()
	e.mobile.Changed(0)
	e.store.Hub.StateChanged()
}

func (e *Emulator) log(line string) {
	e.mu.Lock()
	e.logLine = line
	e.mu.Unlock()
	proxy.Debugf("emulator: %s", line)
}

func (e *Emulator) run(timeout time.Duration, name string, args ...string) (string, error) {
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	sysproxy.HideWindow(cmd)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (e *Emulator) adbCmd(serial string, timeout time.Duration, args ...string) (string, error) {
	full := append([]string{"-s", serial}, args...)
	return e.run(timeout, e.adb, full...)
}

func (e *Emulator) Launch(avd string, rep *apk.Report, unpin bool) error {
	e.mu.Lock()
	if e.state != "idle" && e.state != "error" {
		cur := e.state
		e.mu.Unlock()
		return fmt.Errorf("the emulator is already %s — stop it first", cur)
	}
	e.state, e.avd, e.appName, e.message, e.serial, e.pkg = "booting", avd, apk.FirstNonEmpty(rep.Label, rep.Name), "", "", rep.Package
	e.unpin, e.fridaActive = unpin, false
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.mu.Unlock()
	e.mobile.Changed(0)

	apkPath := rep.APKPath()
	if apkPath == "" {
		e.setState("error", "The APK file for this report is no longer available. Re-open the APK.")
		return nil
	}
	go e.launchFlow(ctx, avd, apkPath, rep.Package)
	return nil
}

func (e *Emulator) launchFlow(ctx context.Context, avd, apkPath, pkg string) {
	defer func() {
		if r := recover(); r != nil {
			e.setState("error", fmt.Sprint(r))
		}
	}()

	serial, fresh := "", false
	if e.isSerial(avd) {
		serial = avd
	} else if s := e.runningSerialFor(avd); s != "" {
		serial = s
	} else {
		if avd == SiftAVD {
			if avdDir(SiftAVD) == "" {
				e.setState("booting", "Creating the Sift device…")
			}
			if err := e.ensureSiftAVD(); err != nil {
				e.setState("error", "Couldn't create the Sift device: "+err.Error())
				return
			}
		}
		fresh = !hasQuickboot(avd)
		if fresh {
			e.setState("booting", "First start of this device, so it does a full boot (about a minute). Stopping it from Sift saves a snapshot, and later launches resume in seconds.")
		} else {
			e.setState("booting", "Resuming the emulator from its snapshot…")
		}
		s, err := e.boot(ctx, avd)
		if err != nil {
			e.setState("error", "Couldn't start the emulator: "+err.Error())
			return
		}
		serial = s
	}
	e.mu.Lock()
	e.serial = serial
	e.mu.Unlock()

	if fresh {
		e.setState("booting", "Waiting for Android to finish its first boot…")
	} else {
		e.setState("booting", "Waiting for Android…")
	}
	if err := e.waitBoot(ctx, serial); err != nil {
		e.setState("error", "The emulator didn't finish booting: "+err.Error())
		return
	}
	e.tune(serial)

	e.setState("installing", "Trusting Sift's certificate…")
	certMsg := e.installCert(ctx, serial)

	e.setState("installing", "Routing the device through Sift…")
	if err := e.configureProxy(serial); err != nil {
		e.setState("error", "Couldn't route the emulator through Sift: "+err.Error())
		return
	}

	e.setState("installing", "Installing the app…")
	if out, err := e.installApp(serial, apkPath, pkg); err != nil {
		detail := strings.TrimSpace(out)
		if detail == "" {
			detail = err.Error()
		}
		e.setState("error", "Couldn't install the app: "+apk.Clip(detail, 240))
		return
	}
	if pkg == "" {
		pkg = e.detectPackage(serial, apkPath)
	}
	e.mu.Lock()
	e.pkg = pkg
	wantUnpin := e.unpin
	e.mu.Unlock()

	fridaMsg := ""
	launched := false
	if wantUnpin && pkg != "" {
		fs := e.FridaProbe(serial)
		if fs.Available && e.startFridaServer(serial) {

			e.setState("installing", "Launching with SSL unpinning (Frida)…")
			switch e.injectFrida(ctx, pkg, "spawn") {
			case fridaOK:
				launched = true
				fridaMsg = "SSL unpinning is active (Frida, spawn) — the app's HTTPS is decrypted, including pinned connections."
			case fridaDied:
				e.stopFrida()
				e.setState("installing", "App blocks Frida spawn — launching normally and attaching…")
				e.adbCmd(serial, 20*time.Second, "shell", "monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1")
				time.Sleep(2 * time.Second)
				if e.injectFrida(ctx, pkg, "attach") == fridaOK {
					launched = true
					fridaMsg = "SSL unpinning is active (Frida, attached after launch) — the app's HTTPS is decrypted."
				} else {
					fridaMsg = "The app resisted SSL unpinning (it detects Frida). It's running, but pinned HTTPS stays encrypted. Non-pinned traffic is still captured."
				}
			default:
				fridaMsg = "Couldn't inject the unpinning script — launched normally; pinned HTTPS stays encrypted."
			}
		} else if !fs.Available {
			fridaMsg = "SSL unpinning unavailable: " + fs.Reason
		} else {
			fridaMsg = "Couldn't start frida-server on the device — launched normally; pinned HTTPS stays encrypted."
		}
	}
	if !launched {
		e.setState("installing", "Launching the app…")
		if pkg != "" {
			e.adbCmd(serial, 20*time.Second, "shell", "monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1")
		}
	}

	msg := "App running on the emulator. Its traffic now appears in the Traffic tab."
	if fridaMsg != "" {
		msg += " " + fridaMsg
	} else if certMsg != "" {
		msg += " " + certMsg
	}
	e.setState("running", msg)

	go e.trackForeground(ctx, serial)
}

func (e *Emulator) isSerial(name string) bool {
	_, ok := e.deviceStates()[name]
	return ok
}

func (e *Emulator) runningSerialFor(avd string) string {
	for serial, online := range e.deviceStates() {
		if !online || !strings.HasPrefix(serial, "emulator-") {
			continue
		}
		out, _ := e.adbCmd(serial, 5*time.Second, "emu", "avd", "name")
		if first, _, _ := strings.Cut(strings.TrimSpace(out), "\n"); strings.TrimSpace(first) == avd {
			return serial
		}
	}
	return ""
}

func (e *Emulator) tune(serial string) {
	script := strings.Join([]string{
		"settings put global window_animation_scale 0",
		"settings put global transition_animation_scale 0",
		"settings put global animator_duration_scale 0",
		"settings put global package_verifier_enable 0",
		"settings put global verifier_verify_adb_installs 0",
		"settings put global hide_error_dialogs 1",
		"settings put secure anr_show_background 0",
		"am broadcast -a android.intent.action.CLOSE_SYSTEM_DIALOGS",
	}, "; ")
	e.adbCmd(serial, 20*time.Second, "shell", script)
}

func (e *Emulator) boot(ctx context.Context, avd string) (string, error) {
	e.run(5*time.Second, e.adb, "reconnect", "offline")
	before := e.deviceSet()
	cmd := exec.CommandContext(ctx, e.emu, bootArgs(avd)...)
	sysproxy.HideWindow(cmd)

	logs := &lineLogger{emu: e}
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		return "", err
	}
	exited := make(chan struct{})
	go func() { cmd.Wait(); close(exited) }()
	e.mu.Lock()
	e.proc, e.exited = cmd, exited
	e.mu.Unlock()

	deadline := time.Now().Add(240 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-exited:
			e.mu.Lock()
			last := e.logLine
			e.mu.Unlock()
			return "", fmt.Errorf("the emulator process exited: %s", apk.Clip(last, 200))
		case <-time.After(time.Second):
		}
		for serial, online := range e.deviceStates() {
			if online && !before[serial] {
				return serial, nil
			}
		}
	}
	return "", fmt.Errorf("timed out waiting for the emulator to come online")
}

type lineLogger struct {
	emu *Emulator
	mu  sync.Mutex
	buf []byte
}

func (l *lineLogger) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf = append(l.buf, p...)
	for {
		i := bytes.IndexByte(l.buf, '\n')
		if i < 0 {
			break
		}
		if line := strings.TrimSpace(string(l.buf[:i])); line != "" {
			l.emu.log(line)
		}
		l.buf = l.buf[i+1:]
	}
	return len(p), nil
}

func (e *Emulator) procExited() bool {
	e.mu.Lock()
	ch := e.exited
	e.mu.Unlock()
	if ch == nil {
		return false
	}
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func (e *Emulator) deviceStates() map[string]bool {
	set := map[string]bool{}
	out, _ := e.run(8*time.Second, e.adb, "devices")
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && (f[1] == "device" || f[1] == "offline") {
			set[f[0]] = f[1] == "device"
		}
	}
	return set
}

func (e *Emulator) deviceSet() map[string]bool {
	set := map[string]bool{}
	for s, online := range e.deviceStates() {
		if online {
			set[s] = true
		}
	}
	return set
}

func (e *Emulator) waitBoot(ctx context.Context, serial string) error {
	e.adbCmd(serial, 240*time.Second, "wait-for-device")
	deadline := time.Now().Add(300 * time.Second)
	missing := 0
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}

		if e.procExited() {
			return fmt.Errorf("the emulator shut down before finishing boot")
		}

		if !e.deviceStates()[serial] {
			missing++
			if missing >= 5 {
				return fmt.Errorf("the emulator disconnected before finishing boot (it may have crashed — try booting it in Android Studio first)")
			}
			continue
		}
		missing = 0
		out, _ := e.adbCmd(serial, 8*time.Second, "shell", "getprop sys.boot_completed; pm path android")
		if strings.HasPrefix(strings.TrimSpace(out), "1") && strings.Contains(out, "package:") {
			return nil
		}
	}
	return fmt.Errorf("boot timed out")
}

const proxyExclusions = "127.0.0.1,localhost,*.gstatic.com,connectivitycheck.gstatic.com," +
	"connectivitycheck.android.com,*.googleapis.com,clients3.google.com,clients4.google.com," +
	"play.googleapis.com,android.clients.google.com,mtalk.google.com"

func (e *Emulator) configureProxy(serial string) error {
	host := e.proxyHostAlias()
	port := e.port
	combined := fmt.Sprintf("%s:%d", host, port)

	var lastErr string
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {

			e.adbCmd(serial, 15*time.Second, "wait-for-device")
			time.Sleep(time.Duration(attempt) * time.Second)
		}

		e.adbCmd(serial, 10*time.Second, "shell", "settings", "put", "global", "global_http_proxy_host", host)
		e.adbCmd(serial, 10*time.Second, "shell", "settings", "put", "global", "global_http_proxy_port", strconv.Itoa(port))
		e.adbCmd(serial, 10*time.Second, "shell", "settings", "put", "global", "global_http_proxy_exclusion_list", proxyExclusions)
		out, err := e.adbCmd(serial, 10*time.Second, "shell", "settings", "put", "global", "http_proxy", combined)
		if err != nil {
			lastErr = strings.TrimSpace(out)
			if lastErr == "" {
				lastErr = err.Error()
			}
		}

		got, _ := e.adbCmd(serial, 8*time.Second, "shell", "settings", "get", "global", "http_proxy")
		if strings.TrimSpace(got) == combined {
			return nil
		}
		if lastErr == "" {
			lastErr = "proxy didn't take (read back " + apk.Clip(strings.TrimSpace(got), 40) + ")"
		}
	}
	return fmt.Errorf("couldn't set the proxy after several tries: %s", apk.Clip(lastErr, 120))
}

func (e *Emulator) proxyHostAlias() string { return "10.0.2.2" }

func (e *Emulator) clearProxy(serial string) {
	for _, k := range []string{"http_proxy", "global_http_proxy_host", "global_http_proxy_port", "global_http_proxy_exclusion_list"} {
		e.adbCmd(serial, 8*time.Second, "shell", "settings", "delete", "global", k)
	}

	e.adbCmd(serial, 8*time.Second, "shell", "settings", "put", "global", "http_proxy", ":0")
}

func (e *Emulator) installCert(ctx context.Context, serial string) string {
	certPEM := e.ca.PEM()

	hashName, err := androidCertHash(e.ca.DER())
	if err != nil || hashName == "" {
		hashName = "sift"
	}
	certFile := hashName + ".0"
	tmp := filepath.Join(os.TempDir(), certFile)
	if os.WriteFile(tmp, certPEM, 0o644) != nil {
		return ""
	}
	defer os.Remove(tmp)

	const sysOK = "Sift's certificate is trusted system-wide, so most apps' HTTPS is decrypted. Apps that pin their certificate still show as encrypted tunnels."

	installed := "[ -f /apex/com.android.conscrypt/cacerts/" + certFile + " ] || [ -f /system/etc/security/cacerts/" + certFile + " ] && echo SIFT_CERT_PRESENT"
	if out, _ := e.adbCmd(serial, 8*time.Second, "shell", installed); strings.Contains(out, "SIFT_CERT_PRESENT") {
		return sysOK
	}

	e.adbCmd(serial, 15*time.Second, "root")
	for i := 0; i < 10; i++ {
		time.Sleep(time.Second)
		e.adbCmd(serial, 10*time.Second, "wait-for-device")
		if out, _ := e.adbCmd(serial, 5*time.Second, "shell", "id"); strings.Contains(out, "uid=0") || (i >= 3 && strings.Contains(out, "uid=")) {
			break
		}
	}

	e.adbCmd(serial, 20*time.Second, "push", tmp, "/data/local/tmp/"+certFile)
	if e.certBindMount(serial, certFile) {
		if e.OnCertInstalled != nil {
			e.OnCertInstalled()
		}
		return sysOK
	}

	e.adbCmd(serial, 15*time.Second, "push", tmp, "/sdcard/Download/sift-ca.pem")
	return "Couldn't trust Sift's certificate system-wide because this device can't be rooted (Play Store images can't). Pick the \"Sift device\" instead, or import /sdcard/Download/sift-ca.pem via Settings → Security → Install a certificate (browsers only)."
}

func (e *Emulator) certBindMount(serial, certFile string) bool {
	su := []string{"shell"}
	if out, _ := e.adbCmd(serial, 8*time.Second, "shell", "id"); !strings.Contains(out, "uid=0") {
		if out2, _ := e.adbCmd(serial, 8*time.Second, "shell", "su", "0", "id"); !strings.Contains(out2, "uid=0") {
			return false
		}
		su = []string{"shell", "su", "0"}
	}
	script := strings.Join([]string{
		"S=/system/etc/security/cacerts",
		"A=/apex/com.android.conscrypt/cacerts",
		"T=/data/local/tmp/sift-cacerts",
		"rm -rf $T; mkdir -p -m 700 $T",
		"cp $S/* $T/ 2>/dev/null",
		"[ -d $A ] && cp $A/* $T/ 2>/dev/null",
		"cp /data/local/tmp/" + certFile + " $T/",
		"mount -t tmpfs tmpfs $S",
		"cp $T/* $S/",
		"chown root:root $S/*",
		"chmod 644 $S/*",
		"chcon u:object_r:system_file:s0 $S/*",
		"rm -rf $T",
		"if [ -d $A ]; then",
		"  mount --bind $S $A",
		"  for Z in $(pidof zygote) $(pidof zygote64); do",
		"    nsenter --mount=/proc/$Z/ns/mnt -- /bin/mount --bind $S $A",
		"    for P in $(ps -o PID -P $Z | grep -v PID); do nsenter --mount=/proc/$P/ns/mnt -- /bin/mount --bind $S $A 2>/dev/null & done",
		"  done",
		"  wait",
		"fi",
		"[ -f $S/" + certFile + " ] && echo SIFT_CERT_OK",
	}, "\n")
	args := append(su, "sh", "-c", shellQuote(script))
	out, _ := e.adbCmd(serial, 60*time.Second, args...)
	return strings.Contains(out, "SIFT_CERT_OK")
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

var installFailure = regexp.MustCompile(`Failure \[[^\]]*\]|INSTALL_[A-Z_]+[^\r\n]*`)

func failureReason(out string) string {
	if m := installFailure.FindString(out); m != "" {
		return m
	}
	return lastLine(out)
}

func needsUninstall(out string) bool {
	return strings.Contains(out, "INSTALL_FAILED_VERSION_DOWNGRADE") ||
		strings.Contains(out, "INSTALL_FAILED_UPDATE_INCOMPATIBLE") ||
		strings.Contains(out, "signatures do not match")
}

func (e *Emulator) install(serial, pkg string, files ...string) (string, error) {
	verb := "install"
	if len(files) > 1 {
		verb = "install-multiple"
	}
	try := func() (string, error) {
		args := append([]string{"-s", serial, verb, "-r", "-g", "-d"}, files...)
		out, err := e.run(10*time.Minute, e.adb, args...)
		if err != nil && !strings.Contains(out, "Success") {
			return out, fmt.Errorf("%s", failureReason(out))
		}
		return out, nil
	}
	out, err := try()
	if err != nil && pkg != "" && needsUninstall(out) {
		e.setState("installing", "A different build of this app is already on the device — replacing it…")
		e.adbCmd(serial, 60*time.Second, "uninstall", pkg)
		out, err = try()
	}
	return out, err
}

func (e *Emulator) installApp(serial, path, pkg string) (string, error) {
	lower := strings.ToLower(path)
	isBundle := strings.HasSuffix(lower, ".xapk") || strings.HasSuffix(lower, ".apks") ||
		strings.HasSuffix(lower, ".apkm") || strings.HasSuffix(lower, ".aab")
	if !isBundle {

		if !apk.IsPlainAPK(path) {
			isBundle = true
		}
	}

	if !isBundle {
		out, err := e.install(serial, pkg, path)
		if err != nil {
			return err.Error(), err
		}
		return out, nil
	}

	tmp, err := os.MkdirTemp("", "sift-splits-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	apks, err := apk.ExtractAllAPKs(path, tmp)
	if err != nil {
		return err.Error(), fmt.Errorf("couldn't read the bundle")
	}
	if len(apks) == 0 {
		return "the bundle contains no APK files", fmt.Errorf("no apks in bundle")
	}

	deviceABIs := e.deviceABIs(serial)
	kept, droppedABIs, hadABISplit, keptABISplit := filterSplitsForABI(apks, deviceABIs)

	if hadABISplit && !keptABISplit && baseHasNoNativeLibs(apk.PickBaseAPK(apks)) {
		return "", fmt.Errorf("this download has native code only for %s, but the emulator is %s. Get an arm64-v8a or universal build of the app, or use an ARM system image. (The download ships no compatible native libraries.)",
			strings.Join(droppedABIs, "/"), strings.Join(deviceABIs, "/"))
	}

	e.setState("installing", fmt.Sprintf("Installing %d APKs…", len(kept)))
	out, err := e.install(serial, pkg, kept...)
	if err != nil {
		if strings.Contains(out, "NO_MATCHING_ABIS") {
			return "", fmt.Errorf("the app's native libraries don't match the emulator (%s). Use an arm64-v8a/universal build of the app, or an ARM system image.", strings.Join(deviceABIs, "/"))
		}
		if base := apk.PickBaseAPK(apks); base != "" {
			if o2, e2 := e.install(serial, pkg, base); e2 == nil {
				return o2, nil
			}
		}
		return err.Error(), err
	}
	return out, nil
}

func (e *Emulator) deviceABIs(serial string) []string {
	out, _ := e.adbCmd(serial, 8*time.Second, "shell", "getprop", "ro.product.cpu.abilist")
	var abis []string
	for _, a := range strings.Split(strings.TrimSpace(out), ",") {
		if a = strings.TrimSpace(a); a != "" {
			abis = append(abis, a)
		}
	}
	if len(abis) == 0 {
		abis = []string{"x86_64", "arm64-v8a"}
	}
	return abis
}

func filterSplitsForABI(apks, deviceABIs []string) (kept, dropped []string, hadABI, keptABI bool) {
	supported := map[string]bool{}
	for _, a := range deviceABIs {
		supported[normalizeABI(a)] = true
	}
	for _, p := range apks {
		abi := abiOfSplit(filepath.Base(p))
		if abi == "" {
			kept = append(kept, p)
			continue
		}
		hadABI = true
		if supported[normalizeABI(abi)] {
			kept = append(kept, p)
			keptABI = true
		} else {
			dropped = apk.AppendUnique(dropped, abi)
		}
	}
	return kept, dropped, hadABI, keptABI
}

func abiOfSplit(name string) string {
	n := strings.ToLower(name)
	for _, abi := range []string{"arm64_v8a", "arm64-v8a", "armeabi_v7a", "armeabi-v7a", "x86_64", "x86"} {
		if strings.Contains(n, "config."+abi) || strings.Contains(n, "."+abi+".") || strings.HasSuffix(n, "."+abi+".apk") {
			return strings.ReplaceAll(abi, "_", "-")
		}
	}
	return ""
}

func normalizeABI(a string) string { return strings.ReplaceAll(strings.ToLower(a), "_", "-") }

func baseHasNoNativeLibs(basePath string) bool {
	if basePath == "" {
		return false
	}
	zr, err := zip.OpenReader(basePath)
	if err != nil {
		return false
	}
	defer zr.Close()
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "lib/") && strings.HasSuffix(f.Name, ".so") {
			return false
		}
	}
	return true
}

func (e *Emulator) detectPackage(serial, apkPath string) string {

	out, _ := e.adbCmd(serial, 10*time.Second, "shell", "pm", "list", "packages", "-3")
	pkgs := strings.Split(out, "\n")
	if len(pkgs) > 0 {
		last := strings.TrimSpace(pkgs[len(pkgs)-1])
		return strings.TrimPrefix(last, "package:")
	}
	return ""
}

func (e *Emulator) trackForeground(ctx context.Context, serial string) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		e.mu.Lock()
		running := e.state == "running" && e.serial == serial
		e.mu.Unlock()
		if !running {
			return
		}
		if e.procExited() {
			e.stopFrida()
			e.mu.Lock()
			e.state, e.serial, e.pkg, e.appName, e.proc, e.cancel, e.exited = "idle", "", "", "", nil, nil, nil
			e.message = "The emulator was closed."
			e.mu.Unlock()
			e.mobile.Changed(0)
			e.store.Hub.StateChanged()
			return
		}
	}
}

func (e *Emulator) Stop() {
	e.mu.Lock()
	serial, cancel, proc, exited := e.serial, e.cancel, e.proc, e.exited
	e.state = "stopping"
	e.mu.Unlock()
	e.mobile.Changed(0)

	e.stopFrida()
	if serial != "" {
		e.clearProxy(serial)
		if proc != nil {
			e.adbCmd(serial, 10*time.Second, "emu", "kill")
		}
	}
	if proc != nil && exited != nil {
		select {
		case <-exited:
		case <-time.After(45 * time.Second):
		}
	}
	if cancel != nil {
		cancel()
	}
	e.mu.Lock()
	e.state, e.serial, e.pkg, e.appName, e.proc, e.cancel, e.exited = "idle", "", "", "", nil, nil, nil
	e.message = "Emulator stopped."
	e.mu.Unlock()
	e.mobile.Changed(0)
	e.store.Hub.StateChanged()
}

func (e *Emulator) EmulatorApp() (name, serial string, ok bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state == "running" && e.appName != "" {
		return e.appName, e.serial, true
	}
	return "", "", false
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func androidCertHash(der []byte) (string, error) {
	var cert struct {
		TBSCertificate struct {
			Raw          asn1.RawContent
			Version      asn1.RawValue `asn1:"optional,explicit,tag:0"`
			SerialNumber asn1.RawValue
			Signature    asn1.RawValue
			Issuer       asn1.RawValue
			Validity     asn1.RawValue
			Subject      asn1.RawValue
		}
	}
	if _, err := asn1.Unmarshal(der, &cert); err != nil {
		return "", err
	}
	subject := cert.TBSCertificate.Subject.FullBytes
	sum := md5.Sum(subject)

	h := uint32(sum[0]) | uint32(sum[1])<<8 | uint32(sum[2])<<16 | uint32(sum[3])<<24
	return fmt.Sprintf("%08x", h), nil
}

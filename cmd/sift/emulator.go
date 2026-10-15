package main

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/asn1"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The emulator manager boots an Android emulator, points it at Sift's proxy, trusts Sift's
// certificate, installs the APK and launches it — so you can drive the app by hand while all
// its traffic flows into Sift's Traffic tab. It shells out to the Android SDK's `emulator`
// and `adb`; nothing is bundled.

type Emulator struct {
	app *App
	sdk string // Android SDK root
	adb string
	emu string

	mu      sync.Mutex
	state   string // idle | booting | installing | running | stopping | error
	avd     string // the AVD currently in use
	serial  string // adb serial of the running emulator, e.g. emulator-5554
	pkg     string // package of the installed app
	appName string // human label
	message string
	logLine string
	cancel  context.CancelFunc
	proc    *exec.Cmd

	unpin       bool     // bypass SSL pinning with Frida
	fridaCmd    *exec.Cmd // the spawn-under-frida driver
	fridaSrv    *exec.Cmd // the detached frida-server launcher
	fridaActive bool
}

func NewEmulator(app *App) *Emulator {
	e := &Emulator{app: app, state: "idle"}
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

// findAndroidSDK locates the SDK from the usual env vars or default install paths.
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
		if fileExists(filepath.Join(c, "platform-tools", exe("adb"))) {
			return c
		}
	}
	return ""
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// Available reports whether the emulator feature can be used on this machine.
func (e *Emulator) Available() bool {
	return e.sdk != "" && fileExists(e.adb) && fileExists(e.emu)
}

// EmulatorStatus is sent to the dashboard.
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
	Running   []string `json:"running,omitempty"` // already-connected devices
	Reason    string   `json:"reason,omitempty"`  // why unavailable
	Unpin     bool     `json:"unpin"`             // SSL unpinning requested
	FridaOn   bool     `json:"fridaOn"`           // Frida currently injected
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

// ListDevices returns the AVDs that can be launched and any devices already connected.
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
	e.app.mobile.Changed(0) // nudge the apps SSE stream
	e.app.store.hub.StateChanged()
}

func (e *Emulator) log(line string) {
	e.mu.Lock()
	e.logLine = line
	e.mu.Unlock()
	debugf("emulator: %s", line)
	e.app.mobile.Changed(0)
}

// run executes a command and returns combined output. timeout 0 means no timeout (for
// long-lived helpers like starting frida-server detached).
func (e *Emulator) run(timeout time.Duration, name string, args ...string) (string, error) {
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	hideWindow(cmd)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (e *Emulator) adbCmd(serial string, timeout time.Duration, args ...string) (string, error) {
	full := append([]string{"-s", serial}, args...)
	return e.run(timeout, e.adb, full...)
}

// Launch boots the AVD (or uses an already-running serial), installs the cert and APK, and
// starts the app. report provides the APK path and package. It runs in the background; the
// UI follows progress via Status().
func (e *Emulator) Launch(avd string, rep *Report, unpin bool) error {
	e.mu.Lock()
	if e.state != "idle" && e.state != "error" {
		cur := e.state
		e.mu.Unlock()
		return fmt.Errorf("the emulator is already %s — stop it first", cur)
	}
	e.state, e.avd, e.appName, e.message, e.serial, e.pkg = "booting", avd, firstNonEmpty(rep.Label, rep.Name), "", "", rep.Package
	e.unpin, e.fridaActive = unpin, false
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.mu.Unlock()
	e.app.mobile.Changed(0)

	apkPath := rep.apkPath()
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

	// 1. Is this a pre-running device/serial, or an AVD to boot?
	serial := ""
	if strings.HasPrefix(avd, "emulator-") || strings.Contains(avd, ":") {
		serial = avd // already a device serial
	} else {
		e.setState("booting", "Starting the emulator…")
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

	e.setState("booting", "Waiting for Android to finish starting…")
	if err := e.waitBoot(ctx, serial); err != nil {
		e.setState("error", "The emulator didn't finish booting: "+err.Error())
		return
	}

	// 2. Point it at Sift and trust the certificate.
	e.setState("installing", "Configuring the proxy and certificate…")
	if err := e.configureProxy(serial); err != nil {
		e.setState("error", "Couldn't route the emulator through Sift: "+err.Error())
		return
	}
	certMsg := e.installCert(ctx, serial)

	// 3. Install and launch the APK (handling XAPK/APKS bundles of split APKs).
	e.setState("installing", "Installing the app…")
	if out, err := e.installApp(serial, apkPath); err != nil {
		detail := strings.TrimSpace(out)
		if detail == "" {
			detail = err.Error() // ABI-mismatch and similar return the message in the error
		}
		e.setState("error", "Couldn't install the app: "+clip(detail, 240))
		return
	}
	if pkg == "" {
		pkg = e.detectPackage(serial, apkPath)
	}
	e.mu.Lock()
	e.pkg = pkg
	wantUnpin := e.unpin
	e.mu.Unlock()

	// 4. Launch the app — under Frida (SSL unpinning) if requested and available, else normally.
	fridaMsg := ""
	launched := false
	if wantUnpin && pkg != "" {
		fs := e.fridaProbe(serial)
		if fs.Available && e.startFridaServer(serial) {
			// First try spawn mode (catches pinning set up at startup). If the app self-kills
			// — anti-tamper apps like TikTok detect being spawned under Frida — fall back to
			// launching it normally and attaching, which those apps tolerate.
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
	// keep tagging the active app for the traffic view
	go e.trackForeground(ctx, serial)
}

// boot starts the emulator process and returns its adb serial once it registers.
func (e *Emulator) boot(ctx context.Context, avd string) (string, error) {
	e.run(5*time.Second, e.adb, "reconnect", "offline") // clear stale offline entries from a prior run
	before := e.deviceSet()
	args := []string{
		"-avd", avd,
		"-writable-system",  // lets us install the CA as a system cert
		"-no-snapshot-load", // clean boot so proxy/cert settings apply fresh
		"-no-boot-anim",
	}
	cmd := exec.CommandContext(ctx, e.emu, args...)
	hideWindow(cmd)
	// surface emulator errors into the log
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return "", err
	}
	e.mu.Lock()
	e.proc = cmd
	e.mu.Unlock()
	if stderr != nil {
		go func() {
			sc := bufio.NewScanner(stderr)
			for sc.Scan() {
				e.log(sc.Text())
			}
		}()
	}
	// Wait up to 120s for a device that is ONLINE and wasn't already online before. A serial
	// can briefly reappear as "offline" (a restarting emulator) — we only accept it once it
	// reports "device".
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
		for serial, online := range e.deviceStates() {
			if online && !before[serial] {
				return serial, nil
			}
		}
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			return "", fmt.Errorf("the emulator process exited (check the AVD in Android Studio)")
		}
	}
	return "", fmt.Errorf("timed out waiting for the emulator to come online")
}

// deviceStates maps serial -> online. "before" boot we record only ONLINE devices, so a
// stale offline entry from a previous run doesn't block detecting the new one.
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

// deviceSet returns only the currently-online devices (used as the "before" baseline).
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
	e.adbCmd(serial, 120*time.Second, "wait-for-device")
	deadline := time.Now().Add(120 * time.Second)
	missing := 0
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
		// If the emulator process we started has exited, stop waiting immediately.
		e.mu.Lock()
		proc := e.proc
		e.mu.Unlock()
		if proc != nil && proc.ProcessState != nil && proc.ProcessState.Exited() {
			return fmt.Errorf("the emulator shut down before finishing boot")
		}
		// If the device has fallen off adb (crash / disconnect), don't hang the full timeout.
		if !e.deviceStates()[serial] {
			missing++
			if missing >= 5 { // ~10s of absence
				return fmt.Errorf("the emulator disconnected before finishing boot (it may have crashed — try booting it in Android Studio first)")
			}
			continue
		}
		missing = 0
		out, _ := e.adbCmd(serial, 8*time.Second, "shell", "getprop", "sys.boot_completed")
		if strings.TrimSpace(out) == "1" {
			time.Sleep(2 * time.Second) // let the launcher settle
			return nil
		}
	}
	return fmt.Errorf("boot timed out")
}

// proxyExclusions are hosts the emulator must reach DIRECTLY, not through Sift. Android's
// captive-portal / connectivity check (generate_204) and Play-services pings must return
// their exact expected responses or the OS marks the network "no internet" and apps hang
// waiting on it. Keeping them off the proxy lets Wi-Fi validate as connected.
const proxyExclusions = "127.0.0.1,localhost,*.gstatic.com,connectivitycheck.gstatic.com," +
	"connectivitycheck.android.com,*.googleapis.com,clients3.google.com,clients4.google.com," +
	"play.googleapis.com,android.clients.google.com,mtalk.google.com"

// configureProxy routes the emulator's traffic through Sift using the emulator's built-in
// host-loopback alias 10.0.2.2 (which always maps to the host and needs no adb tunnel, so it
// can't break when adb reconnects). Connectivity-check hosts are excluded so the OS still
// sees the network as online.
//
// It is tolerant of transient adb hiccups: `settings put` can briefly fail (device busy, a
// momentary disconnect) with an empty error. Rather than trust each command's exit code, it
// retries and then verifies success by reading the value back. The combined `http_proxy`
// string is the one that actually matters, so success is judged on that.
func (e *Emulator) configureProxy(serial string) error {
	host := e.proxyHostAlias()
	port := e.app.proxyPort
	combined := fmt.Sprintf("%s:%d", host, port)

	var lastErr string
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			// make sure the device is back before retrying
			e.adbCmd(serial, 15*time.Second, "wait-for-device")
			time.Sleep(time.Duration(attempt) * time.Second)
		}
		// Android reads these keys together for the global proxy; the combined string also
		// covers apps/WebViews that read it directly. Errors here are ignored — we verify below.
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
		// Verify by reading it back — this is the real success check.
		got, _ := e.adbCmd(serial, 8*time.Second, "shell", "settings", "get", "global", "http_proxy")
		if strings.TrimSpace(got) == combined {
			return nil
		}
		if lastErr == "" {
			lastErr = "proxy didn't take (read back " + clip(strings.TrimSpace(got), 40) + ")"
		}
	}
	return fmt.Errorf("couldn't set the proxy after several tries: %s", clip(lastErr, 120))
}

// proxyHostAlias is how the emulator reaches Sift on the host. 10.0.2.2 is the standard
// emulator alias for the host loopback; it works even though Sift binds to 127.0.0.1.
func (e *Emulator) proxyHostAlias() string { return "10.0.2.2" }

// clearProxy removes the proxy so the device is left with working direct internet when reused.
func (e *Emulator) clearProxy(serial string) {
	for _, k := range []string{"http_proxy", "global_http_proxy_host", "global_http_proxy_port", "global_http_proxy_exclusion_list"} {
		e.adbCmd(serial, 8*time.Second, "shell", "settings", "delete", "global", k)
	}
	// belt-and-suspenders: some builds honour :0 only
	e.adbCmd(serial, 8*time.Second, "shell", "settings", "put", "global", "http_proxy", ":0")
}

// installCert installs Sift's CA. On a writable-system emulator it becomes a *system* cert
// (trusted by most apps); otherwise it falls back to a user cert (browsers only).
func (e *Emulator) installCert(ctx context.Context, serial string) string {
	certPEM := e.app.ca.PEM()
	// Android names a system CA file by the hash of its subject: <hash>.0
	hashName, err := androidCertHash(e.app.ca.certDER)
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

	// Become root (no-op on userdebug images; fails silently on locked ones).
	e.adbCmd(serial, 15*time.Second, "root")
	time.Sleep(1500 * time.Millisecond)
	e.adbCmd(serial, 10*time.Second, "wait-for-device")

	// Push the cert to a staging spot on the device.
	e.adbCmd(serial, 20*time.Second, "push", tmp, "/data/local/tmp/"+certFile)

	// Method 1: writable-system image — remount and copy into /system directly.
	if out, _ := e.adbCmd(serial, 20*time.Second, "remount"); !strings.Contains(strings.ToLower(out), "must be bootloader") {
		if o, err := e.adbCmd(serial, 15*time.Second, "shell", "cp", "/data/local/tmp/"+certFile, "/system/etc/security/cacerts/"+certFile); err == nil && o == "" {
			e.adbCmd(serial, 10*time.Second, "shell", "chmod", "644", "/system/etc/security/cacerts/"+certFile)
			return sysOK
		}
	}

	// Method 2: rooted device with verity (e.g. a Frida AVD) — tmpfs bind-mount over the
	// system cacerts dir, seeded with the existing certs plus ours. Survives until reboot.
	if e.certBindMount(serial, certFile) {
		return sysOK
	}

	// Method 3: user cert — works for browsers; most apps won't trust it.
	e.adbCmd(serial, 15*time.Second, "push", tmp, "/sdcard/Download/sift-ca.pem")
	return "Couldn't install the certificate as a system CA (this device's /system is read-only). Browser HTTPS is decrypted; for other apps, use a rooted/Frida AVD, or import /sdcard/Download/sift-ca.pem via Settings → Security → Install a certificate."
}

// certBindMount adds Sift's CA on a rooted device without modifying /system: it mounts a
// tmpfs over the cacerts dir, fills it with the current system+APEX certs, adds ours, and
// fixes the SELinux label. This is the standard way to trust a user CA system-wide on
// modern (verity-enforcing) rooted Android.
func (e *Emulator) certBindMount(serial, certFile string) bool {
	// Confirm root is available.
	if out, _ := e.adbCmd(serial, 8*time.Second, "shell", "su", "0", "id"); !strings.Contains(out, "uid=0") {
		if out2, _ := e.adbCmd(serial, 8*time.Second, "shell", "id"); !strings.Contains(out2, "uid=0") {
			return false
		}
	}
	script := strings.Join([]string{
		"set -e",
		"D=/system/etc/security/cacerts",
		"mount -t tmpfs tmpfs $D",
		// seed with whatever the system had (APEX on Android 14, or the dir itself)
		"cp /apex/com.android.conscrypt/cacerts/* $D/ 2>/dev/null || true",
		"cp /system/etc/security/cacerts.bak/* $D/ 2>/dev/null || true",
		"cp /data/local/tmp/" + certFile + " $D/" + certFile,
		"chown root:root $D/* 2>/dev/null || true",
		"chmod 644 $D/* 2>/dev/null || true",
		"chcon u:object_r:system_security_cacerts_file:s0 $D/* 2>/dev/null || true",
		// Android 14 also reads from the APEX copy; mirror it there if present
		"if [ -d /apex/com.android.conscrypt/cacerts ]; then mount -t tmpfs tmpfs /apex/com.android.conscrypt/cacerts 2>/dev/null && cp $D/* /apex/com.android.conscrypt/cacerts/ 2>/dev/null && chcon u:object_r:system_security_cacerts_file:s0 /apex/com.android.conscrypt/cacerts/* 2>/dev/null; fi || true",
		"echo SIFT_CERT_OK",
	}, "\n")
	out, _ := e.adbCmd(serial, 30*time.Second, "shell", "su", "0", "sh", "-c", shellQuote(script))
	return strings.Contains(out, "SIFT_CERT_OK")
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// installApp installs an app on the device. A plain .apk installs directly; an XAPK/APKS/AAB
// bundle (a zip containing a base APK plus split APKs) is unpacked and installed with
// `adb install-multiple`, because the app needs its splits (language/density/ABI) to run —
// installing only the base fails or crashes at launch. Returns adb's output and an error.
func (e *Emulator) installApp(serial, path string) (string, error) {
	lower := strings.ToLower(path)
	isBundle := strings.HasSuffix(lower, ".xapk") || strings.HasSuffix(lower, ".apks") ||
		strings.HasSuffix(lower, ".apkm") || strings.HasSuffix(lower, ".aab")
	if !isBundle {
		// Even a .apk could actually be a renamed bundle; peek inside.
		if !isPlainAPK(path) {
			isBundle = true
		}
	}

	if !isBundle {
		out, err := e.adbCmd(serial, 10*time.Minute, "install", "-r", "-g", path)
		if err != nil && !strings.Contains(out, "Success") {
			return lastLine(out), fmt.Errorf("install failed")
		}
		return out, nil
	}

	// Unpack the bundle's APKs to a temp dir.
	tmp, err := os.MkdirTemp("", "sift-splits-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	apks, err := extractAllAPKs(path, tmp)
	if err != nil {
		return err.Error(), fmt.Errorf("couldn't read the bundle")
	}
	if len(apks) == 0 {
		return "the bundle contains no APK files", fmt.Errorf("no apks in bundle")
	}

	// Drop ABI splits the device can't run. A split named config.<abi>.apk (e.g.
	// config.armeabi_v7a.apk) only installs on a matching device; installing an incompatible
	// one fails the whole bundle with NO_MATCHING_ABIS. Keep base + language/density splits +
	// only ABI splits the device supports.
	deviceABIs := e.deviceABIs(serial)
	kept, droppedABIs, hadABISplit, keptABISplit := filterSplitsForABI(apks, deviceABIs)

	// If the app's only native code is in an ABI split the device can't run, the app won't
	// work even if the base installs — warn clearly instead of a cryptic failure later.
	if hadABISplit && !keptABISplit && baseHasNoNativeLibs(pickBaseAPK(apks)) {
		return "", fmt.Errorf("this download has native code only for %s, but the emulator is %s. Get an arm64-v8a or universal build of the app, or use an ARM system image. (The download ships no compatible native libraries.)",
			strings.Join(droppedABIs, "/"), strings.Join(deviceABIs, "/"))
	}

	e.setState("installing", fmt.Sprintf("Installing %d APKs…", len(kept)))
	args := append([]string{"-s", serial, "install-multiple", "-r", "-g"}, kept...)
	out, err := e.run(10*time.Minute, e.adb, args...)
	if err != nil && !strings.Contains(out, "Success") {
		if strings.Contains(out, "NO_MATCHING_ABIS") {
			return "", fmt.Errorf("the app's native libraries don't match the emulator (%s). Use an arm64-v8a/universal build of the app, or an ARM system image.", strings.Join(deviceABIs, "/"))
		}
		// Fall back to just the base APK if install-multiple fails for another reason.
		if base := pickBaseAPK(apks); base != "" {
			if o2, e2 := e.adbCmd(serial, 10*time.Minute, "install", "-r", "-g", base); e2 == nil || strings.Contains(o2, "Success") {
				return o2, nil
			}
		}
		return lastLine(out), fmt.Errorf("install-multiple failed")
	}
	return out, nil
}

// deviceABIs returns the ABIs the device/emulator can run (primary first), e.g.
// ["x86_64","arm64-v8a"] on an x86_64 image with ARM translation.
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

// filterSplitsForABI keeps base + non-ABI splits (language/density) + ABI splits the device
// supports, and drops ABI splits it can't run. Returns the kept list, the dropped ABI names,
// and whether the bundle had any ABI split / kept a compatible one.
func filterSplitsForABI(apks, deviceABIs []string) (kept, dropped []string, hadABI, keptABI bool) {
	supported := map[string]bool{}
	for _, a := range deviceABIs {
		supported[normalizeABI(a)] = true
	}
	for _, p := range apks {
		abi := abiOfSplit(filepath.Base(p))
		if abi == "" {
			kept = append(kept, p) // base or language/density split — always keep
			continue
		}
		hadABI = true
		if supported[normalizeABI(abi)] {
			kept = append(kept, p)
			keptABI = true
		} else {
			dropped = appendUnique(dropped, abi)
		}
	}
	return kept, dropped, hadABI, keptABI
}

// abiOfSplit returns the ABI a config split targets, or "" if it isn't an ABI split.
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

// baseHasNoNativeLibs reports whether the base APK ships no lib/ entries (so all native code
// lives in ABI splits).
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

// extractAllAPKs unpacks every .apk entry from a bundle zip into dir, returning their paths
// with the base APK first (adb install-multiple wants the base listed first).
func extractAllAPKs(bundlePath, dir string) ([]string, error) {
	zr, err := zip.OpenReader(bundlePath)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	var apks []string
	for _, f := range zr.File {
		if !strings.HasSuffix(strings.ToLower(f.Name), ".apk") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		outPath := filepath.Join(dir, filepath.Base(f.Name))
		out, err := os.Create(outPath)
		if err != nil {
			rc.Close()
			continue
		}
		io.Copy(out, rc)
		out.Close()
		rc.Close()
		apks = append(apks, outPath)
	}
	// base first
	if base := pickBaseAPK(apks); base != "" {
		ordered := []string{base}
		for _, p := range apks {
			if p != base {
				ordered = append(ordered, p)
			}
		}
		apks = ordered
	}
	return apks, nil
}

// pickBaseAPK chooses the base (non-split) APK from a list of extracted APK paths.
func pickBaseAPK(apks []string) string {
	for _, p := range apks {
		bn := strings.ToLower(filepath.Base(p))
		if bn == "base.apk" {
			return p
		}
	}
	for _, p := range apks {
		bn := strings.ToLower(filepath.Base(p))
		if !strings.HasPrefix(bn, "config.") && !strings.Contains(bn, "split_config") && !strings.Contains(bn, ".config.") {
			return p // first non-config APK
		}
	}
	if len(apks) > 0 {
		return apks[0]
	}
	return ""
}

// detectPackage reads the package name from an installed APK via adb (pm/aapt not needed).
func (e *Emulator) detectPackage(serial, apkPath string) string {
	// `adb install` already put it on the device; get the most recently installed 3rd-party pkg.
	out, _ := e.adbCmd(serial, 10*time.Second, "shell", "pm", "list", "packages", "-3")
	pkgs := strings.Split(out, "\n")
	if len(pkgs) > 0 {
		last := strings.TrimSpace(pkgs[len(pkgs)-1])
		return strings.TrimPrefix(last, "package:")
	}
	return ""
}

// trackForeground keeps the current app name available so traffic can be tagged with it.
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
	}
}

// Stop shuts down the emulator Sift started (leaves pre-existing devices alone unless asked).
func (e *Emulator) Stop() {
	e.mu.Lock()
	serial, cancel, proc := e.serial, e.cancel, e.proc
	e.state = "stopping"
	e.mu.Unlock()
	e.app.mobile.Changed(0)

	e.stopFrida()
	if cancel != nil {
		cancel()
	}
	if serial != "" {
		e.clearProxy(serial)
		e.adbCmd(serial, 10*time.Second, "emu", "kill")
	}
	if proc != nil {
		time.AfterFunc(5*time.Second, func() {
			if proc.ProcessState == nil {
				proc.Process.Kill()
			}
		})
	}
	e.mu.Lock()
	e.state, e.serial, e.pkg, e.appName, e.proc, e.cancel = "idle", "", "", "", nil, nil
	e.message = "Emulator stopped."
	e.mu.Unlock()
	e.app.mobile.Changed(0)
	e.app.store.hub.StateChanged()
}

// EmulatorApp returns the label of the app currently running in the emulator, if any, so
// loopback traffic from it can be tagged in the Traffic view.
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

// androidCertHash computes the <subject_hash>.0 filename Android uses for a system CA.
// It's the first 4 bytes of SHA-1 over the DER-encoded subject, in OpenSSL's old-hash order.
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
	sum := sha1.Sum(subject)
	// OpenSSL subject_hash_old: first 4 bytes, little-endian, as 8 hex digits.
	h := uint32(sum[0]) | uint32(sum[1])<<8 | uint32(sum[2])<<16 | uint32(sum[3])<<24
	return fmt.Sprintf("%08x", h), nil
}

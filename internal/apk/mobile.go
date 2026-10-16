package apk

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"sift/internal/sysproxy"
)

type Analyser struct {
	store *MobileStore
	tools *Tools
	work  string
}

func NewAnalyser(home string, store *MobileStore, tools *Tools) *Analyser {
	work := filepath.Join(home, "analysis")
	os.MkdirAll(work, 0o755)

	if entries, err := os.ReadDir(work); err == nil {
		for _, e := range entries {
			os.RemoveAll(filepath.Join(work, e.Name()))
		}
	}
	return &Analyser{store: store, tools: tools, work: work}
}

func cleanupReport(r *Report) {
	if r.SrcDir != "" {

		os.RemoveAll(filepath.Dir(r.SrcDir))
	}
}

var androidMagic = []byte("AndroidManifest.xml")

func (a *Analyser) Analyse(name string, data []byte) (*Report, error) {
	kind, why := detectKind(name, data)
	if kind == "" {
		return nil, fmt.Errorf("%s", why)
	}
	dir := filepath.Join(a.work, fmt.Sprintf("%d-%s", time.Now().UnixNano(), sanitize(name)))
	os.MkdirAll(dir, 0o755)
	inPath := filepath.Join(dir, sanitize(name))
	if err := os.WriteFile(inPath, data, 0o644); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	r := &Report{Name: name, Kind: kind, Size: int64(len(data)), State: "queued", Progress: "Queued", InPath: inPath}
	a.store.Add(r)
	go a.run(r, inPath, dir)
	return r, nil
}

func detectKind(name string, data []byte) (kind, reason string) {
	lower := strings.ToLower(name)
	if len(data) < 100 {
		return "", "that file is empty or truncated — the download probably didn't finish. Re-download the app and try again."
	}

	head := bytes.TrimSpace(data[:min(len(data), 512)])
	if bytes.HasPrefix(bytes.ToLower(head), []byte("<!doctype")) || bytes.HasPrefix(bytes.ToLower(head), []byte("<html")) {
		return "", "that's a web page, not an app. The download gave back an HTML page — open the app's page in a browser and download the actual file."
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", "that file isn't a valid app package (couldn't read it as a zip). It may be corrupted or an unsupported format."
	}
	hasManifest, hasPayload, hasDex, hasInnerAPK := false, false, false, false
	for _, f := range zr.File {
		switch {
		case f.Name == "AndroidManifest.xml":
			hasManifest = true
		case strings.HasPrefix(f.Name, "Payload/") && strings.Contains(f.Name, ".app/"):
			hasPayload = true
		case strings.HasSuffix(f.Name, ".dex"):
			hasDex = true
		case strings.HasSuffix(strings.ToLower(f.Name), ".apk"):
			hasInnerAPK = true
		}
	}
	switch {
	case hasPayload || strings.HasSuffix(lower, ".ipa"):
		return "ipa", ""
	case hasManifest || hasDex:
		return "apk", ""
	case hasInnerAPK || strings.HasSuffix(lower, ".xapk") || strings.HasSuffix(lower, ".apks") || strings.HasSuffix(lower, ".apkm"):
		return "apk", ""
	case strings.HasSuffix(lower, ".aab"):
		return "apk", ""
	case strings.HasSuffix(lower, ".apk"):
		return "", "that .apk doesn't contain any Android code (no AndroidManifest.xml or classes.dex). The download may be incomplete."
	}
	return "", "not an APK or IPA. Supported: .apk, .xapk, .apks, .aab, and .ipa."
}

func IsPlainAPK(path string) bool {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return true
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name == "AndroidManifest.xml" || strings.HasSuffix(f.Name, ".dex") {
			return true
		}
	}
	return false
}

func extractBaseAPK(inPath, dir string) string {
	zr, err := zip.OpenReader(inPath)
	if err != nil {
		return ""
	}
	defer zr.Close()

	var base *zip.File
	var fallback *zip.File
	for _, f := range zr.File {
		n := strings.ToLower(f.Name)
		if !strings.HasSuffix(n, ".apk") || strings.Contains(n, "/") && strings.Count(n, "/") > 1 {
			continue
		}
		bn := filepath.Base(n)
		if strings.HasPrefix(bn, "config.") || strings.Contains(bn, "split_config") || strings.Contains(bn, ".config.") {
			continue
		}
		if fallback == nil {
			fallback = f
		}
		if bn == "base.apk" || strings.Contains(bn, "base") {
			base = f
			break
		}
	}
	if base == nil {
		base = fallback
	}
	if base == nil {
		return ""
	}
	rc, err := base.Open()
	if err != nil {
		return ""
	}
	defer rc.Close()
	outPath := filepath.Join(dir, "base.apk")
	out, err := os.Create(outPath)
	if err != nil {
		return ""
	}
	defer out.Close()
	if _, err := io.Copy(out, rc); err != nil {
		return ""
	}
	return outPath
}

func (a *Analyser) run(r *Report, inPath, dir string) {
	defer func() {
		if rec := recover(); rec != nil {
			r.set(func() { r.State = "error"; r.Error = fmt.Sprint(rec) })
			a.store.Changed(r.ID)
		}
	}()
	var err error
	if r.Kind == "apk" {
		err = a.runAPK(r, inPath, dir)
	} else {
		err = a.runIPA(r, inPath, dir)
	}
	if err != nil {
		r.set(func() { r.State = "error"; r.Error = err.Error() })
	} else {
		r.set(func() {
			r.State = "done"
			r.Progress = fmt.Sprintf("Done · %d findings", len(r.Findings))
		})
	}
	a.store.Changed(r.ID)
}

func (a *Analyser) runAPK(r *Report, inPath, dir string) error {

	if !IsPlainAPK(inPath) {
		if base := extractBaseAPK(inPath, dir); base != "" {
			inPath = base
			r.set(func() { r.Progress = "Found a split-APK bundle; using the base APK…" })
			a.store.Changed(r.ID)
		}
	}
	jadx := a.tools.JadxPath()
	if jadx == "" {
		r.set(func() { r.State = "downloading-tool"; r.Progress = "Downloading jadx (first time only)…" })
		a.store.Changed(r.ID)
		done := make(chan error, 1)
		a.tools.EnsureJadx(func(ok bool, msg string) {
			if ok {
				done <- nil
			} else {
				done <- fmt.Errorf("%s", msg)
			}
		})
		if err := <-done; err != nil {
			return err
		}
		jadx = a.tools.JadxPath()
	}

	out := filepath.Join(dir, "src")
	r.set(func() {
		r.Platform = "Android"
		r.Signer = apkSigner(inPath)
	})

	if err := a.quickScanAPK(r, inPath, out); err != nil {
		return err
	}

	if dexMB := totalDexMB(inPath); dexMB <= jadxHeapMB()*3/2 {
		go a.decompileInBackground(r, inPath, dir)
	}
	return nil
}

func (a *Analyser) decompileInBackground(r *Report, inPath, dir string) {
	defer func() { recover() }()
	jadx := a.tools.JadxPath()
	if jadx == "" {
		a.tools.EnsureJadx(nil)
		jadx = a.tools.JadxPath()
		if jadx == "" {
			return
		}
	}
	out := filepath.Join(dir, "decompiled")
	heaps := []int{jadxHeapMB()}
	if half := heaps[0] / 2; half >= 512 {
		heaps = append(heaps, half)
	}
	for _, heapMB := range heaps {
		os.RemoveAll(out)
		msg, err := a.runJadx(jadx, inPath, out, dir, heapMB)
		if err == nil {
			break
		}
		if !isMemoryError(msg) {
			return
		}
	}
	if !dirHasFiles(out) {
		return
	}

	r.Lock().Lock()
	haveManifest := r.Package != ""
	r.Lock().Unlock()
	if manifest := findFile(out, "AndroidManifest.xml"); manifest != "" && !haveManifest {
		a.readManifest(r, manifest)
	}
	r.set(func() {
		r.SrcDir = out
		r.QuickScan = false
	})
	a.store.Changed(r.ID)
}

func totalDexMB(inPath string) int {
	zr, err := zip.OpenReader(inPath)
	if err != nil {
		return 0
	}
	defer zr.Close()
	var total uint64
	for _, f := range zr.File {
		if strings.HasSuffix(strings.ToLower(f.Name), ".dex") {
			total += f.UncompressedSize64
		}
	}
	return int(total / (1024 * 1024))
}

func (a *Analyser) readManifest(r *Report, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	type intentFilter struct {
		Data []struct {
			Scheme string `xml:"scheme,attr"`
			Host   string `xml:"host,attr"`
		} `xml:"data"`
	}
	type comp struct {
		Name     string         `xml:"name,attr"`
		Exported string         `xml:"exported,attr"`
		Filters  []intentFilter `xml:"intent-filter"`
	}
	var m struct {
		Package     string `xml:"package,attr"`
		VersionName string `xml:"versionName,attr"`
		VersionCode string `xml:"versionCode,attr"`
		UsesSDK     struct {
			Min    string `xml:"minSdkVersion,attr"`
			Target string `xml:"targetSdkVersion,attr"`
		} `xml:"uses-sdk"`
		UsesPerms []struct {
			Name string `xml:"name,attr"`
		} `xml:"uses-permission"`
		App struct {
			Label         string `xml:"label,attr"`
			Cleartext     string `xml:"usesCleartextTraffic,attr"`
			NetworkConfig string `xml:"networkSecurityConfig,attr"`
			Activities    []comp `xml:"activity"`
			Services      []comp `xml:"service"`
			Receivers     []comp `xml:"receiver"`
			Providers     []comp `xml:"provider"`
		} `xml:"application"`
	}
	if xml.Unmarshal(data, &m) != nil {
		return
	}
	r.set(func() {
		r.Package = m.Package
		r.Version = m.VersionName
		r.Build = m.VersionCode
		r.MinSDK = m.UsesSDK.Min
		r.TargetSDK = m.UsesSDK.Target
		if m.App.Label != "" && !strings.HasPrefix(m.App.Label, "@") {
			r.Label = m.App.Label
		}
		for _, p := range m.UsesPerms {
			r.Permissions = append(r.Permissions, shortPerm(p.Name))
		}
		add := func(typ string, cs []comp) {
			for _, c := range cs {
				exported := c.Exported == "true" || (c.Exported == "" && len(c.Filters) > 0)
				r.Components = append(r.Components, Component{Type: typ, Name: c.Name, Exported: exported})
				for _, f := range c.Filters {
					for _, d := range f.Data {
						if d.Scheme != "" && d.Scheme != "http" && d.Scheme != "https" {
							link := d.Scheme + "://" + d.Host
							r.DeepLinks = AppendUnique(r.DeepLinks, link)
						}
					}
				}
			}
		}
		add("activity", m.App.Activities)
		add("service", m.App.Services)
		add("receiver", m.App.Receivers)
		add("provider", m.App.Providers)
		if m.App.Cleartext == "true" {
			r.Cleartext = true
			r.CleartextNote = "android:usesCleartextTraffic=\"true\" — the app allows plain HTTP"
		}
		if m.App.NetworkConfig != "" {
			r.CleartextNote = "has a network security config (" + m.App.NetworkConfig + ") — check it for cleartext/pinning rules"
		}
	})
}

func (a *Analyser) runIPA(r *Report, inPath, dir string) error {
	r.set(func() { r.State = "decompiling"; r.Progress = "Extracting the IPA…" })
	a.store.Changed(r.ID)
	out := filepath.Join(dir, "src")
	if err := unzipTo(inPath, out); err != nil {
		return err
	}
	r.set(func() { r.SrcDir = out; r.Platform = "iOS" })

	appDir := findAppDir(out)
	if appDir != "" {
		if plist := filepath.Join(appDir, "Info.plist"); FileExists(plist) {
			a.readInfoPlist(r, plist)
		}

		if bin := machoBinary(appDir, r.Label); bin != "" {
			a.dumpStrings(bin, filepath.Join(out, "_binary_strings.txt"))
		}

		if prov := filepath.Join(appDir, "embedded.mobileprovision"); FileExists(prov) {
			a.dumpProvisionStrings(prov, filepath.Join(out, "_entitlements.txt"))
		}
	}
	return a.scan(r, out)
}

func (a *Analyser) readInfoPlist(r *Report, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	v, err := parsePlist(data)
	if err != nil {
		return
	}
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	str := func(k string) string { s, _ := m[k].(string); return s }
	r.set(func() {
		r.Package = str("CFBundleIdentifier")
		r.Label = FirstNonEmpty(str("CFBundleDisplayName"), str("CFBundleName"))
		r.Version = str("CFBundleShortVersionString")
		r.Build = str("CFBundleVersion")
		r.MinSDK = str("MinimumOSVersion")

		if types, ok := m["CFBundleURLTypes"].([]any); ok {
			for _, t := range types {
				if tm, ok := t.(map[string]any); ok {
					if schemes, ok := tm["CFBundleURLSchemes"].([]any); ok {
						for _, s := range schemes {
							if ss, ok := s.(string); ok {
								r.DeepLinks = AppendUnique(r.DeepLinks, ss+"://")
							}
						}
					}
				}
			}
		}

		if ats, ok := m["NSAppTransportSecurity"].(map[string]any); ok {
			if allow, _ := ats["NSAllowsArbitraryLoads"].(bool); allow {
				r.Cleartext = true
				r.CleartextNote = "NSAllowsArbitraryLoads = true — ATS is disabled, the app allows plain HTTP"
			}
			if ex, ok := ats["NSExceptionDomains"].(map[string]any); ok {
				for dom := range ex {
					r.CleartextNote = FirstNonEmpty(r.CleartextNote, "has ATS exception domains")
					r.Permissions = AppendUnique(r.Permissions, "ATS exception: "+dom)
				}
			}
		}

		for k, val := range m {
			if strings.HasSuffix(k, "UsageDescription") {
				if desc, ok := val.(string); ok {
					r.Permissions = AppendUnique(r.Permissions, prettyUsage(k)+": "+Clip(desc, 60))
				}
			}
		}
	})
}

func (a *Analyser) scan(r *Report, root string) error {
	r.set(func() { r.State = "scanning"; r.Progress = "Scanning for endpoints, secrets and pinning…" })
	a.store.Changed(r.ID)
	last := time.Now()
	r.set(func() { r.ScanDir = root })
	res := scanTree(scanConfig{
		root:        root,
		maxFileSize: 512 << 20,
		onProgress: func(files int) {
			if time.Since(last) > 400*time.Millisecond {
				last = time.Now()
				r.set(func() { r.Progress = fmt.Sprintf("Scanning… %d files", files) })
				a.store.Changed(r.ID)
			}
		},
	})
	r.set(func() {
		r.Findings = res.Findings
		r.recount()
	})
	return nil
}

func (a *Analyser) dumpStrings(binPath, outPath string) {
	data, err := os.ReadFile(binPath)
	if err != nil {
		return
	}
	out, err := os.Create(outPath)
	if err != nil {
		return
	}
	defer out.Close()
	w := bytesWriter{out}

	start := -1
	for i, b := range data {
		printable := b >= 0x20 && b < 0x7f
		if printable {
			if start < 0 {
				start = i
			}
		} else {
			if start >= 0 && i-start >= 5 {
				w.line(data[start:i])
			}
			start = -1
		}
		if i > 400<<20 {
			break
		}
	}
	if start >= 0 && len(data)-start >= 5 {
		w.line(data[start:])
	}
}

type bytesWriter struct{ w io.Writer }

func (b bytesWriter) line(s []byte) { b.w.Write(s); b.w.Write([]byte{'\n'}) }

func (a *Analyser) dumpProvisionStrings(provPath, outPath string) {
	data, err := os.ReadFile(provPath)
	if err != nil {
		return
	}

	if i := bytes.Index(data, []byte("<?xml")); i >= 0 {
		if j := bytes.LastIndex(data, []byte("</plist>")); j > i {
			os.WriteFile(outPath, data[i:j+len("</plist>")], 0o644)
		}
	}
}

func (a *Analyser) runJadx(jadx, inPath, out, dir string, heapMB int) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, jadx, "-d", out, "-j", "4", "--log-level", "ERROR", inPath)
	sysproxy.HideWindow(cmd)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), fmt.Sprintf("JADX_OPTS=-Xmx%dm -XX:MaxRAMPercentage=25 -XX:+UseSerialGC -Xss4m", heapMB))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	msg := strings.TrimSpace(stderr.String())
	if dirHasFiles(out) {
		return msg, nil
	}
	if msg == "" && runErr != nil {
		msg = runErr.Error()
	}
	return msg, fmt.Errorf("no output")
}

func isMemoryError(msg string) bool {
	m := strings.ToLower(msg)
	return strings.Contains(m, "paging file") || strings.Contains(m, "outofmemory") ||
		strings.Contains(m, "commit_memory") || strings.Contains(m, "could not reserve") ||
		strings.Contains(m, "insufficient memory") || strings.Contains(m, "cannot allocate") ||
		strings.Contains(m, "gc overhead limit")
}

func jadxHeapMB() int {
	const floor, ceil = 512, 4096
	avail := sysproxy.AvailableCommitMB()
	want := 3072
	if avail > 0 {

		budget := avail/2 - 256
		if budget < want {
			want = budget
		}
	}
	if want < floor {
		want = floor
	}
	if want > ceil {
		want = ceil
	}
	return want
}

func dirHasFiles(dir string) bool {
	found := false
	filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func findFile(root, name string) string {
	var hit string
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == name {
			hit = path
			return filepath.SkipAll
		}
		return nil
	})
	return hit
}

func findAppDir(root string) string {
	payload := filepath.Join(root, "Payload")
	entries, err := os.ReadDir(payload)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasSuffix(e.Name(), ".app") {
			return filepath.Join(payload, e.Name())
		}
	}
	return ""
}

func machoBinary(appDir, label string) string {

	base := strings.TrimSuffix(filepath.Base(appDir), ".app")
	candidates := []string{base, label}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		p := filepath.Join(appDir, c)
		if FileExists(p) {
			return p
		}
	}

	var best string
	var bestSize int64
	entries, _ := os.ReadDir(appDir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, _ := e.Info()
		p := filepath.Join(appDir, e.Name())
		if info != nil && info.Size() > bestSize && isMachO(p) {
			best, bestSize = p, info.Size()
		}
	}
	return best
}

func isMachO(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	io.ReadFull(f, magic[:])
	switch {
	case magic == [4]byte{0xcf, 0xfa, 0xed, 0xfe},
		magic == [4]byte{0xce, 0xfa, 0xed, 0xfe},
		magic == [4]byte{0xca, 0xfe, 0xba, 0xbe},
		magic == [4]byte{0xbe, 0xba, 0xfe, 0xca}:
		return true
	}
	return false
}

func apkSigner(inPath string) string {

	zr, err := zip.OpenReader(inPath)
	if err != nil {
		return ""
	}
	defer zr.Close()
	v1, v2 := false, false
	for _, f := range zr.File {
		u := strings.ToUpper(f.Name)
		if strings.HasPrefix(u, "META-INF/") && (strings.HasSuffix(u, ".RSA") || strings.HasSuffix(u, ".DSA") || strings.HasSuffix(u, ".EC")) {
			v1 = true
		}
	}

	if data, err := os.ReadFile(inPath); err == nil {
		v2 = bytes.Contains(data, []byte("APK Sig Block 42"))
	}
	switch {
	case v2:
		return "signed (v2/v3 scheme)"
	case v1:
		return "signed (v1 / JAR scheme only)"
	}
	return "unsigned or unknown"
}

var permPrefix = regexp.MustCompile(`^android\.permission\.`)

func shortPerm(p string) string { return permPrefix.ReplaceAllString(p, "") }

func prettyUsage(k string) string {
	k = strings.TrimPrefix(k, "NS")
	k = strings.TrimSuffix(k, "UsageDescription")
	var out strings.Builder
	for i, c := range k {
		if i > 0 && c >= 'A' && c <= 'Z' {
			out.WriteByte(' ')
		}
		out.WriteRune(c)
	}
	return out.String()
}

func AppendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func FirstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func sanitize(name string) string {
	name = filepath.Base(name)
	name = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, name)
	if name == "" || name == "." {
		h := sha256.Sum256([]byte(name))
		return "app-" + hex.EncodeToString(h[:4])
	}
	return name
}

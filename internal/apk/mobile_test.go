package apk

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPlistXML(t *testing.T) {
	data := []byte(`<?xml version="1.0"?><!DOCTYPE plist><plist version="1.0"><dict>
	<key>CFBundleIdentifier</key><string>com.example.app</string>
	<key>CFBundleURLTypes</key><array><dict><key>CFBundleURLSchemes</key><array><string>myapp</string></array></dict></array>
	<key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict>
	<key>NSCameraUsageDescription</key><string>We need the camera</string>
	</dict></plist>`)
	v, err := parsePlist(data)
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	if m["CFBundleIdentifier"] != "com.example.app" {
		t.Errorf("bundle id = %v", m["CFBundleIdentifier"])
	}
	ats := m["NSAppTransportSecurity"].(map[string]any)
	if ats["NSAllowsArbitraryLoads"] != true {
		t.Errorf("ATS = %v", ats)
	}
}

func TestScanner(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "Api.java"), []byte(`
public class Api {
  String base = "https://api.example.com/v1/login";
  String key = "AIzaSyA1234567890123456789012345678901234";
  CertificatePinner pinner = new CertificatePinner.Builder().build();
  void recaptcha() { loadUrl("https://www.google.com/recaptcha/api.js"); }
}`), 0o644)
	res := scanTree(scanConfig{root: dir})
	kinds := map[string]bool{}
	for _, f := range res.Findings {
		kinds[f.Kind+"/"+f.Subtype] = true
	}
	for _, want := range []string{"endpoint/URL", "secret/Google API key", "pinning/OkHttp CertificatePinner", "auth/reCAPTCHA", "auth/Login endpoint"} {
		if !kinds[want] {
			t.Errorf("missing finding: %s (got %v)", want, kinds)
		}
	}
}

func TestFindingFilesStayReachableAfterDecompile(t *testing.T) {
	dir := t.TempDir()
	quick := filepath.Join(dir, "src")
	os.MkdirAll(filepath.Join(quick, "strings"), 0o755)
	os.WriteFile(filepath.Join(quick, "strings", "classes.dex.txt"), []byte("https://api.example.com/v1/x\n"), 0o644)

	r := &Report{}
	a := &Analyser{store: NewMobileStore()}
	a.scan(r, quick)
	if len(r.Findings) == 0 {
		t.Fatal("no findings from the strings dump")
	}
	r.set(func() { r.SrcDir = filepath.Join(dir, "decompiled") })

	file := r.Findings[0].File
	found := false
	for _, root := range r.SourceRoots() {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(file))); err == nil {
			found = true
		}
	}
	if !found {
		t.Errorf("%s not reachable from roots %v", file, r.SourceRoots())
	}
}

func TestResourceLabel(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "res", "values"), 0o755)
	manifest := filepath.Join(dir, "AndroidManifest.xml")
	os.WriteFile(manifest, []byte(`<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.epicgames.portal"><application android:label="@string/app_name"/></manifest>`), 0o644)
	os.WriteFile(filepath.Join(dir, "res", "values", "strings.xml"), []byte(`<resources><string name="other">x</string><string name="app_name">Epic Games</string></resources>`), 0o644)
	if got := resourceLabel(manifest); got != "Epic Games" {
		t.Errorf("resourceLabel = %q, want Epic Games", got)
	}
}

func TestSplitConcatURLs(t *testing.T) {
	got := splitConcatURLs("https://a.com/xhttps://b.com/y")
	if len(got) != 2 || got[0] != "https://a.com/x" || got[1] != "https://b.com/y" {
		t.Errorf("split = %v", got)
	}
	got = splitConcatURLs("https://a.com/path/AIzaSyABCDEFGHIJKLMNOPQRSTUV")
	if got[0] != "https://a.com/path/" {
		t.Errorf("trim trailing = %q", got[0])
	}
}

func TestScanMasksSecrets(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.java"), []byte(`String k = "AKIAIOSFODNN7EXAMPLE";`), 0o644)
	res := scanTree(scanConfig{root: dir})
	for _, f := range res.Findings {
		if f.Kind == "secret" && f.Value == "AKIAIOSFODNN7EXAMPLE" {
			t.Errorf("secret not masked: %s", f.Value)
		}
	}
}

func TestDexStrings(t *testing.T) {

	s := "https://api.test.com/login"
	dex := buildMiniDex(s)
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.txt")
	writeDexStrings(dex, outPath)
	data, _ := os.ReadFile(outPath)
	if !containsStr(string(data), s) {
		t.Errorf("dex string not extracted: got %q", string(data))
	}
}

func TestMemoryErrorAndHeap(t *testing.T) {
	for _, m := range []string{
		"os::commit_memory(0x...) failed; error='The paging file is too small'",
		"java.lang.OutOfMemoryError: Java heap space",
		"Could not reserve enough space for object heap",
		"GC overhead limit exceeded",
	} {
		if !isMemoryError(m) {
			t.Errorf("should be a memory error: %q", m)
		}
	}
	if isMemoryError("jadx: unknown option") {
		t.Error("false positive on a non-memory error")
	}
	if h := jadxHeapMB(); h < 512 || h > 4096 {
		t.Errorf("heap out of bounds: %d", h)
	}
}

func TestDetectKind(t *testing.T) {
	apk := makeZip(t, map[string][]byte{"AndroidManifest.xml": []byte("x"), "classes.dex": []byte("d")})
	if k, _ := detectKind("app.apk", apk); k != "apk" {
		t.Errorf("apk detect = %q", k)
	}
	ipa := makeZip(t, map[string][]byte{"Payload/Foo.app/Info.plist": []byte("x"), "Payload/Foo.app/Foo": []byte("b")})
	if k, _ := detectKind("app.ipa", ipa); k != "ipa" {
		t.Errorf("ipa detect = %q", k)
	}

	inner := makeZip(t, map[string][]byte{"AndroidManifest.xml": []byte("x"), "classes.dex": []byte("d")})
	xapk := makeZip(t, map[string][]byte{"base.apk": inner, "config.arm64_v8a.apk": []byte("split")})
	if k, _ := detectKind("app.xapk", xapk); k != "apk" {
		t.Errorf("xapk detect = %q", k)
	}
}

func TestDetectKindRejects(t *testing.T) {
	cases := []struct {
		name     string
		data     []byte
		wantWord string
	}{
		{"empty.apk", []byte{}, "empty or truncated"},
		{"stub.apk", []byte("x"), "empty or truncated"},
		{"page.apk", []byte("<!DOCTYPE html><html><body>Not found</body></html>" + string(make([]byte, 100))), "web page"},
		{"notes.txt", append([]byte("hello this is just text "), make([]byte, 200)...), "valid app package"},
	}
	for _, c := range cases {
		k, reason := detectKind(c.name, c.data)
		if k != "" {
			t.Errorf("%s: expected rejection, got kind %q", c.name, k)
		}
		if !containsStr(reason, c.wantWord) {
			t.Errorf("%s: reason %q should mention %q", c.name, reason, c.wantWord)
		}
	}
}

func TestExtractBaseAPK(t *testing.T) {
	dir := t.TempDir()
	inner := makeZip(t, map[string][]byte{"AndroidManifest.xml": []byte("manifest"), "classes.dex": []byte("dex")})
	xapk := makeZip(t, map[string][]byte{
		"base.apk":             inner,
		"config.en.apk":        []byte("english split"),
		"config.arm64_v8a.apk": []byte("abi split"),
	})
	src := filepath.Join(dir, "app.xapk")
	os.WriteFile(src, xapk, 0o644)
	got := extractBaseAPK(src, dir)
	if got == "" {
		t.Fatal("extractBaseAPK returned nothing")
	}
	data, _ := os.ReadFile(got)
	if len(data) != len(inner) {
		t.Errorf("extracted base = %d bytes, want %d (the base.apk, not a split)", len(data), len(inner))
	}
	if IsPlainAPK(got) != true {
		t.Error("extracted base should be a plain APK")
	}
}

func TestExtractAllAPKs(t *testing.T) {
	dir := t.TempDir()

	xapk := makeZip(t, map[string][]byte{
		"config.en.apk":     []byte("lang split"),
		"config.xxhdpi.apk": []byte("density split"),
		"base.apk":          []byte("the base apk bytes"),
		"manifest.json":     []byte("{}"),
	})
	src := filepath.Join(dir, "app.xapk")
	os.WriteFile(src, xapk, 0o644)
	out := t.TempDir()
	apks, err := ExtractAllAPKs(src, out)
	if err != nil {
		t.Fatal(err)
	}
	if len(apks) != 3 {
		t.Fatalf("got %d apks, want 3 (manifest.json excluded): %v", len(apks), apks)
	}
	if filepath.Base(apks[0]) != "base.apk" {
		t.Errorf("base.apk must be first for install-multiple, got %s", filepath.Base(apks[0]))
	}
	if b := PickBaseAPK(apks); filepath.Base(b) != "base.apk" {
		t.Errorf("pickBaseAPK = %s, want base.apk", filepath.Base(b))
	}

	noBase := []string{"/x/config.en.apk", "/x/split_feature.apk", "/x/config.arm64.apk"}
	if b := PickBaseAPK(noBase); filepath.Base(b) != "split_feature.apk" {
		t.Errorf("pickBaseAPK fallback = %s, want split_feature.apk", filepath.Base(b))
	}
}

func containsStr(h, sub string) bool {
	for i := 0; i+len(sub) <= len(h); i++ {
		if h[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

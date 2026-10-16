package emulator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRAMMB(t *testing.T) {
	for in, want := range map[string]int{"2G": 2048, "2048": 2048, "1536M": 1536, "4GB": 4096, "": 0} {
		if got := parseRAMMB(in); got != want {
			t.Errorf("parseRAMMB(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestSiftAVDPicksRootableImage(t *testing.T) {
	sdk := t.TempDir()
	abi, _ := hostABI()
	for _, p := range []string{
		"android-36.1/google_apis_playstore",
		"android-34/google_apis",
		"android-29/google_apis",
	} {
		dir := filepath.Join(sdk, "system-images", filepath.FromSlash(p), abi)
		os.MkdirAll(dir, 0o755)
		os.WriteFile(filepath.Join(dir, "system.img"), []byte("x"), 0o644)
	}
	img, err := pickSystemImage(sdk)
	if err != nil || img.api != 34 || img.tag != "google_apis" {
		t.Fatalf("picked %+v, %v; want android-34 google_apis", img, err)
	}

	home := t.TempDir()
	t.Setenv("ANDROID_AVD_HOME", home)
	e := &Emulator{sdk: sdk}
	if usable, ready, _ := e.SiftDeviceStatus(); !usable || ready {
		t.Fatalf("before create: usable=%v ready=%v", usable, ready)
	}
	if err := e.ensureSiftAVD(); err != nil {
		t.Fatal(err)
	}
	cfg := avdConfig(SiftAVD)
	if cfg["tag.id"] != "google_apis" || cfg["hw.gpu.enabled"] != "yes" || !strings.Contains(cfg["image.sysdir.1"], "android-34") {
		t.Errorf("config = %v", cfg)
	}
	if _, ready, _ := e.SiftDeviceStatus(); !ready {
		t.Error("Sift AVD should be ready after create")
	}
	args := strings.Join(bootArgs(SiftAVD), " ")
	if strings.Contains(args, "-memory") || strings.Contains(args, "-writable-system") || strings.Contains(args, "-no-snapshot") || !strings.Contains(args, "-gpu auto") {
		t.Errorf("boot args = %s", args)
	}
}

func TestPlayStoreOnlyIsRefused(t *testing.T) {
	sdk := t.TempDir()
	abi, _ := hostABI()
	dir := filepath.Join(sdk, "system-images", "android-36", "google_apis_playstore", abi)
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "system.img"), []byte("x"), 0o644)
	if _, err := pickSystemImage(sdk); err == nil || !strings.Contains(err.Error(), "Play Store") {
		t.Errorf("err = %v, want a Play Store explanation", err)
	}
}

func TestABISplitFiltering(t *testing.T) {

	cases := map[string]string{
		"config.armeabi_v7a.apk":   "armeabi-v7a",
		"config.arm64_v8a.apk":     "arm64-v8a",
		"config.x86_64.apk":        "x86-64",
		"config.en.apk":            "",
		"config.hdpi.apk":          "",
		"base.apk":                 "",
		"com.reddit.frontpage.apk": "",
	}
	for name, want := range cases {
		if got := abiOfSplit(name); got != want {
			t.Errorf("abiOfSplit(%q) = %q, want %q", name, got, want)
		}
	}

	apks := []string{"/x/base.apk", "/x/config.en.apk", "/x/config.hdpi.apk", "/x/config.armeabi_v7a.apk"}
	kept, dropped, hadABI, keptABI := filterSplitsForABI(apks, []string{"x86_64", "arm64-v8a"})
	if len(kept) != 3 {
		t.Errorf("kept %d, want 3 (base+en+hdpi): %v", len(kept), kept)
	}
	if !hadABI || keptABI {
		t.Errorf("hadABI=%v keptABI=%v, want true/false", hadABI, keptABI)
	}
	if len(dropped) != 1 || dropped[0] != "armeabi-v7a" {
		t.Errorf("dropped = %v, want [armeabi-v7a]", dropped)
	}

	apks2 := []string{"/x/base.apk", "/x/config.arm64_v8a.apk"}
	_, _, _, keptABI2 := filterSplitsForABI(apks2, []string{"x86_64", "arm64-v8a"})
	if !keptABI2 {
		t.Error("arm64-v8a split should be kept on an x86_64+arm64 device")
	}
}

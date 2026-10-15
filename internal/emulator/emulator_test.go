package emulator

import "testing"

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

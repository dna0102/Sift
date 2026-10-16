package emulator

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"sift/internal/apk"
	"sift/internal/sysproxy"
)

const SiftAVD = "Sift"

func avdHome() string {
	if p := os.Getenv("ANDROID_AVD_HOME"); p != "" {
		return p
	}
	if p := os.Getenv("ANDROID_USER_HOME"); p != "" {
		return filepath.Join(p, "avd")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".android", "avd")
}

func avdDir(name string) string {
	if data, err := os.ReadFile(filepath.Join(avdHome(), name+".ini")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(line), "path="); ok && dirExists(v) {
				return v
			}
		}
	}
	if d := filepath.Join(avdHome(), name+".avd"); dirExists(d) {
		return d
	}
	return ""
}

func avdConfig(name string) map[string]string {
	cfg := map[string]string{}
	dir := avdDir(name)
	if dir == "" {
		return cfg
	}
	data, err := os.ReadFile(filepath.Join(dir, "config.ini"))
	if err != nil {
		return cfg
	}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			cfg[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return cfg
}

func hasQuickboot(avd string) bool {
	dir := avdDir(avd)
	return dir != "" && apk.FileExists(filepath.Join(dir, "snapshots", "default_boot", "snapshot.pb"))
}

func parseRAMMB(v string) int {
	v = strings.ToUpper(strings.TrimSpace(v))
	mult := 1
	switch {
	case strings.HasSuffix(v, "GB"), strings.HasSuffix(v, "G"):
		mult = 1024
	}
	n, _ := strconv.Atoi(strings.TrimRight(v, "GMB"))
	return n * mult
}

func guestRAMMB() int {
	avail := sysproxy.AvailableCommitMB()
	switch {
	case avail == 0 || avail >= 12000:
		return 4096
	case avail >= 7000:
		return 3072
	}
	return 2048
}

func guestCores() int {
	return min(4, max(2, runtime.NumCPU()/2))
}

func bootArgs(avd string) []string {
	args := []string{
		"-avd", avd,
		"-gpu", "auto",
		"-no-boot-anim",
		"-no-audio",
		"-camera-back", "none",
		"-camera-front", "none",
		"-netdelay", "none",
		"-netspeed", "full",
	}
	cfg := avdConfig(avd)
	if parseRAMMB(cfg["hw.ramSize"]) < 3072 {
		args = append(args, "-memory", strconv.Itoa(guestRAMMB()))
	}
	if n, _ := strconv.Atoi(cfg["hw.cpu.ncore"]); n < 2 {
		args = append(args, "-cores", strconv.Itoa(guestCores()))
	}
	return args
}

type systemImage struct {
	rel string
	api int
	tag string
	abi string
}

func hostABI() (abi, arch string) {
	if runtime.GOARCH == "arm64" {
		return "arm64-v8a", "arm64"
	}
	return "x86_64", "x86_64"
}

func imageScore(img systemImage) int {
	tagRank := map[string]int{"google_apis": 3, "default": 2}[img.tag]
	var apiRank int
	switch {
	case img.api == 34:
		apiRank = 50
	case img.api >= 30 && img.api < 34:
		apiRank = 40 + img.api - 30
	case img.api > 34:
		apiRank = 30 - (img.api - 35)
	default:
		apiRank = img.api - 20
	}
	return tagRank*100 + apiRank
}

func findSystemImages(sdk string) []systemImage {
	abi, _ := hostABI()
	var out []systemImage
	root := filepath.Join(sdk, "system-images")
	platforms, _ := os.ReadDir(root)
	for _, p := range platforms {
		apiStr, ok := strings.CutPrefix(p.Name(), "android-")
		if !ok {
			continue
		}
		api, err := strconv.Atoi(strings.SplitN(apiStr, ".", 2)[0])
		if err != nil {
			continue
		}
		tags, _ := os.ReadDir(filepath.Join(root, p.Name()))
		for _, t := range tags {
			dir := filepath.Join(root, p.Name(), t.Name(), abi)
			if _, err := os.Stat(filepath.Join(dir, "system.img")); err != nil {
				continue
			}
			rel := filepath.Join("system-images", p.Name(), t.Name(), abi) + string(os.PathSeparator)
			out = append(out, systemImage{rel: rel, api: api, tag: t.Name(), abi: abi})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return imageScore(out[i]) > imageScore(out[j]) })
	return out
}

func pickSystemImage(sdk string) (systemImage, error) {
	imgs := findSystemImages(sdk)
	for _, img := range imgs {
		if img.tag == "google_apis" || img.tag == "default" {
			return img, nil
		}
	}
	abi, _ := hostABI()
	if len(imgs) > 0 {
		return systemImage{}, fmt.Errorf("only Play Store system images are installed, and those can't be rooted, so Sift can't trust its certificate on them. In Android Studio open SDK Manager → SDK Platforms → Show Package Details, and install \"Google APIs %s System Image\" for Android 14 (API 34)", abi)
	}
	return systemImage{}, fmt.Errorf("no %s system image is installed. In Android Studio open SDK Manager → SDK Platforms → Show Package Details, and install \"Google APIs %s System Image\" for Android 14 (API 34)", abi, abi)
}

func (e *Emulator) SiftDeviceStatus() (usable, ready bool, note string) {
	if avdDir(SiftAVD) != "" {
		return true, true, ""
	}
	img, err := pickSystemImage(e.sdk)
	if err != nil {
		return false, false, err.Error()
	}
	return true, false, fmt.Sprintf("It will use Android %d (%s)", img.api, img.tag)
}

func (e *Emulator) ensureSiftAVD() error {
	if avdDir(SiftAVD) != "" {
		return nil
	}
	img, err := pickSystemImage(e.sdk)
	if err != nil {
		return err
	}
	_, arch := hostABI()
	home := avdHome()
	dir := filepath.Join(home, SiftAVD+".avd")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	config := []string{
		"avd.ini.encoding=UTF-8",
		"AvdId=" + SiftAVD,
		"avd.ini.displayname=" + SiftAVD,
		"abi.type=" + img.abi,
		"hw.cpu.arch=" + arch,
		"image.sysdir.1=" + img.rel,
		"tag.id=" + img.tag,
		"tag.ids=" + img.tag,
		"PlayStore.enabled=no",
		"hw.ramSize=" + strconv.Itoa(guestRAMMB()),
		"vm.heapSize=256",
		"hw.cpu.ncore=" + strconv.Itoa(guestCores()),
		"hw.gpu.enabled=yes",
		"hw.gpu.mode=auto",
		"hw.lcd.width=1080",
		"hw.lcd.height=1920",
		"hw.lcd.density=420",
		"hw.keyboard=yes",
		"hw.mainKeys=no",
		"hw.audioInput=no",
		"hw.audioOutput=no",
		"hw.camera.back=none",
		"hw.camera.front=none",
		"hw.initialOrientation=portrait",
		"disk.dataPartition.size=6G",
		"fastboot.forceColdBoot=no",
		"fastboot.forceFastBoot=yes",
		"showDeviceFrame=no",
		"runtime.network.latency=none",
		"runtime.network.speed=full",
	}
	if err := os.WriteFile(filepath.Join(dir, "config.ini"), []byte(strings.Join(config, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	ini := []string{
		"avd.ini.encoding=UTF-8",
		"path=" + dir,
		"path.rel=" + filepath.Join("avd", SiftAVD+".avd"),
		fmt.Sprintf("target=android-%d", img.api),
	}
	return os.WriteFile(filepath.Join(home, SiftAVD+".ini"), []byte(strings.Join(ini, "\n")+"\n"), 0o644)
}

package apk

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func ExtractAllAPKs(bundlePath, dir string) ([]string, error) {
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

	if base := PickBaseAPK(apks); base != "" {
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

func PickBaseAPK(apks []string) string {
	for _, p := range apks {
		bn := strings.ToLower(filepath.Base(p))
		if bn == "base.apk" {
			return p
		}
	}
	for _, p := range apks {
		bn := strings.ToLower(filepath.Base(p))
		if !strings.HasPrefix(bn, "config.") && !strings.Contains(bn, "split_config") && !strings.Contains(bn, ".config.") {
			return p
		}
	}
	if len(apks) > 0 {
		return apks[0]
	}
	return ""
}

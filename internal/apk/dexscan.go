package apk

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func (a *Analyser) quickScanAPK(r *Report, inPath, out string) error {
	os.MkdirAll(out, 0o755)
	r.set(func() { r.State = "scanning"; r.Progress = "Large app — scanning code and resources directly…" })
	a.store.Changed(r.ID)

	zr, err := zip.OpenReader(inPath)
	if err != nil {
		return err
	}
	defer zr.Close()

	for _, f := range zr.File {
		if f.Name == "AndroidManifest.xml" {
			if rc, err := f.Open(); err == nil {
				data, _ := io.ReadAll(io.LimitReader(rc, 8<<20))
				rc.Close()
				a.readBinaryManifest(r, data)
			}
			break
		}
	}

	strDir := filepath.Join(out, "strings")
	os.MkdirAll(strDir, 0o755)
	dexCount := 0
	for _, f := range zr.File {
		name := strings.ToLower(f.Name)
		switch {
		case strings.HasSuffix(name, ".dex"):
			dexCount++
			rc, err := f.Open()
			if err != nil {
				continue
			}
			data, _ := io.ReadAll(io.LimitReader(rc, 256<<20))
			rc.Close()
			outPath := filepath.Join(strDir, strings.ReplaceAll(f.Name, "/", "_")+".txt")
			writeDexStrings(data, outPath)
			r.set(func() { r.Progress = fmt.Sprintf("Scanning code… %d dex files", dexCount) })
			a.store.Changed(r.ID)
		case strings.HasSuffix(name, ".json"), strings.HasSuffix(name, ".js"), strings.HasSuffix(name, ".html"),
			strings.HasSuffix(name, ".xml") && !strings.HasPrefix(name, "res/"):

			if f.UncompressedSize64 < 4<<20 {
				if rc, err := f.Open(); err == nil {
					data, _ := io.ReadAll(io.LimitReader(rc, 4<<20))
					rc.Close()
					os.WriteFile(filepath.Join(strDir, strings.ReplaceAll(f.Name, "/", "_")), data, 0o644)
				}
			}
		}
	}
	r.set(func() { r.SrcDir = out; r.Platform = "Android"; r.QuickScan = true })
	return a.scan(r, out)
}

func writeDexStrings(dex []byte, outPath string) {
	out, err := os.Create(outPath)
	if err != nil {
		return
	}
	defer out.Close()
	w := bufio.NewWriterSize(out, 1<<20)
	defer w.Flush()

	if len(dex) < 0x70 || !bytes.HasPrefix(dex, []byte("dex\n")) {

		rawStrings(dex, w)
		return
	}
	stringIDsSize := int(binary.LittleEndian.Uint32(dex[0x38:]))
	stringIDsOff := int(binary.LittleEndian.Uint32(dex[0x3c:]))
	if stringIDsOff <= 0 || stringIDsSize <= 0 || stringIDsSize > 20_000_000 ||
		stringIDsOff+stringIDsSize*4 > len(dex) {
		rawStrings(dex, w)
		return
	}
	for i := 0; i < stringIDsSize; i++ {
		dataOff := int(binary.LittleEndian.Uint32(dex[stringIDsOff+i*4:]))
		if dataOff <= 0 || dataOff >= len(dex) {
			continue
		}

		_, n := readUleb128(dex[dataOff:])
		if n == 0 {
			continue
		}
		start := dataOff + n
		end := bytes.IndexByte(dex[start:], 0)
		if end < 0 {
			continue
		}
		s := dex[start : start+end]

		if len(s) >= 6 && len(s) < 2000 && !isDescriptor(s) {
			w.Write(s)
			w.WriteByte('\n')
		}
	}
}

func isDescriptor(s []byte) bool {
	if len(s) == 0 {
		return false
	}
	switch s[0] {
	case 'L', '(', '[':
		return bytes.IndexByte(s, ' ') < 0
	}
	return false
}

func readUleb128(b []byte) (val, size int) {
	result := 0
	shift := 0
	for i := 0; i < len(b) && i < 5; i++ {
		result |= int(b[i]&0x7f) << shift
		if b[i]&0x80 == 0 {
			return result, i + 1
		}
		shift += 7
	}
	return 0, 0
}

func rawStrings(data []byte, w *bufio.Writer) {
	start := -1
	for i, b := range data {
		if b >= 0x20 && b < 0x7f {
			if start < 0 {
				start = i
			}
		} else {
			if start >= 0 && i-start >= 6 {
				w.Write(data[start:i])
				w.WriteByte('\n')
			}
			start = -1
		}
	}
}

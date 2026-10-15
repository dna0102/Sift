package main

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

// Very large apps (TikTok has 56 dex files / 350 MB of code) can't be fully decompiled by
// jadx without many GB of heap. For those, Sift reads the string pool out of each .dex
// directly and scans it. No Java source (so no code viewer), but all the findings:
// endpoints, secrets, pinning, auth, trackers. This never needs much memory.

// quickScanAPK extracts the manifest to readable XML (jadx-free) and scans dex strings and
// text resources. out is where it writes the files the scanner reads. Returns the findings.
func (a *Analyser) quickScanAPK(r *Report, inPath, out string) error {
	os.MkdirAll(out, 0o755)
	r.set(func() { r.State = "scanning"; r.Progress = "Large app — scanning code and resources directly…" })
	a.app.mobile.Changed(r.ID)

	zr, err := zip.OpenReader(inPath)
	if err != nil {
		return err
	}
	defer zr.Close()

	// 1) Manifest: the binary AXML is parsed for identity (package, version, components…).
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

	// 2) Dump dex strings and text resources into files the normal scanner then reads.
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
			a.app.mobile.Changed(r.ID)
		case strings.HasSuffix(name, ".json"), strings.HasSuffix(name, ".js"), strings.HasSuffix(name, ".html"),
			strings.HasSuffix(name, ".xml") && !strings.HasPrefix(name, "res/"):
			// small text assets often hold endpoints/keys too
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

// writeDexStrings pulls the UTF-8 string pool out of a .dex and writes one string per line.
// A dex has a string_ids table pointing at MUTF-8 strings; we read those directly, which is
// far more precise than a generic "strings" sweep.
func writeDexStrings(dex []byte, outPath string) {
	out, err := os.Create(outPath)
	if err != nil {
		return
	}
	defer out.Close()
	w := bufio.NewWriterSize(out, 1<<20)
	defer w.Flush()

	// dex header: magic(8) checksum(4) signature(20) file_size(4) header_size(4) endian(4)
	// link_size(4) link_off(4) map_off(4) string_ids_size(4) string_ids_off(4) ...
	if len(dex) < 0x70 || !bytes.HasPrefix(dex, []byte("dex\n")) {
		// not a parseable dex (maybe compressed differently); fall back to a raw sweep
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
		// string_data_item: uleb128 utf16_size, then MUTF-8 bytes until NUL
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
		// keep only interesting strings: those with a URL, a dot, a slash, or that look like
		// identifiers/keys — skips the flood of type descriptors like "Ljava/lang/Object;"
		if len(s) >= 6 && len(s) < 2000 && !isDescriptor(s) {
			w.Write(s)
			w.WriteByte('\n')
		}
	}
}

// isDescriptor spots JVM type/method descriptors so we don't flood the scanner with them.
func isDescriptor(s []byte) bool {
	if len(s) == 0 {
		return false
	}
	switch s[0] {
	case 'L', '(', '[':
		return bytes.IndexByte(s, ' ') < 0 // descriptors have no spaces
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

// rawStrings is the fallback: runs of printable ASCII, used when a dex can't be parsed.
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

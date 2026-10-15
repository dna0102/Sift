package main

import (
	"archive/zip"
	"bytes"
	"testing"
)

// buildMiniDex makes a minimal .dex whose string_ids table points at one MUTF-8 string, to
// test the dex string-pool reader. Layout: [112-byte header][string_ids: 1 u32][string_data].
func buildMiniDex(s string) []byte {
	const headerSize = 0x70
	stringDataOff := headerSize + 4 // header + one u32 string_id
	buf := make([]byte, stringDataOff)
	copy(buf, "dex\n035\x00")
	// string_ids_size @0x38, string_ids_off @0x3c
	putU32(buf[0x38:], 1)
	putU32(buf[0x3c:], uint32(headerSize))
	putU32(buf[headerSize:], uint32(stringDataOff))
	// string_data_item: uleb128 char count, then MUTF-8 bytes, then NUL
	buf = append(buf, byte(len(s))) // utf16 size (fits in one uleb byte for short strings)
	buf = append(buf, []byte(s)...)
	buf = append(buf, 0)
	return buf
}

func putU32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}

func makeZip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		w, _ := zw.Create(name)
		w.Write(data)
	}
	zw.Close()
	return buf.Bytes()
}

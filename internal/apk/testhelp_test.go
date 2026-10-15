package apk

import (
	"archive/zip"
	"bytes"
	"testing"
)

func buildMiniDex(s string) []byte {
	const headerSize = 0x70
	stringDataOff := headerSize + 4
	buf := make([]byte, stringDataOff)
	copy(buf, "dex\n035\x00")

	putU32(buf[0x38:], 1)
	putU32(buf[0x3c:], uint32(headerSize))
	putU32(buf[headerSize:], uint32(stringDataOff))

	buf = append(buf, byte(len(s)))
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

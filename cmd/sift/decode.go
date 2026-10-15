package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

const maxDecoded = 64 << 20

// decodeBody undoes Content-Encoding (gzip, deflate, br, zstd) for display.
// Truncated bodies decode as far as possible.
func decodeBody(data []byte, encoding string) ([]byte, bool) {
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	if len(data) == 0 || encoding == "" || encoding == "identity" {
		return data, true
	}
	encs := strings.Split(encoding, ",")
	out := data
	for i := len(encs) - 1; i >= 0; i-- {
		var r io.Reader
		var err error
		switch strings.TrimSpace(encs[i]) {
		case "gzip", "x-gzip":
			r, err = gzip.NewReader(bytes.NewReader(out))
		case "deflate":
			if r, err = zlib.NewReader(bytes.NewReader(out)); err != nil {
				r, err = flate.NewReader(bytes.NewReader(out)), nil
			}
		case "br":
			r = brotli.NewReader(bytes.NewReader(out))
		case "zstd":
			var d *zstd.Decoder
			if d, err = zstd.NewReader(bytes.NewReader(out), zstd.WithDecoderMaxMemory(maxDecoded)); err == nil {
				defer d.Close()
				r = d
			}
		case "identity", "":
			continue
		default:
			return data, false
		}
		if err != nil {
			return data, false
		}
		dec, err := io.ReadAll(io.LimitReader(r, maxDecoded))
		if err != nil && len(dec) == 0 {
			return data, false
		}
		out = dec
	}
	return out, true
}

// isBinary looks at the first 4 KB: NUL bytes or lots of control characters mean binary.
func isBinary(b []byte) bool {
	sampled := len(b) > 4096
	if sampled {
		b = b[:4096]
	}
	if bytes.IndexByte(b, 0) >= 0 {
		return true
	}
	if utf8.Valid(b) {
		return false
	}
	if sampled { // a multi-byte character may be cut at the sample boundary
		for i := 1; i <= 3; i++ {
			if utf8.Valid(b[:len(b)-i]) {
				return false
			}
		}
	}
	ctrl := 0
	for _, c := range b {
		if c < 9 || (c > 13 && c < 32) {
			ctrl++
		}
	}
	return ctrl > len(b)/10
}

// classify returns a short content type for the list. Caller holds f.mu.
func classify(f *Flow) string {
	switch f.Kind {
	case "ws":
		return "ws"
	case "tunnel":
		return "tunnel"
	case "tls":
		return "tls"
	}
	ct := ""
	if f.ResHeader != nil {
		ct = strings.ToLower(f.ResHeader.Get("Content-Type"))
	}
	reqCT := ""
	if f.ReqHeader != nil {
		reqCT = strings.ToLower(f.ReqHeader.Get("Content-Type"))
	}
	p := strings.ToLower(f.Path)
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	switch {
	case strings.Contains(p, "graphql") || strings.Contains(reqCT, "graphql"):
		return "graphql"
	case strings.Contains(ct, "json"):
		return "json"
	case strings.Contains(ct, "html"):
		return "html"
	case strings.Contains(ct, "xml") && !strings.Contains(ct, "svg"):
		return "xml"
	case strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript"):
		return "js"
	case strings.Contains(ct, "css"):
		return "css"
	case strings.HasPrefix(ct, "image/"):
		return "image"
	case strings.HasPrefix(ct, "font/") || strings.Contains(ct, "font"):
		return "font"
	case strings.HasPrefix(ct, "video/") || strings.HasPrefix(ct, "audio/") || strings.Contains(ct, "mpegurl"):
		return "media"
	case strings.Contains(ct, "event-stream"):
		return "sse"
	case strings.HasPrefix(ct, "text/"):
		return "text"
	}
	switch path.Ext(p) {
	case ".js", ".mjs", ".cjs":
		return "js"
	case ".css":
		return "css"
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".svg", ".ico", ".bmp":
		return "image"
	case ".woff", ".woff2", ".ttf", ".otf", ".eot":
		return "font"
	case ".mp4", ".webm", ".mp3", ".m4a", ".m3u8", ".ts", ".ogg", ".wav":
		return "media"
	case ".html", ".htm":
		return "html"
	case ".json":
		return "json"
	}
	if f.Status == 0 {
		return ""
	}
	return "other"
}

// ---------------------------------------------------------------- host helpers

func defaultPort(scheme string) int {
	if scheme == "https" || scheme == "wss" {
		return 443
	}
	return 80
}

func hostPort(host string, port int, scheme string) string {
	h := host
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	if port != 0 && port != defaultPort(scheme) {
		return h + ":" + strconv.Itoa(port)
	}
	return h
}

func splitHostPort(s string, def int) (string, int) {
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return strings.ToLower(strings.Trim(s, "[]")), def
	}
	n, err := strconv.Atoi(p)
	if err != nil || n == 0 {
		n = def
	}
	return strings.ToLower(h), n
}

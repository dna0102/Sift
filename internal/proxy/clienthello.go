package proxy

import "encoding/binary"

type clientHello struct {
	SNI  string
	ALPN []string
}

func parseClientHello(rec []byte) (h clientHello, ok bool) {
	if len(rec) < 5+4 || rec[0] != 0x16 || rec[5] != 0x01 {
		return h, false
	}
	b := rec[5+4:]
	if len(b) < 2+32+1 {
		return h, false
	}
	b = b[2+32:]
	skip := func(n int) bool {
		if len(b) < n {
			return false
		}
		b = b[n:]
		return true
	}
	if !skip(1 + int(b[0])) {
		return h, false
	}
	if len(b) < 2 || !skip(2+int(binary.BigEndian.Uint16(b))) {
		return h, false
	}
	if len(b) < 1 || !skip(1+int(b[0])) {
		return h, false
	}
	if len(b) < 2 {
		return h, true
	}
	ext := b[2:min(len(b), 2+int(binary.BigEndian.Uint16(b)))]
	for len(ext) >= 4 {
		typ, n := binary.BigEndian.Uint16(ext), int(binary.BigEndian.Uint16(ext[2:]))
		if len(ext) < 4+n {
			break
		}
		data := ext[4 : 4+n]
		ext = ext[4+n:]
		switch typ {
		case 0:
			if len(data) >= 5 && data[2] == 0 {
				l := int(binary.BigEndian.Uint16(data[3:]))
				if len(data) >= 5+l {
					h.SNI = string(data[5 : 5+l])
				}
			}
		case 16:
			if len(data) >= 2 {
				list := data[2:]
				for len(list) > 0 {
					l := int(list[0])
					if len(list) < 1+l {
						break
					}
					h.ALPN = append(h.ALPN, string(list[1:1+l]))
					list = list[1+l:]
				}
			}
		}
	}
	return h, true
}

func (h clientHello) speaksHTTP() bool {
	if len(h.ALPN) == 0 {
		return true
	}
	for _, p := range h.ALPN {
		if p == "h2" || p == "http/1.1" || p == "http/1.0" {
			return true
		}
	}
	return false
}

func looksLikeHTTP(b []byte) bool {
	if len(b) >= 3 && string(b[:3]) == "PRI" {
		return true
	}
	i := 0
	for i < len(b) && i < 12 && b[i] >= 'A' && b[i] <= 'Z' {
		i++
	}
	return i >= 3 && i < len(b) && b[i] == ' '
}

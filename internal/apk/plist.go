package apk

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
)

func parsePlist(data []byte) (any, error) {
	if bytes.HasPrefix(data, []byte("bplist00")) {
		return parseBinaryPlist(data)
	}
	return parseXMLPlist(data)
}

func parseXMLPlist(data []byte) (any, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "plist" {
			return xmlValue(dec)
		}
	}
}

func xmlValue(dec *xml.Decoder) (any, error) {
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "dict":
			return xmlDict(dec)
		case "array":
			return xmlArray(dec)
		case "string":
			return xmlText(dec, se.Name.Local)
		case "true":
			dec.Skip()
			return true, nil
		case "false":
			dec.Skip()
			return false, nil
		case "integer":
			s, _ := xmlText(dec, se.Name.Local)
			n, _ := strconv.ParseInt(strings.TrimSpace(s.(string)), 10, 64)
			return n, nil
		case "real":
			s, _ := xmlText(dec, se.Name.Local)
			f, _ := strconv.ParseFloat(strings.TrimSpace(s.(string)), 64)
			return f, nil
		case "date", "data":
			return xmlText(dec, se.Name.Local)
		}
	}
}

func xmlText(dec *xml.Decoder, name string) (any, error) {
	var sb strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return sb.String(), err
		}
		switch t := tok.(type) {
		case xml.CharData:
			sb.Write(t)
		case xml.EndElement:
			if t.Name.Local == name {
				return sb.String(), nil
			}
		}
	}
}

func xmlDict(dec *xml.Decoder) (map[string]any, error) {
	m := map[string]any{}
	var key string
	for {
		tok, err := dec.Token()
		if err != nil {
			return m, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "key" {
				k, _ := xmlText(dec, "key")
				key, _ = k.(string)
			} else {
				v, err := xmlValueFrom(dec, t)
				if err != nil {
					return m, err
				}
				m[key] = v
			}
		case xml.EndElement:
			if t.Name.Local == "dict" {
				return m, nil
			}
		}
	}
}

func xmlArray(dec *xml.Decoder) ([]any, error) {
	var arr []any
	for {
		tok, err := dec.Token()
		if err != nil {
			return arr, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			v, err := xmlValueFrom(dec, t)
			if err != nil {
				return arr, err
			}
			arr = append(arr, v)
		case xml.EndElement:
			if t.Name.Local == "array" {
				return arr, nil
			}
		}
	}
}

func xmlValueFrom(dec *xml.Decoder, se xml.StartElement) (any, error) {
	switch se.Name.Local {
	case "dict":
		return xmlDict(dec)
	case "array":
		return xmlArray(dec)
	case "true":
		dec.Skip()
		return true, nil
	case "false":
		dec.Skip()
		return false, nil
	case "integer":
		s, _ := xmlText(dec, se.Name.Local)
		n, _ := strconv.ParseInt(strings.TrimSpace(fmt.Sprint(s)), 10, 64)
		return n, nil
	case "real":
		s, _ := xmlText(dec, se.Name.Local)
		f, _ := strconv.ParseFloat(strings.TrimSpace(fmt.Sprint(s)), 64)
		return f, nil
	default:
		return xmlText(dec, se.Name.Local)
	}
}

func parseBinaryPlist(data []byte) (any, error) {
	if len(data) < 40 {
		return nil, fmt.Errorf("binary plist too short")
	}
	trailer := data[len(data)-32:]
	offsetSize := int(trailer[6])
	refSize := int(trailer[7])
	numObjects := int(binary.BigEndian.Uint64(trailer[8:16]))
	topObject := int(binary.BigEndian.Uint64(trailer[16:24]))
	offsetTableStart := int(binary.BigEndian.Uint64(trailer[24:32]))

	if numObjects <= 0 || numObjects > 10_000_000 || offsetTableStart+numObjects*offsetSize > len(data) {
		return nil, fmt.Errorf("binary plist: bad trailer")
	}
	offsets := make([]int, numObjects)
	for i := range offsets {
		off := offsetTableStart + i*offsetSize
		offsets[i] = int(readSizedInt(data[off:off+offsetSize], offsetSize))
	}
	bp := &bplist{data: data, offsets: offsets, refSize: refSize}
	return bp.object(topObject, 0)
}

type bplist struct {
	data    []byte
	offsets []int
	refSize int
}

func readSizedInt(b []byte, size int) uint64 {
	var v uint64
	for i := 0; i < size && i < len(b); i++ {
		v = v<<8 | uint64(b[i])
	}
	return v
}

func (p *bplist) object(index, depth int) (any, error) {
	if depth > 100 || index < 0 || index >= len(p.offsets) {
		return nil, fmt.Errorf("binary plist: bad reference")
	}
	off := p.offsets[index]
	if off >= len(p.data) {
		return nil, fmt.Errorf("binary plist: offset out of range")
	}
	marker := p.data[off]
	hi, lo := marker>>4, int(marker&0x0f)
	body := p.data[off+1:]
	switch hi {
	case 0x0:
		switch lo {
		case 0x0:
			return nil, nil
		case 0x8:
			return false, nil
		case 0x9:
			return true, nil
		}
		return nil, nil
	case 0x1:
		n := 1 << lo
		return int64(readSizedInt(body, n)), nil
	case 0x2:
		n := 1 << lo
		bits := readSizedInt(body, n)
		if n == 8 {
			return math.Float64frombits(bits), nil
		}
		return math.Float64frombits(uint64(math.Float32frombits(uint32(bits)))), nil
	case 0x3:
		return "date", nil
	case 0x4:
		cnt, rest := p.count(lo, body)
		return string(rest[:min(cnt, len(rest))]), nil
	case 0x5:
		cnt, rest := p.count(lo, body)
		return string(rest[:min(cnt, len(rest))]), nil
	case 0x6:
		cnt, rest := p.count(lo, body)
		return utf16BEString(rest, cnt), nil
	case 0xa, 0xc:
		cnt, rest := p.count(lo, body)
		arr := make([]any, 0, cnt)
		for i := 0; i < cnt; i++ {
			ref := int(readSizedInt(rest[i*p.refSize:], p.refSize))
			v, err := p.object(ref, depth+1)
			if err != nil {
				return arr, nil
			}
			arr = append(arr, v)
		}
		return arr, nil
	case 0xd:
		cnt, rest := p.count(lo, body)
		m := map[string]any{}
		for i := 0; i < cnt; i++ {
			kref := int(readSizedInt(rest[i*p.refSize:], p.refSize))
			vref := int(readSizedInt(rest[(cnt+i)*p.refSize:], p.refSize))
			k, _ := p.object(kref, depth+1)
			v, _ := p.object(vref, depth+1)
			if ks, ok := k.(string); ok {
				m[ks] = v
			}
		}
		return m, nil
	}
	return nil, nil
}

func (p *bplist) count(lo int, body []byte) (int, []byte) {
	if lo != 0x0f {
		return lo, body
	}
	intMarker := body[0]
	n := 1 << int(intMarker&0x0f)
	cnt := int(readSizedInt(body[1:], n))
	return cnt, body[1+n:]
}

func utf16BEString(b []byte, n int) string {
	u := make([]uint16, 0, n)
	for i := 0; i < n*2 && i+1 < len(b); i += 2 {
		u = append(u, binary.BigEndian.Uint16(b[i:]))
	}
	return string(utf16.Decode(u))
}

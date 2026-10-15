package apk

import (
	"encoding/binary"
	"strconv"
	"unicode/utf16"
)

const (
	axmlStringPool  = 0x0001
	axmlStartTag    = 0x0102
	axmlEndTag      = 0x0103
	axmlResourceMap = 0x0180
)

type axml struct {
	data    []byte
	strings []string
}

func (a *Analyser) readBinaryManifest(r *Report, data []byte) {
	m := parseAXML(data)
	if m == nil {
		return
	}
	m.apply(r)
}

type axmlAttr struct {
	ns, name, value string
	typ             uint32
	raw             uint32
}

type axmlTag struct {
	name  string
	attrs []axmlAttr
}

type axmlDoc struct {
	tags []axmlTag
}

func parseAXML(data []byte) *axmlDoc {
	if len(data) < 8 || binary.LittleEndian.Uint16(data) != 0x0003 {
		return nil
	}
	var pool []string
	doc := &axmlDoc{}
	off := 8
	for off+8 <= len(data) {
		typ := binary.LittleEndian.Uint16(data[off:])
		size := int(binary.LittleEndian.Uint32(data[off+4:]))
		if size < 8 || off+size > len(data) {
			break
		}
		chunk := data[off : off+size]
		switch typ {
		case axmlStringPool:
			pool = parseStringPool(chunk)
		case axmlStartTag:
			if t, ok := parseStartTag(chunk, pool); ok {
				doc.tags = append(doc.tags, t)
			}
		case axmlEndTag, axmlResourceMap:

		}
		off += size
	}
	if len(doc.tags) == 0 {
		return nil
	}
	return doc
}

func parseStringPool(chunk []byte) []string {
	if len(chunk) < 28 {
		return nil
	}
	count := int(binary.LittleEndian.Uint32(chunk[8:]))
	flags := binary.LittleEndian.Uint32(chunk[16:])
	stringsStart := int(binary.LittleEndian.Uint32(chunk[20:]))
	utf8 := flags&(1<<8) != 0
	if count <= 0 || count > 5_000_000 || 28+count*4 > len(chunk) {
		return nil
	}
	out := make([]string, count)
	for i := 0; i < count; i++ {
		strOff := int(binary.LittleEndian.Uint32(chunk[28+i*4:]))
		base := stringsStart + strOff
		if base < 0 || base >= len(chunk) {
			continue
		}
		out[i] = decodeAXMLString(chunk[base:], utf8)
	}
	return out
}

func decodeAXMLString(b []byte, utf8 bool) string {
	if utf8 {

		p := 0
		_, n := axmlLen8(b[p:])
		p += n
		blen, n2 := axmlLen8(b[p:])
		p += n2
		if p+blen > len(b) || blen < 0 {
			return ""
		}
		return string(b[p : p+blen])
	}

	if len(b) < 2 {
		return ""
	}
	clen := int(binary.LittleEndian.Uint16(b))
	p := 2
	if clen&0x8000 != 0 {
		clen = ((clen & 0x7fff) << 16) | int(binary.LittleEndian.Uint16(b[2:]))
		p = 4
	}
	if p+clen*2 > len(b) || clen < 0 {
		return ""
	}
	u := make([]uint16, clen)
	for i := 0; i < clen; i++ {
		u[i] = binary.LittleEndian.Uint16(b[p+i*2:])
	}
	return utf16Decode(u)
}

func axmlLen8(b []byte) (int, int) {
	if len(b) == 0 {
		return 0, 0
	}
	if b[0]&0x80 != 0 {
		if len(b) < 2 {
			return 0, 1
		}
		return (int(b[0]&0x7f) << 8) | int(b[1]), 2
	}
	return int(b[0]), 1
}

func parseStartTag(chunk []byte, pool []string) (axmlTag, bool) {

	if len(chunk) < 36 {
		return axmlTag{}, false
	}
	nameIdx := int(int32(binary.LittleEndian.Uint32(chunk[20:])))
	attrCount := int(binary.LittleEndian.Uint16(chunk[28:]))
	t := axmlTag{name: str(pool, nameIdx)}
	base := 36
	const attrLen = 20
	for i := 0; i < attrCount && base+(i+1)*attrLen <= len(chunk); i++ {
		a := chunk[base+i*attrLen:]
		nsIdx := int(int32(binary.LittleEndian.Uint32(a[0:])))
		nmIdx := int(int32(binary.LittleEndian.Uint32(a[4:])))
		rawIdx := int(int32(binary.LittleEndian.Uint32(a[8:])))
		typ := binary.LittleEndian.Uint32(a[12:]) >> 24
		data := binary.LittleEndian.Uint32(a[16:])
		attr := axmlAttr{ns: str(pool, nsIdx), name: str(pool, nmIdx), typ: typ, raw: data}
		switch typ {
		case 0x03:
			attr.value = str(pool, int(data))
			if attr.value == "" && rawIdx >= 0 {
				attr.value = str(pool, rawIdx)
			}
		case 0x10:
			attr.value = strconv.Itoa(int(int32(data)))
		case 0x12:
			if data != 0 {
				attr.value = "true"
			} else {
				attr.value = "false"
			}
		default:
			if rawIdx >= 0 {
				attr.value = str(pool, rawIdx)
			}
		}
		t.attrs = append(t.attrs, attr)
	}
	return t, t.name != ""
}

func str(pool []string, i int) string {
	if i < 0 || i >= len(pool) {
		return ""
	}
	return pool[i]
}

func (t axmlTag) attr(name string) string {
	for _, a := range t.attrs {
		if a.name == name {
			return a.value
		}
	}
	return ""
}

func (d *axmlDoc) apply(r *Report) {
	r.set(func() {
		var lastComponent string
		for i := range d.tags {
			t := d.tags[i]
			switch t.name {
			case "manifest":
				r.Package = t.attr("package")
				if v := t.attr("versionName"); v != "" {
					r.Version = v
				}
				if v := t.attr("versionCode"); v != "" {
					r.Build = v
				}
			case "uses-sdk":
				r.MinSDK = FirstNonEmpty(t.attr("minSdkVersion"), r.MinSDK)
				r.TargetSDK = FirstNonEmpty(t.attr("targetSdkVersion"), r.TargetSDK)
			case "uses-permission", "uses-permission-sdk-23":
				if p := t.attr("name"); p != "" {
					r.Permissions = AppendUnique(r.Permissions, shortPerm(p))
				}
			case "application":
				if t.attr("usesCleartextTraffic") == "true" {
					r.Cleartext = true
					r.CleartextNote = "android:usesCleartextTraffic=\"true\" — the app allows plain HTTP"
				}
			case "activity", "service", "receiver", "provider":
				name := t.attr("name")
				lastComponent = name
				exported := t.attr("exported") == "true"
				r.Components = append(r.Components, Component{Type: t.name, Name: name, Exported: exported})
			case "data":
				scheme := t.attr("scheme")
				if scheme != "" && scheme != "http" && scheme != "https" {
					link := scheme + "://" + t.attr("host")
					r.DeepLinks = AppendUnique(r.DeepLinks, link)
				}
				_ = lastComponent
			}
		}
	})
}

func utf16Decode(u []uint16) string { return string(utf16.Decode(u)) }

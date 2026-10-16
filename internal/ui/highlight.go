package ui

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func highlightSource(path string, data []byte, firstLine int) string {
	ext := strings.ToLower(filepath.Ext(path))
	text := string(data)
	var body string
	switch ext {
	case ".json":
		body = string(highlightJSON(data))
	case ".xml", ".html", ".plist":
		body = string(highlightMarkup(text))
	case ".java", ".kt", ".swift", ".smali", ".c", ".h", ".m", ".js", ".ts", ".gradle":
		body = highlightCode(text)
	default:
		body = esc(text)
	}

	lines := strings.Split(body, "\n")
	var b strings.Builder
	b.Grow(len(body) + len(lines)*40)
	b.WriteString(`<table class="src">`)
	for i, ln := range lines {
		n := strconv.Itoa(i + firstLine)
		b.WriteString(`<tr id="L`)
		b.WriteString(n)
		b.WriteString(`"><td class="ln">`)
		b.WriteString(n)
		b.WriteString(`</td><td class="lc">`)
		if ln == "" {
			b.WriteString(" ")
		} else {
			b.WriteString(ln)
		}
		b.WriteString("</td></tr>")
	}
	b.WriteString("</table>")
	return b.String()
}

var codeKeyword = regexp.MustCompile(`^(?:public|private|protected|static|final|abstract|class|interface|enum|extends|implements|import|package|void|int|long|float|double|boolean|char|byte|short|return|if|else|for|while|do|switch|case|break|continue|new|this|super|try|catch|finally|throw|throws|synchronized|volatile|transient|native|fun|val|var|object|companion|override|suspend|when|is|in|out|func|let|guard|struct|protocol|extension|self|nil|null|true|false|const)$`)

func highlightCode(src string) string {
	var b strings.Builder
	b.Grow(len(src) * 2)
	i, n := 0, len(src)
	emit := func(cls, text string) {
		if cls == "" {
			b.WriteString(esc(text))
		} else {
			b.WriteString(`<span class="` + cls + `">`)
			b.WriteString(esc(text))
			b.WriteString(`</span>`)
		}
	}
	for i < n {
		c := src[i]
		switch {
		case c == '/' && i+1 < n && src[i+1] == '/':
			j := strings.IndexByte(src[i:], '\n')
			if j < 0 {
				emit("c", src[i:])
				i = n
			} else {
				emit("c", src[i:i+j])
				i += j
			}
		case c == '#' && (i == 0 || src[i-1] == '\n'):
			j := strings.IndexByte(src[i:], '\n')
			if j < 0 {
				emit("c", src[i:])
				i = n
			} else {
				emit("c", src[i:i+j])
				i += j
			}
		case c == '/' && i+1 < n && src[i+1] == '*':
			j := strings.Index(src[i+2:], "*/")
			if j < 0 {
				emit("c", src[i:])
				i = n
			} else {
				emit("c", src[i:i+2+j+2])
				i += 2 + j + 2
			}
		case c == '"' || c == '\'':
			j := i + 1
			for j < n && src[j] != c {
				if src[j] == '\\' {
					j++
				}
				j++
			}
			j = min(j+1, n)
			emit("s", src[i:j])
			i = j
		case isIdentStart(c):
			j := i + 1
			for j < n && isIdentPart(src[j]) {
				j++
			}
			word := src[i:j]
			if codeKeyword.MatchString(word) {
				emit("k", word)
			} else {
				emit("", word)
			}
			i = j
		case c >= '0' && c <= '9':
			j := i + 1
			for j < n && (isIdentPart(src[j]) || src[j] == '.') {
				j++
			}
			emit("n", src[i:j])
			i = j
		default:
			emit("", src[i:i+1])
			i++
		}
	}
	return b.String()
}

func isIdentStart(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
func isIdentPart(c byte) bool { return isIdentStart(c) || c >= '0' && c <= '9' }

package main

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// highlightSource renders a decompiled file as highlighted HTML with line numbers, so the
// app-analysis viewer can show exactly where a finding is. It reuses the JSON/XML highlighters
// for those types and has a light keyword highlighter for Java/Kotlin/Swift/Smali.

func highlightSource(path string, data []byte) string {
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
	// wrap each line in a numbered row
	lines := strings.Split(body, "\n")
	var b strings.Builder
	b.Grow(len(body) + len(lines)*40)
	b.WriteString(`<table class="src">`)
	for i, ln := range lines {
		b.WriteString(`<tr id="L`)
		b.WriteString(strconv.Itoa(i+1))
		b.WriteString(`"><td class="ln">`)
		b.WriteString(strconv.Itoa(i+1))
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

// highlightCode tokenises the raw source in a single left-to-right pass, so strings and
// comments are matched before their contents are mistaken for keywords, and every emitted
// piece is HTML-escaped exactly once.
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
		case c == '/' && i+1 < n && src[i+1] == '/': // line comment
			j := strings.IndexByte(src[i:], '\n')
			if j < 0 {
				emit("c", src[i:])
				i = n
			} else {
				emit("c", src[i:i+j])
				i += j
			}
		case c == '#' && (i == 0 || src[i-1] == '\n'): // smali / shell comment
			j := strings.IndexByte(src[i:], '\n')
			if j < 0 {
				emit("c", src[i:])
				i = n
			} else {
				emit("c", src[i:i+j])
				i += j
			}
		case c == '/' && i+1 < n && src[i+1] == '*': // block comment
			j := strings.Index(src[i+2:], "*/")
			if j < 0 {
				emit("c", src[i:])
				i = n
			} else {
				emit("c", src[i:i+2+j+2])
				i += 2 + j + 2
			}
		case c == '"' || c == '\'': // string / char literal
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
		case isIdentStart(c): // identifier or keyword
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
		case c >= '0' && c <= '9': // number
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

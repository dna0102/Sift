package ui

import "testing"

func TestHighlightCode(t *testing.T) {
	html := highlightCode(`String u = "https://x.com"; // note`)

	for _, want := range []string{`<span class="s">`, `<span class="c">`} {
		if !containsStr(html, want) {
			t.Errorf("missing %s in %s", want, html)
		}
	}

	if containsStr(html, "&amp;#") {
		t.Errorf("double-escaped output: %s", html)
	}
}

func containsStr(h, sub string) bool {
	for i := 0; i+len(sub) <= len(h); i++ {
		if h[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

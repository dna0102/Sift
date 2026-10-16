package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveUnderStaysInRoot(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "strings"), 0o755)
	os.WriteFile(filepath.Join(root, "strings", "classes.dex.txt"), []byte("a\n"), 0o644)
	if resolveUnder(root, "strings/classes.dex.txt") == "" {
		t.Error("existing file not resolved")
	}
	if resolveUnder(root, "../secret.txt") != "" {
		t.Error("path escaped the root")
	}
	if resolveUnder(root, "strings") != "" {
		t.Error("directory resolved as a file")
	}
}

func TestReadWindowKeepsLineNumbers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.txt")
	var b strings.Builder
	for i := 1; b.Len() < 2<<20; i++ {
		fmt.Fprintf(&b, "line %d padding padding padding padding padding\n", i)
	}
	os.WriteFile(path, []byte(b.String()), 0o644)

	data, first, err := readWindow(path, 40000, 600)
	if err != nil {
		t.Fatal(err)
	}
	if first != 39700 {
		t.Errorf("first = %d, want 39700", first)
	}
	lines := strings.Split(string(data), "\n")
	if lines[0] != "line 39700 padding padding padding padding padding" || len(lines) != 601 {
		t.Errorf("window starts %q with %d lines", lines[0], len(lines))
	}
	html := highlightSource("big.txt", data, first)
	if !strings.Contains(html, `id="L40000"`) {
		t.Error("target line missing from rendered window")
	}
}

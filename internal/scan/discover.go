package scan

import (
	"net/http"
	"strings"

	"sift/internal/core"
)

var discoveryWords = []string{
	"admin", "administrator", "login", "logout", "register", "signup", "dashboard", "console",
	"api", "api/v1", "api/v2", "graphql", "swagger", "swagger.json", "openapi.json", "api-docs",
	"config", "config.json", "config.php", ".env", ".git/config", ".git/HEAD", ".svn/entries",
	"backup", "backup.zip", "backup.sql", "db.sql", "dump.sql", "database.sql",
	"test", "dev", "staging", "debug", "status", "health", "healthz", "metrics", "actuator",
	"actuator/health", "actuator/env", "phpinfo.php", "info.php", "server-status", "server-info",
	"robots.txt", "sitemap.xml", ".well-known/security.txt", "crossdomain.xml",
	"wp-admin", "wp-login.php", "wp-config.php", "wp-json", "xmlrpc.php",
	"user", "users", "account", "accounts", "profile", "settings", "upload", "uploads",
	"files", "file", "download", "downloads", "tmp", "temp", "logs", "log", "old", "bak",
	"private", "internal", "secret", "secrets", "token", "tokens", "key", "keys",
	"readme.md", "CHANGELOG.md", "package.json", "composer.json", "web.config", ".htaccess",
	"s3", "storage", "cdn", "assets", "static", "media", "images",
}

var mineParams = []string{
	"debug", "test", "admin", "id", "user", "user_id", "uid", "account", "page", "file",
	"path", "dir", "url", "redirect", "next", "return", "callback", "lang", "locale",
	"format", "type", "view", "action", "cmd", "exec", "query", "q", "search", "key", "token",
	"api_key", "access", "role", "include", "template", "preview", "source", "show", "mode",
}

func (e *Engine) inScopeRoots(opts Options) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range e.flows.All() {
		t := targetFromFlow(f)
		if t == nil || t.host == "" {
			continue
		}
		if !opts.Scope.InScope(t.url()) {
			continue
		}
		root := t.scheme + "://" + core.HostPort(t.host, t.port, t.scheme)
		if !seen[root] {
			seen[root] = true
			out = append(out, root)
		}
	}
	return out
}

func (e *Engine) discover(run *runner, opts Options) {
	for _, root := range e.inScopeRoots(opts) {
		if run.ctx.Err() != nil {
			return
		}
		e.discoverHost(run, root, opts)
	}
}

func (e *Engine) discoverHost(run *runner, root string, opts Options) {
	base, err := run.send(&Request{Method: "GET", URL: root + "/sift" + marker(), Header: http.Header{}, Tag: "discover"})
	if err != nil || base == nil {
		return
	}
	softLen := len(base.Body)
	for _, word := range discoveryWords {
		if run.ctx.Err() != nil {
			return
		}
		r, err := run.send(&Request{Method: "GET", URL: root + "/" + word, Header: http.Header{}, Tag: "discover"})
		if err != nil || r == nil || r.Status == 0 {
			continue
		}
		if !interestingPath(r, base.Status, softLen) {
			continue
		}
		sev, note := pathSeverity(word, r.Status)
		run.add(&Finding{Type: "discovered-path", Title: "Discovered " + note, Severity: sev, Confidence: ConfFirm,
			CWE: "CWE-200", Method: "GET", URL: root + "/" + word, Host: hostOfRoot(root),
			Detail:      "Content discovery found /" + word + " responding with HTTP " + itoa(r.Status) + ", which is not linked from observed traffic.",
			Remediation: "Remove or protect administrative, backup and debug resources that should not be exposed.",
			Evidence:    []Evidence{{Label: "Response", Flow: r.FlowID, Snippet: "HTTP " + itoa(r.Status) + ", " + itoa(len(r.Body)) + " bytes"}}})
	}
	e.mineHost(run, root, base.Status, softLen)
}

func (e *Engine) mineHost(run *runner, root string, base404 int, softLen int) {
	refURL := root + "/?sift" + marker() + "=1"
	ref, err := run.send(&Request{Method: "GET", URL: refURL, Header: http.Header{}, Tag: "discover"})
	if err != nil || ref == nil {
		return
	}
	for _, name := range mineParams {
		if run.ctx.Err() != nil {
			return
		}
		val := marker()
		r, err := run.send(&Request{Method: "GET", URL: root + "/?" + name + "=" + val, Header: http.Header{}, Tag: "discover"})
		if err != nil || r == nil {
			continue
		}
		if r.Status != ref.Status || reflects(string(r.Body), val) || absDiff(len(r.Body), len(ref.Body)) > 96 {
			run.add(&Finding{Type: "hidden-parameter", Title: "Hidden parameter " + name, Severity: SevLow, Confidence: ConfTentative,
				CWE: "CWE-200", Method: "GET", URL: root + "/?" + name + "=", Host: hostOfRoot(root), Param: name, Where: "query",
				Detail:      "The parameter " + name + " changed the response although it is not used by the observed request, suggesting hidden functionality worth testing.",
				Remediation: "",
				Evidence:    []Evidence{{Label: "Effect", Flow: r.FlowID, Snippet: "status " + itoa(r.Status) + " vs " + itoa(ref.Status) + ", len " + itoa(len(r.Body)) + " vs " + itoa(len(ref.Body))}}})
		}
	}
}

func interestingPath(r *Response, base404 int, softLen int) bool {
	if r.Status == 404 || r.Status == 0 {
		return false
	}
	if r.Status == base404 && absDiff(len(r.Body), softLen) < 64 {
		return false
	}
	switch r.Status {
	case 200, 201, 204, 206, 301, 302, 307, 308, 401, 403, 405, 500:
		return true
	}
	return false
}

func pathSeverity(word string, status int) (Severity, string) {
	sensitive := strings.Contains(word, ".env") || strings.Contains(word, ".git") || strings.Contains(word, "backup") ||
		strings.Contains(word, ".sql") || strings.Contains(word, "wp-config") || strings.Contains(word, "secret") ||
		strings.Contains(word, "dump") || strings.Contains(word, "actuator/env") || strings.Contains(word, "phpinfo")
	if status == 200 && sensitive {
		return SevHigh, "sensitive file /" + word
	}
	if status == 200 {
		return SevLow, "resource /" + word
	}
	if status == 401 || status == 403 {
		return SevInfo, "protected resource /" + word
	}
	return SevInfo, "resource /" + word
}

func hostOfRoot(root string) string {
	s := root
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}

func absDiff(a, b int) int {
	if a > b {
		return a - b
	}
	return b - a
}

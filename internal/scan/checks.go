package scan

type CheckInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
	Kind     string `json:"kind"`
	Default  bool   `json:"default"`
	Detail   string `json:"detail"`
}

var checkRegistry = []CheckInfo{
	{"headers", "Security headers", "passive", "passive", true, "Missing or weak HSTS, CSP, X-Frame-Options, X-Content-Type-Options and related headers."},
	{"cookies", "Cookie attributes", "passive", "passive", true, "Session cookies without Secure, HttpOnly, SameSite or with overly broad scope."},
	{"cors", "CORS misconfiguration", "passive", "passive", true, "Reflected or wildcard Access-Control-Allow-Origin with credentials."},
	{"infoleak", "Information disclosure", "passive", "passive", true, "Server banners, stack traces, internal IPs, source paths, debug data and tokens in responses."},
	{"mixedtls", "Transport weaknesses", "passive", "passive", true, "Cleartext HTTP, mixed content, Set-Cookie over HTTP, sensitive data in URLs."},
	{"secrets", "Exposed secrets", "passive", "passive", true, "API keys, tokens and private keys reflected in responses or scripts."},
	{"jsendpoints", "Endpoints in JavaScript", "passive", "passive", true, "URLs, API paths and parameters mined from served JavaScript."},

	{"reflection", "Reflected input / XSS", "injection", "active", true, "Input reflected into HTML, attributes, JS or URLs leading to cross-site scripting."},
	{"sqli", "SQL injection", "injection", "active", true, "Error-based, boolean-based and time-based SQL injection."},
	{"ssti", "Template injection", "injection", "active", true, "Server-side template injection across common engines."},
	{"cmdi", "OS command injection", "injection", "active", true, "Command execution via shell metacharacters, including time-based blind."},
	{"traversal", "Path traversal / LFI", "injection", "active", true, "Directory traversal and local file inclusion."},
	{"redirect", "Open redirect", "injection", "active", true, "Attacker-controlled redirect destinations."},
	{"ssrf", "Server-side request forgery", "injection", "active", true, "Requests forced to internal or attacker-chosen hosts."},
	{"crlf", "CRLF / header injection", "injection", "active", true, "Response header or response splitting via injected carriage returns."},
	{"xxe", "XML external entity", "injection", "active", true, "External entity and DTD processing in XML bodies."},
	{"nosqli", "NoSQL injection", "injection", "active", true, "Operator and boolean injection into NoSQL queries."},

	{"discovery", "Content discovery", "discovery", "active", true, "Hidden files, directories, backups and admin endpoints."},
	{"params", "Parameter mining", "discovery", "active", true, "Unlinked query and body parameters that change responses."},
}

func AllChecks() []CheckInfo { return checkRegistry }

func AllCheckIDs() []string {
	out := make([]string, 0, len(checkRegistry))
	for _, c := range checkRegistry {
		out = append(out, c.ID)
	}
	return out
}

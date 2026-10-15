package scan

import (
	"fmt"
	"net/http"
	"strings"

	"sift/internal/core"
)

type flowSnap struct {
	id        int64
	method    string
	scheme    string
	host      string
	port      int
	url       string
	rootURL   string
	status    int
	reqHeader http.Header
	resHeader http.Header
	reqBody   []byte
	resBody   []byte
	ctype     string
	kind      string
}

func snapFlow(f *core.Flow) *flowSnap {
	f.Lock()
	defer f.Unlock()
	if f.Kind != "http" || f.Status == 0 {
		return nil
	}
	body := f.ResBody
	if !f.Decoded {
		if d, ok := core.DecodeBody(body, f.ResHeader.Get("Content-Encoding")); ok {
			body = d
		}
	}
	sn := &flowSnap{
		id: f.ID, method: f.Method, scheme: f.Scheme, host: f.Host, port: f.Port,
		url: f.URL(), status: f.Status, reqBody: append([]byte(nil), f.ReqBody...),
		resBody: body, kind: f.Kind,
	}
	if f.ReqHeader != nil {
		sn.reqHeader = f.ReqHeader.Clone()
	} else {
		sn.reqHeader = http.Header{}
	}
	if f.ResHeader != nil {
		sn.resHeader = f.ResHeader.Clone()
		sn.ctype = strings.ToLower(f.ResHeader.Get("Content-Type"))
	} else {
		sn.resHeader = http.Header{}
	}
	sn.rootURL = f.Scheme + "://" + core.HostPort(f.Host, f.Port, f.Scheme) + "/"
	return sn
}

func (sn *flowSnap) isHTML() bool { return strings.Contains(sn.ctype, "html") }
func (sn *flowSnap) https() bool   { return sn.scheme == "https" }

func (e *Engine) Passive(f *core.Flow) {
	sn := snapFlow(f)
	if sn == nil {
		return
	}
	if sn.host == "" || strings.EqualFold(sn.host, "127.0.0.1") {
		return
	}
	add := func(fd *Finding) {
		fd.Passive = true
		fd.Flows = append(fd.Flows, sn.id)
		e.store.Add(fd)
	}
	for _, c := range e.passiveChecks {
		c(sn, add)
	}
}

type passiveCheck func(sn *flowSnap, add func(*Finding))

func passiveCheckMap() map[string]passiveCheck {
	return map[string]passiveCheck{
		"headers":     checkHeaders,
		"cookies":     checkCookies,
		"cors":        checkCORS,
		"infoleak":    checkInfoLeak,
		"mixedtls":    checkTransport,
		"secrets":     checkSecrets,
		"jsendpoints": checkJSEndpoints,
	}
}

func checkHeaders(sn *flowSnap, add func(*Finding)) {
	if !sn.isHTML() {
		return
	}
	h := sn.resHeader
	missing := func(id, title string, sev Severity, cwe, detail, fix string) {
		add(&Finding{Type: id, Title: title, Severity: sev, Confidence: ConfFirm, CWE: cwe,
			Method: sn.method, URL: sn.rootURL, Host: sn.host, Detail: detail, Remediation: fix,
			Evidence: []Evidence{{Label: "Response headers", Flow: sn.id, Snippet: headerBlock(h)}}})
	}
	if sn.https() && h.Get("Strict-Transport-Security") == "" {
		missing("hdr-hsts", "Missing HSTS", SevLow, "CWE-319",
			"The HTTPS response does not set Strict-Transport-Security, so a user's first or downgraded request can be forced over cleartext.",
			"Send Strict-Transport-Security with a long max-age, includeSubDomains and preload where appropriate.")
	}
	if h.Get("Content-Security-Policy") == "" {
		missing("hdr-csp", "Missing Content-Security-Policy", SevLow, "CWE-1021",
			"No Content-Security-Policy is set, removing a key defence-in-depth control against XSS and clickjacking.",
			"Define a restrictive Content-Security-Policy and tighten it over time.")
	}
	if h.Get("X-Content-Type-Options") == "" {
		missing("hdr-nosniff", "Missing X-Content-Type-Options", SevInfo, "CWE-430",
			"X-Content-Type-Options: nosniff is absent, allowing MIME sniffing of responses.",
			"Set X-Content-Type-Options: nosniff on all responses.")
	}
	if h.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(h.Get("Content-Security-Policy")), "frame-ancestors") {
		missing("hdr-xfo", "Clickjacking protection missing", SevLow, "CWE-1021",
			"Neither X-Frame-Options nor a CSP frame-ancestors directive is set, so the page can be framed by any site.",
			"Set X-Frame-Options: DENY or a CSP frame-ancestors directive.")
	}
}

func headerBlock(h http.Header) string {
	var b strings.Builder
	for _, row := range core.HeaderRows(h) {
		fmt.Fprintf(&b, "%s: %s\n", row[0], row[1])
	}
	return clip(b.String(), 1200)
}

func checkCookies(sn *flowSnap, add func(*Finding)) {
	res := http.Response{Header: sn.resHeader}
	for _, c := range res.Cookies() {
		if looksSessionCookie(c.Name) {
			var problems []string
			sev := SevLow
			if sn.https() && !c.Secure {
				problems = append(problems, "no Secure flag")
				sev = SevMedium
			}
			if !c.HttpOnly {
				problems = append(problems, "no HttpOnly flag")
			}
			if c.SameSite == http.SameSiteNoneMode && !c.Secure {
				problems = append(problems, "SameSite=None without Secure")
				sev = SevMedium
			}
			if c.SameSite == http.SameSiteDefaultMode {
				problems = append(problems, "no SameSite attribute")
			}
			if len(problems) == 0 {
				continue
			}
			add(&Finding{Type: "cookie-flags", Title: "Session cookie missing protections", Severity: sev,
				Confidence: ConfFirm, CWE: "CWE-614", Method: sn.method, URL: sn.rootURL, Host: sn.host, Param: c.Name, Where: "cookie",
				Detail: fmt.Sprintf("The cookie %q has: %s.", c.Name, strings.Join(problems, ", ")),
				Remediation: "Set Secure, HttpOnly and an explicit SameSite on session cookies.",
				Evidence:    []Evidence{{Label: "Set-Cookie", Flow: sn.id, Snippet: clip(c.Raw, 300)}}})
		}
	}
}

func looksSessionCookie(name string) bool {
	n := strings.ToLower(name)
	for _, k := range []string{"sess", "sid", "auth", "token", "jwt", "login", "csrf", "xsrf", "remember", "account"} {
		if strings.Contains(n, k) {
			return true
		}
	}
	return false
}

func checkCORS(sn *flowSnap, add func(*Finding)) {
	acao := sn.resHeader.Get("Access-Control-Allow-Origin")
	if acao == "" {
		return
	}
	creds := strings.EqualFold(sn.resHeader.Get("Access-Control-Allow-Credentials"), "true")
	origin := sn.reqHeader.Get("Origin")
	switch {
	case origin != "" && acao == origin && creds:
		add(&Finding{Type: "cors-reflect", Title: "CORS reflects Origin with credentials", Severity: SevHigh,
			Confidence: ConfFirm, CWE: "CWE-942", Method: sn.method, URL: sn.url, Host: sn.host,
			Detail: "The response reflects the request Origin in Access-Control-Allow-Origin and allows credentials, letting any origin read authenticated responses.",
			Remediation: "Validate Origin against an allowlist and never combine credentials with a reflected or wildcard origin.",
			Evidence:    []Evidence{{Label: "Request Origin", Snippet: origin}, {Label: "ACAO", Flow: sn.id, Snippet: acao + " (credentials: true)"}}})
	case acao == "*" && creds:
		add(&Finding{Type: "cors-wildcard", Title: "CORS wildcard with credentials", Severity: SevMedium,
			Confidence: ConfFirm, CWE: "CWE-942", Method: sn.method, URL: sn.url, Host: sn.host,
			Detail: "Access-Control-Allow-Origin: * is combined with credentials.",
			Remediation: "Do not combine a wildcard origin with credentials.",
			Evidence:    []Evidence{{Label: "ACAO", Flow: sn.id, Snippet: "* (credentials: true)"}}})
	case strings.EqualFold(acao, "null"):
		add(&Finding{Type: "cors-null", Title: "CORS allows null origin", Severity: SevLow, Confidence: ConfTentative,
			CWE: "CWE-942", Method: sn.method, URL: sn.url, Host: sn.host,
			Detail:      "Access-Control-Allow-Origin: null can be reached from sandboxed iframes and some local contexts.",
			Remediation: "Do not allow the null origin.",
			Evidence:    []Evidence{{Label: "ACAO", Flow: sn.id, Snippet: "null"}}})
	}
}

func checkInfoLeak(sn *flowSnap, add func(*Finding)) {
	body := string(sn.resBody)
	for _, s := range errorSigs {
		if m := s.re.FindString(body); m != "" {
			add(&Finding{Type: "infoleak-error", Title: s.name + " in response", Severity: SevLow, Confidence: ConfFirm,
				CWE: "CWE-209", Method: sn.method, URL: sn.url, Host: sn.host,
				Detail:      "The response exposes a " + s.name + ", revealing framework, file paths or query internals.",
				Remediation: "Return generic error pages and log details server-side only.",
				Evidence:    []Evidence{{Label: "Matched", Flow: sn.id, Snippet: clip(m, 300)}}})
			break
		}
	}
	if m := internalIP.FindString(body); m != "" {
		add(&Finding{Type: "infoleak-ip", Title: "Internal IP address disclosed", Severity: SevInfo, Confidence: ConfFirm,
			CWE: "CWE-200", Method: sn.method, URL: sn.url, Host: sn.host,
			Detail: "A private-range IP address appears in the response.", Remediation: "Strip internal addresses from responses.",
			Evidence: []Evidence{{Label: "Matched", Flow: sn.id, Snippet: m}}})
	}
	if m := pathLeak.FindString(body); m != "" {
		add(&Finding{Type: "infoleak-path", Title: "Server file path disclosed", Severity: SevInfo, Confidence: ConfTentative,
			CWE: "CWE-200", Method: sn.method, URL: sn.url, Host: sn.host,
			Detail: "A server-side filesystem path appears in the response.", Remediation: "Avoid leaking absolute paths.",
			Evidence: []Evidence{{Label: "Matched", Flow: sn.id, Snippet: clip(m, 200)}}})
	}
	for _, hdr := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"} {
		if v := sn.resHeader.Get(hdr); v != "" && strings.ContainsAny(v, "0123456789") {
			add(&Finding{Type: "infoleak-banner", Title: "Software version disclosed", Severity: SevInfo, Confidence: ConfFirm,
				CWE: "CWE-200", Method: sn.method, URL: sn.rootURL, Host: sn.host, Param: hdr, Where: "header",
				Detail: "The " + hdr + " header reveals a software version that narrows known-vulnerability lookups.",
				Remediation: "Remove or generalise version banners.", Evidence: []Evidence{{Label: hdr, Flow: sn.id, Snippet: v}}})
		}
	}
}

func checkTransport(sn *flowSnap, add func(*Finding)) {
	if !sn.https() {
		if strings.Contains(sn.resHeader.Get("Set-Cookie"), "=") {
			add(&Finding{Type: "tls-cookie-cleartext", Title: "Cookie set over cleartext HTTP", Severity: SevMedium,
				Confidence: ConfFirm, CWE: "CWE-319", Method: sn.method, URL: sn.url, Host: sn.host,
				Detail: "A cookie is set on an unencrypted HTTP response and can be captured on the wire.",
				Remediation: "Serve the site over HTTPS and set Secure on cookies."})
		}
		if looksAuthBody(sn.reqBody) {
			add(&Finding{Type: "tls-cleartext-creds", Title: "Credentials sent over cleartext HTTP", Severity: SevHigh,
				Confidence: ConfFirm, CWE: "CWE-319", Method: sn.method, URL: sn.url, Host: sn.host,
				Detail: "A request carrying credential-like fields was sent over unencrypted HTTP.",
				Remediation: "Require HTTPS for all authentication traffic."})
		}
	}
	if sensitiveParam.MatchString(sn.url) {
		add(&Finding{Type: "sensitive-in-url", Title: "Sensitive value in URL", Severity: SevLow, Confidence: ConfFirm,
			CWE: "CWE-598", Method: sn.method, URL: sn.url, Host: sn.host,
			Detail: "A password, token or key appears in the request URL, where it is logged and cached.",
			Remediation: "Move secrets out of the URL into headers or the request body."})
	}
}

func looksAuthBody(body []byte) bool {
	b := strings.ToLower(string(body))
	return (strings.Contains(b, "password") || strings.Contains(b, "passwd")) && len(b) < 4096
}

func checkSecrets(sn *flowSnap, add func(*Finding)) {
	if sn.kind != "http" {
		return
	}
	body := string(sn.resBody)
	for _, s := range secretSigs {
		if m := s.re.FindString(body); m != "" {
			add(&Finding{Type: "secret-exposed", Title: s.name + " exposed in response", Severity: SevHigh,
				Confidence: ConfFirm, CWE: "CWE-200", Method: sn.method, URL: sn.url, Host: sn.host, Param: s.name,
				Detail: "A " + s.name + " was found in the response body and may grant access if live.",
				Remediation: "Revoke the exposed credential and keep secrets server-side.",
				Evidence:    []Evidence{{Label: s.name, Flow: sn.id, Snippet: maskMiddle(m)}}})
		}
	}
}

func maskMiddle(s string) string {
	if len(s) <= 10 {
		return strings.Repeat("•", len(s))
	}
	return s[:4] + strings.Repeat("•", 8) + s[len(s)-4:]
}

func checkJSEndpoints(sn *flowSnap, add func(*Finding)) {
	if !strings.Contains(sn.ctype, "javascript") && !strings.Contains(sn.ctype, "ecmascript") {
		return
	}
	body := string(sn.resBody)
	seen := map[string]bool{}
	var found []string
	for _, m := range jsEndpoint.FindAllStringSubmatch(body, 40) {
		p := m[1]
		if seen[p] {
			continue
		}
		seen[p] = true
		found = append(found, p)
	}
	if len(found) == 0 {
		return
	}
	add(&Finding{Type: "js-endpoints", Title: "API endpoints found in JavaScript", Severity: SevInfo, Confidence: ConfFirm,
		Method: sn.method, URL: sn.url, Host: sn.host,
		Detail:      fmt.Sprintf("%d API-like paths were mined from this script and are candidates for further testing.", len(found)),
		Remediation: "",
		Evidence:    []Evidence{{Label: "Paths", Flow: sn.id, Snippet: clip(strings.Join(found, "\n"), 1500)}}})
}

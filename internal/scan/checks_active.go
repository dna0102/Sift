package scan

import (
	"crypto/rand"
	"math"
	"math/big"
	"net/url"
	"strings"
)

func randInt(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return n / 2
	}
	return int(v.Int64())
}

func around(body, needle string, pad int) string {
	i := strings.Index(body, needle)
	if i < 0 {
		return ""
	}
	s := i - pad
	if s < 0 {
		s = 0
	}
	e := i + len(needle) + pad
	if e > len(body) {
		e = len(body)
	}
	return clip(body[s:e], 300)
}

func isHTMLResp(r *Response) bool {
	return r != nil && strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "html")
}

func (p *probe) repro(payload string) []string {
	return []string{
		"Send a " + p.target.method + " request to " + p.target.url(),
		"Set the " + p.point.Where + " parameter " + p.point.Name + " to: " + clip(payload, 200),
		"Observe the response confirming the injection described above.",
	}
}

func similar(r *Response, b *baseline) bool {
	if !b.ok || r == nil {
		return false
	}
	if r.Status != b.status {
		return false
	}
	delta := int(math.Abs(float64(len(r.Body) - b.length)))
	return delta <= b.lenVar+48
}

func differ(a, c *Response) bool {
	if a == nil || c == nil {
		return false
	}
	if a.Status != c.Status {
		return true
	}
	delta := int(math.Abs(float64(len(a.Body) - len(c.Body))))
	return delta > 48 && delta > len(a.Body)/20
}

func (p *probe) timing(payload string, encode bool) (int64, *Response, bool) {
	res, err := p.send(payload, encode)
	if err != nil || res == nil {
		return 0, nil, false
	}
	return res.Duration, res, true
}

func blindConfirm(p *probe, mk func(sec int) string, encode bool) (int64, bool) {
	base := p.baseline.medianTime()
	d5, _, ok := p.timing(mk(5), encode)
	if !ok || d5 < base+3500 {
		return 0, false
	}
	d2, _, ok := p.timing(mk(2), encode)
	if !ok {
		return 0, false
	}
	if d2 > base+900 && d2 < d5-1500 {
		return d5, true
	}
	d5b, _, ok := p.timing(mk(5), encode)
	if ok && d5b >= base+3500 && d2 < d5b-1200 {
		return d5b, true
	}
	return 0, false
}

func checkReflection(p *probe) {
	m := marker()
	r1, err := p.send(m, true)
	if err != nil || r1 == nil || r1.Status == 0 {
		return
	}
	b1 := string(r1.Body)
	if !reflects(b1, m) {
		return
	}
	tag := marker()
	payload := tag + `"'<` + tag + `>`
	r2, err := p.send(payload, true)
	if err != nil || r2 == nil {
		return
	}
	b2 := string(r2.Body)
	switch {
	case strings.Contains(b2, "<"+tag+">"):
		p.add(&Finding{Type: "xss-reflected", Title: "Reflected cross-site scripting", Severity: SevHigh, Confidence: ConfFirm,
			CWE: "CWE-79", Payload: payload,
			Detail:      "Input is reflected into the HTML response with angle brackets intact, so an attacker-supplied value can inject markup and script.",
			Remediation: "Apply context-aware output encoding and deploy a restrictive Content-Security-Policy.",
			Repro:       p.repro(payload),
			Evidence:    []Evidence{{Label: "Unescaped reflection", Flow: r2.FlowID, Snippet: around(b2, "<"+tag+">", 90)}}})
	case strings.Contains(b2, tag+`"`) || strings.Contains(b2, tag+`'`):
		p.add(&Finding{Type: "xss-attr", Title: "Reflected input breaks attribute quoting", Severity: SevMedium, Confidence: ConfTentative,
			CWE: "CWE-79", Payload: payload,
			Detail:      "A quote character in reflected input is returned unencoded, which can allow attribute or event-handler injection depending on context.",
			Remediation: "Encode quotes and angle brackets in reflected values.",
			Repro:       p.repro(payload),
			Evidence:    []Evidence{{Label: "Reflection", Flow: r2.FlowID, Snippet: around(b2, tag, 90)}}})
	default:
		if isHTMLResp(r1) {
			p.add(&Finding{Type: "reflected-input", Title: "Input reflected in response", Severity: SevInfo, Confidence: ConfFirm,
				CWE: "CWE-20",
				Detail:   "User input is reflected in the response, though special characters appear encoded here. Worth reviewing in other contexts.",
				Evidence: []Evidence{{Label: "Reflection", Flow: r1.FlowID, Snippet: around(b1, m, 70)}}})
		}
	}
}

func (p *probe) sqli(technique, payload, evidence string, conf Confidence, flow int64, dur int64) {
	detail := "The " + p.point.Where + " parameter appears injectable (" + technique + ")."
	if dur > 0 {
		detail += " A time-based payload delayed the response to about " + itoa(int(dur/1000)) + "s."
	}
	ev := []Evidence{}
	if evidence != "" {
		ev = append(ev, Evidence{Label: "Database error", Flow: flow, Snippet: clip(evidence, 300)})
	}
	p.add(&Finding{Type: "sqli", Title: "SQL injection (" + technique + ")", Severity: SevHigh, Confidence: conf,
		CWE: "CWE-89", Payload: payload, Detail: detail,
		Remediation: "Use parameterised queries or prepared statements; never build SQL from user input.",
		Repro:       p.repro(payload), Evidence: ev})
}

func checkSQLi(p *probe) {
	base := p.point.Value
	for _, pay := range sqlErrorPayloads {
		r, err := p.send(base+pay, true)
		if err != nil || r == nil {
			continue
		}
		if m, ok := p.baseline.newError(r); ok && sqlErrorSig.MatchString(string(r.Body)) {
			conf := ConfFirm
			if r2, _ := p.send(base+pay+pay, true); r2 != nil && !sqlErrorSig.MatchString(string(r2.Body)) {
				conf = ConfCertain
			}
			p.sqli("error-based", base+pay, m, conf, r.FlowID, 0)
			return
		}
	}
	for _, pair := range sqlBooleanPairs {
		rt, et := p.send(base+pair[0], true)
		rf, ef := p.send(base+pair[1], true)
		if et != nil || ef != nil || rt == nil || rf == nil {
			continue
		}
		if similar(rt, p.baseline) && differ(rt, rf) {
			p.sqli("boolean-based", base+pair[0]+"  vs  "+base+pair[1], "", ConfFirm, rt.FlowID, 0)
			return
		}
	}
	if p.opts.Intensity != IntensityLight {
		for _, tmpl := range sqlTimeTemplates {
			mk := func(s int) string { return base + tmpl(s) }
			if dur, ok := blindConfirm(p, mk, true); ok {
				p.sqli("time-based blind", mk(5), "", ConfFirm, 0, dur)
				return
			}
		}
	}
}

func checkSSTI(p *probe) {
	a, b := 1000+randInt(8000), 1000+randInt(8000)
	product := itoa(a * b)
	if strings.Contains(p.baseline.body, product) {
		return
	}
	for _, eng := range sstiEngines {
		pay := eng.tmpl(a, b)
		r, err := p.send(pay, true)
		if err != nil || r == nil {
			continue
		}
		body := string(r.Body)
		if strings.Contains(body, product) && !strings.Contains(body, pay) {
			p.add(&Finding{Type: "ssti", Title: "Server-side template injection", Severity: SevHigh, Confidence: ConfFirm,
				CWE: "CWE-1336", Payload: pay,
				Detail:      "The expression " + pay + " was evaluated server-side to " + product + " (" + eng.name + "), indicating template injection that often leads to remote code execution.",
				Remediation: "Never place user input into template source; use a sandboxed, logic-less templating approach.",
				Repro:       p.repro(pay),
				Evidence:    []Evidence{{Label: "Evaluated result", Flow: r.FlowID, Snippet: around(body, product, 70)}}})
			return
		}
	}
}

func checkCmdInjection(p *probe) {
	if p.opts.Intensity == IntensityLight {
		return
	}
	base := p.point.Value
	for _, tmpl := range cmdTimeTemplates {
		mk := func(s int) string { return base + tmpl(s) }
		if dur, ok := blindConfirm(p, mk, true); ok {
			p.add(&Finding{Type: "cmdi", Title: "OS command injection (time-based)", Severity: SevCritical, Confidence: ConfFirm,
				CWE: "CWE-78", Payload: mk(5),
				Detail:      "A shell time-delay payload delayed the response to about " + itoa(int(dur/1000)) + "s, indicating injected commands are executed by the operating system.",
				Remediation: "Avoid shelling out with user input; use safe APIs and strict allowlists, never string concatenation into a shell.",
				Repro:       p.repro(mk(5))})
			return
		}
	}
}

func checkTraversal(p *probe) {
	for _, pay := range traversalPayloads {
		r, err := p.send(pay, false)
		if err != nil || r == nil {
			continue
		}
		body := string(r.Body)
		if passwdSig.MatchString(body) && !passwdSig.MatchString(p.baseline.body) {
			p.traversalHit(pay, "/etc/passwd contents", passwdSig.FindString(body), r.FlowID)
			return
		}
		if winIniSig.MatchString(body) && !winIniSig.MatchString(p.baseline.body) {
			p.traversalHit(pay, "Windows win.ini contents", winIniSig.FindString(body), r.FlowID)
			return
		}
	}
}

func (p *probe) traversalHit(payload, what, snippet string, flow int64) {
	p.add(&Finding{Type: "traversal", Title: "Path traversal / local file inclusion", Severity: SevHigh, Confidence: ConfCertain,
		CWE: "CWE-22", Payload: payload,
		Detail:      "Supplying " + payload + " returned " + what + ", confirming the parameter is used to build a filesystem path.",
		Remediation: "Resolve and canonicalise paths against a fixed base directory and reject traversal sequences.",
		Repro:       p.repro(payload),
		Evidence:    []Evidence{{Label: what, Flow: flow, Snippet: clip(snippet, 200)}}})
}

func checkNoSQLi(p *probe) {
	base := p.point.Value
	for _, pay := range nosqlPayloads {
		r, err := p.send(base+pay, true)
		if err != nil || r == nil {
			continue
		}
		if nosqlErrorSig.MatchString(string(r.Body)) && !nosqlErrorSig.MatchString(p.baseline.body) {
			p.add(&Finding{Type: "nosqli", Title: "Possible NoSQL injection", Severity: SevHigh, Confidence: ConfTentative,
				CWE: "CWE-943", Payload: base + pay,
				Detail:      "A NoSQL-style payload produced a database error distinct from the baseline, suggesting the input reaches a NoSQL query unsanitised.",
				Remediation: "Validate and type-check inputs; use query builders that separate operators from data.",
				Repro:       p.repro(base + pay),
				Evidence:    []Evidence{{Label: "Error", Flow: r.FlowID, Snippet: clip(nosqlErrorSig.FindString(string(r.Body)), 200)}}})
			return
		}
	}
}

func looksURL(v string) bool {
	return strings.Contains(v, "http://") || strings.Contains(v, "https://") || strings.HasPrefix(v, "//") || strings.HasPrefix(v, "/")
}

func checkOpenRedirect(p *probe) {
	if p.point.Where == "header" {
		return
	}
	if !redirectParamNames.MatchString(p.point.Name) && !looksURL(p.point.Value) {
		return
	}
	const canary = "sift-oob.example"
	for _, pay := range []string{"https://" + canary + "/", "//" + canary + "/", "/\\" + canary + "/", "https:/" + canary} {
		r, err := p.send(pay, true)
		if err != nil || r == nil {
			continue
		}
		loc := r.Header.Get("Location")
		if loc != "" && r.Status/100 == 3 && redirectsTo(loc, canary) {
			p.add(&Finding{Type: "open-redirect", Title: "Open redirect", Severity: SevMedium, Confidence: ConfFirm,
				CWE: "CWE-601", Payload: pay,
				Detail:      "The parameter controls the redirect target; a crafted value sent the browser to an external host.",
				Remediation: "Redirect only to a server-side allowlist of paths or hosts.",
				Repro:       p.repro(pay),
				Evidence:    []Evidence{{Label: "Location", Flow: r.FlowID, Snippet: loc}}})
			return
		}
	}
}

func redirectsTo(loc, host string) bool {
	if u, err := url.Parse(loc); err == nil && strings.EqualFold(u.Hostname(), host) {
		return true
	}
	return strings.Contains(loc, "//"+host) || strings.HasPrefix(loc, "https://"+host) || strings.HasPrefix(loc, "http://"+host)
}

func checkCRLF(p *probe) {
	for _, c := range crlfPayloads {
		r, err := p.send(c.payload, c.encode)
		if err != nil || r == nil {
			continue
		}
		if r.Header.Get(crlfHeader) != "" {
			p.add(&Finding{Type: "crlf", Title: "CRLF / HTTP response header injection", Severity: SevMedium, Confidence: ConfFirm,
				CWE: "CWE-113", Payload: c.payload,
				Detail:      "An injected carriage-return/line-feed sequence added a new response header, which can enable response splitting, cache poisoning or session fixation.",
				Remediation: "Strip CR and LF from any user input placed into response headers.",
				Repro:       p.repro(c.payload),
				Evidence:    []Evidence{{Label: "Injected header reflected", Flow: r.FlowID, Snippet: crlfHeader + ": " + r.Header.Get(crlfHeader)}}})
			return
		}
	}
}

func checkSSRF(p *probe) {
	if p.point.Where == "header" {
		if !strings.Contains(strings.ToLower(p.point.Name), "forwarded") && !strings.Contains(strings.ToLower(p.point.Name), "client") {
			return
		}
	} else if !ssrfParamNames.MatchString(p.point.Name) && !looksURL(p.point.Value) {
		return
	}
	for _, pay := range ssrfPayloads {
		r, err := p.send(pay, true)
		if err != nil || r == nil {
			continue
		}
		body := string(r.Body)
		if ssrfSig.MatchString(body) && !ssrfSig.MatchString(p.baseline.body) {
			p.add(&Finding{Type: "ssrf", Title: "Server-side request forgery", Severity: SevHigh, Confidence: ConfFirm,
				CWE: "CWE-918", Payload: pay,
				Detail:      "The server fetched an internal URL supplied in this parameter and returned metadata-service content, confirming SSRF.",
				Remediation: "Resolve and validate outbound URLs against an allowlist; block link-local and internal ranges.",
				Repro:       p.repro(pay),
				Evidence:    []Evidence{{Label: "Internal response", Flow: r.FlowID, Snippet: clip(ssrfSig.FindString(body), 200)}}})
			return
		}
	}
	if p.opts.Collab != "" {
		p.send("http://"+p.opts.Collab+"/"+marker(), true)
	}
}

type targetProbe struct {
	run      *runner
	target   *target
	baseline *baseline
	opts     Options
}

func checkXXE(tp *targetProbe) {
	if !strings.Contains(tp.target.ctype, "xml") {
		return
	}
	m := marker()
	entityBody := `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY t "` + m + `">]><r>&t;</r>`
	c := *tp.target
	c.body = []byte(entityBody)
	c.header = tp.target.header.Clone()
	c.header.Set("Content-Type", "application/xml")
	req := c.request("scan")
	r, err := tp.run.send(req)
	if err != nil || r == nil {
		return
	}
	if !strings.Contains(string(r.Body), m) {
		return
	}
	fileBody := `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>`
	c.body = []byte(fileBody)
	req2 := c.request("scan")
	r2, err := tp.run.send(req2)
	sev, conf, detail := SevMedium, ConfFirm, "The XML parser resolves inline entities, so it is likely vulnerable to external entity injection."
	ev := []Evidence{{Label: "Entity expanded", Flow: r.FlowID, Snippet: around(string(r.Body), m, 40)}}
	if err == nil && r2 != nil && passwdSig.MatchString(string(r2.Body)) {
		sev, conf, detail = SevHigh, ConfCertain, "The XML parser resolved an external entity and returned /etc/passwd, confirming XXE with local file read."
		ev = append(ev, Evidence{Label: "/etc/passwd", Flow: r2.FlowID, Snippet: clip(passwdSig.FindString(string(r2.Body)), 200)})
	}
	tp.run.add(&Finding{Type: "xxe", Title: "XML external entity processing", Severity: sev, Confidence: conf,
		CWE: "CWE-611", Method: tp.target.method, URL: tp.target.url(), Host: tp.target.host, Where: "body",
		Detail:      detail,
		Remediation: "Disable DTD and external entity processing in the XML parser.",
		Evidence:    ev})
}

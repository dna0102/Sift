package main

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// The scanner walks decompiled code and resources and flags things worth a closer look:
// endpoints, secrets, SSL-pinning code, auth/captcha screens, trackers. It only reads and
// labels; it never changes an app or talks to a server.

type Finding struct {
	Kind    string `json:"kind"`    // endpoint | secret | pinning | auth | tracker | deeplink | cleartext
	Subtype string `json:"subtype"` // e.g. "AWS key", "login", "reCAPTCHA", "OkHttp CertificatePinner"
	Value   string `json:"value"`   // the matched text (secrets are masked)
	File    string `json:"file"`    // path relative to the decompiled root
	Line    int    `json:"line"`
	Snippet string `json:"snippet"`
	Sev     string `json:"sev"` // info | low | med | high
}

type pattern struct {
	kind, subtype, sev string
	re                 *regexp.Regexp
	mask               bool // mask the matched value (secrets)
}

// Pre-compiled patterns. Kept readable: each line is one thing we look for.
var patterns = func() []pattern {
	p := func(kind, subtype, sev, rx string, mask bool) pattern {
		return pattern{kind, subtype, sev, regexp.MustCompile(rx), mask}
	}
	return []pattern{
		// endpoints — stop at a quote, whitespace, backslash or closing bracket so
		// concatenated string literals don't run together into one giant "URL".
		p("endpoint", "URL", "info", `https?://[^\s"'<>\\)\]}]{4,300}`, false),
		p("endpoint", "WebSocket", "info", `wss?://[^\s"'<>\\)\]}]{4,300}`, false),

		// secrets
		p("secret", "AWS access key", "high", `AKIA[0-9A-Z]{16}`, true),
		p("secret", "AWS secret key", "high", `(?i)aws.{0,20}['"][0-9a-zA-Z/+]{40}['"]`, true),
		p("secret", "Google API key", "high", `AIza[0-9A-Za-z\-_]{35}`, true),
		p("secret", "Google OAuth", "med", `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`, false),
		p("secret", "Firebase URL", "low", `https://[a-z0-9-]+\.firebaseio\.com`, false),
		p("secret", "Firebase database", "low", `[a-z0-9-]+\.firebasedatabase\.app`, false),
		p("secret", "Stripe live key", "high", `sk_live_[0-9a-zA-Z]{24,}`, true),
		p("secret", "Stripe publishable", "low", `pk_live_[0-9a-zA-Z]{24,}`, false),
		p("secret", "Slack token", "high", `xox[baprs]-[0-9A-Za-z-]{10,48}`, true),
		p("secret", "GitHub token", "high", `gh[pousr]_[0-9A-Za-z]{36}`, true),
		p("secret", "JWT", "med", `eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`, true),
		p("secret", "Private key", "high", `-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`, true),
		p("secret", "Twilio SID", "high", `AC[0-9a-fA-F]{32}`, true),
		p("secret", "Mapbox token", "med", `(?:pk|sk)\.eyJ[A-Za-z0-9_-]{50,}`, true),
		p("secret", "Hardcoded password", "med", `(?i)(?:password|passwd|pwd|secret|api[_-]?key|apikey|auth[_-]?token)\s*[=:]\s*['"][^'"\s]{6,60}['"]`, true),

		// SSL pinning — Android
		p("pinning", "OkHttp CertificatePinner", "info", `CertificatePinner`, false),
		p("pinning", "Custom TrustManager", "info", `(?:implements|extends)\s+(?:X509TrustManager|TrustManager)`, false),
		p("pinning", "X509TrustManager", "info", `X509TrustManager`, false),
		p("pinning", "TrustKit", "info", `(?:com\.datatheorem\.android\.trustkit|TrustKit)`, false),
		p("pinning", "Network security config pin", "info", `<pin-set|<pin\s+digest`, false),
		p("pinning", "checkServerTrusted", "info", `checkServerTrusted`, false),
		p("pinning", "Volley pinning", "info", `HurlStack.*SSLSocketFactory`, false),
		// SSL pinning — iOS / cross-platform
		p("pinning", "Alamofire ServerTrust", "info", `(?:ServerTrustPolicy|PinnedCertificatesTrustEvaluator|evaluateServerTrust)`, false),
		p("pinning", "TrustKit (iOS)", "info", `TSKPinnedDomains`, false),
		p("pinning", "SecTrustEvaluate", "info", `SecTrustEvaluate`, false),
		p("pinning", "Flutter pinning", "info", `(?:http_certificate_pinning|badCertificateCallback|SecurityContext)`, false),
		p("pinning", "React Native pinning", "info", `(?:react-native-ssl-pinning|TrustManagerFactory)`, false),

		// auth & captcha mapping (identify, not attack)
		p("auth", "reCAPTCHA", "info", `(?i)(?:recaptcha|www\.google\.com/recaptcha|6L[0-9A-Za-z_-]{38})`, false),
		p("auth", "hCaptcha", "info", `(?i)hcaptcha`, false),
		p("auth", "Cloudflare Turnstile", "info", `(?i)(?:turnstile|challenges\.cloudflare\.com)`, false),
		p("auth", "Arkose/FunCaptcha", "info", `(?i)(?:arkoselabs|funcaptcha)`, false),
		p("auth", "OAuth / OIDC", "info", `(?i)(?:oauth2?|/authorize\b|/token\b|openid|id_token|response_type=)`, false),
		p("auth", "Login endpoint", "info", `(?i)["'/](?:login|signin|sign-in|authenticate|session)s?["'/?]`, false),
		p("auth", "Register endpoint", "info", `(?i)["'/](?:register|signup|sign-up|createaccount|create-account)s?["'/?]`, false),
		p("auth", "OTP / 2FA", "info", `(?i)(?:\botp\b|one.?time.?password|verif(?:y|ication).?code|two.?factor|2fa|mfa)`, false),
		p("auth", "Biometric", "info", `(?i)(?:BiometricPrompt|FaceID|TouchID|LocalAuthentication|FingerprintManager)`, false),
		p("auth", "Password reset", "info", `(?i)(?:forgot.?password|reset.?password|/password/reset)`, false),
		p("auth", "Payment", "info", `(?i)(?:PaymentSheet|BillingClient|/checkout|/payment|/purchase|in.?app.?purchase|StoreKit)`, false),

		// trackers / analytics SDKs
		p("tracker", "Google Analytics / Firebase", "info", `(?:google-analytics|firebase-analytics|FirebaseAnalytics|GoogleAnalytics)`, false),
		p("tracker", "Facebook SDK", "info", `(?:com\.facebook\.|FacebookSDK|graph\.facebook\.com)`, false),
		p("tracker", "Crashlytics", "info", `(?:Crashlytics|crashlytics)`, false),
		p("tracker", "AppsFlyer", "info", `(?i)appsflyer`, false),
		p("tracker", "Adjust", "info", `(?:com\.adjust\.sdk|app\.adjust\.com)`, false),
		p("tracker", "Sentry", "info", `(?i)(?:sentry\.io|io\.sentry)`, false),
		p("tracker", "Branch", "info", `(?i)branch\.io`, false),
		p("tracker", "Amplitude", "info", `(?i)amplitude\.com`, false),
		p("tracker", "Mixpanel", "info", `(?i)mixpanel`, false),
	}
}()

// hosts we never report as endpoints (framework noise)
var boringHost = regexp.MustCompile(`(?i)(?:^https?://(?:schemas\.android\.com|www\.w3\.org|java\.sun\.com|xmlpull\.org|localhost|127\.0\.0\.1|example\.com|android\.googlesource))`)

// scanConfig limits a scan so a huge app can't run forever or use all memory.
type scanConfig struct {
	root        string
	maxFileSize int64
	maxFindings int
	onProgress  func(files int)
	cancel      <-chan struct{}
}

type scanResult struct {
	Findings []Finding
	Files    int
	Hit      bool // maxFindings reached
}

var codeExt = map[string]bool{
	".java": true, ".kt": true, ".xml": true, ".json": true, ".js": true, ".ts": true,
	".smali": true, ".txt": true, ".properties": true, ".gradle": true, ".cfg": true,
	".plist": true, ".html": true, ".m": true, ".swift": true, ".h": true, ".c": true, ".cfg.json": true,
}

func scanTree(cfg scanConfig) scanResult {
	if cfg.maxFileSize == 0 {
		cfg.maxFileSize = 4 << 20
	}
	if cfg.maxFindings == 0 {
		cfg.maxFindings = 20000
	}
	var (
		mu       sync.Mutex
		findings []Finding
		seen     = map[string]bool{} // dedupe by kind+subtype+value
		files    int
		hit      bool
	)
	paths := make(chan string, 256)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range paths {
				fs := scanFile(path, cfg.root, cfg.maxFileSize)
				mu.Lock()
				files++
				if cfg.onProgress != nil && files%200 == 0 {
					cfg.onProgress(files)
				}
				for _, f := range fs {
					key := f.Kind + "|" + f.Subtype + "|" + f.Value
					if seen[key] {
						continue
					}
					seen[key] = true
					findings = append(findings, f)
					if len(findings) >= cfg.maxFindings {
						hit = true
						mu.Unlock()
						return
					}
				}
				mu.Unlock()
			}
		}()
	}
	filepath.WalkDir(cfg.root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		select {
		case <-cfg.cancel:
			return filepath.SkipAll
		default:
		}
		ext := strings.ToLower(filepath.Ext(path))
		if !codeExt[ext] {
			return nil
		}
		paths <- path
		return nil
	})
	close(paths)
	wg.Wait()

	sortFindings(findings)
	return scanResult{Findings: findings, Files: files, Hit: hit}
}

func scanFile(path, root string, maxSize int64) []Finding {
	st, err := os.Stat(path)
	if err != nil || st.Size() > maxSize {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	rel, _ := filepath.Rel(root, path)
	rel = filepath.ToSlash(rel)

	var out []Finding
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		if len(text) > 8000 {
			text = text[:8000] // skip giant minified lines past this point
		}
		for i := range patterns {
			pt := &patterns[i]
			m := pt.re.FindString(text)
			if m == "" {
				continue
			}
			// A compiler can fold several string constants into one, so a single match may
			// contain several URLs run together; split them back apart.
			values := []string{m}
			if pt.kind == "endpoint" {
				values = splitConcatURLs(m)
			}
			for _, v := range values {
				if pt.kind == "endpoint" && boringHost.MatchString(v) {
					continue
				}
				val := v
				if pt.mask {
					val = maskSecret(v)
				}
				out = append(out, Finding{Kind: pt.kind, Subtype: pt.subtype, Value: clip(val, 200),
					File: rel, Line: line, Snippet: clip(strings.TrimSpace(text), 300), Sev: pt.sev})
			}
		}
	}
	return out
}

var embeddedScheme = regexp.MustCompile(`(?:https?|wss?)://`)

// splitConcatURLs breaks "http://a/x...http://b/y" (folded constants) into separate URLs,
// and trims an obvious trailing identifier that was concatenated on (e.g. a key).
func splitConcatURLs(m string) []string {
	locs := embeddedScheme.FindAllStringIndex(m, -1)
	if len(locs) <= 1 {
		return []string{trimTrailingToken(m)}
	}
	var out []string
	for i, loc := range locs {
		end := len(m)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		out = append(out, trimTrailingToken(m[loc[0]:end]))
	}
	return out
}

// trimTrailingToken drops a long run of letters/digits glued onto the end of a URL with no
// path separator, which is usually a separate constant (an API key) folded on.
func trimTrailingToken(u string) string {
	i := strings.LastIndexAny(u, "/?&=.-_:")
	if i < 8 { // keep at least the scheme+host
		return u
	}
	tail := u[i+1:]
	if len(tail) >= 20 && isAlnum(tail) {
		return u[:i+1]
	}
	return u
}

func isAlnum(s string) bool {
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func maskSecret(s string) string {
	if len(s) <= 10 {
		return strings.Repeat("•", len(s))
	}
	return s[:4] + strings.Repeat("•", 8) + s[len(s)-4:]
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

var sevRank = map[string]int{"high": 0, "med": 1, "low": 2, "info": 3}
var kindRank = map[string]int{"pinning": 0, "secret": 1, "auth": 2, "endpoint": 3, "deeplink": 4, "cleartext": 5, "tracker": 6}

func sortFindings(f []Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		if kindRank[f[i].Kind] != kindRank[f[j].Kind] {
			return kindRank[f[i].Kind] < kindRank[f[j].Kind]
		}
		if sevRank[f[i].Sev] != sevRank[f[j].Sev] {
			return sevRank[f[i].Sev] < sevRank[f[j].Sev]
		}
		return f[i].Subtype < f[j].Subtype
	})
}

// hostOf extracts a hostname from a URL finding, for cross-linking with captured traffic.
func hostOf(url string) string {
	s := url
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(s)
}

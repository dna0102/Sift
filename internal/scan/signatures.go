package scan

import "regexp"

type sig struct {
	name string
	re   *regexp.Regexp
}

var secretSigs = []sig{
	{"AWS access key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"AWS secret key", regexp.MustCompile(`(?i)aws.{0,20}['"][0-9a-zA-Z/+]{40}['"]`)},
	{"Google API key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{"Stripe live key", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`)},
	{"Slack token", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,48}`)},
	{"GitHub token", regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{36}`)},
	{"Private key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`)},
	{"Twilio SID", regexp.MustCompile(`AC[0-9a-fA-F]{32}`)},
	{"JWT", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}`)},
}

var errorSigs = []sig{
	{"Java stack trace", regexp.MustCompile(`(?:at [a-zA-Z_$][\w$]*(?:\.[\w$]+)+\([\w$]+\.java:\d+\)|javax?\.[\w.]+Exception)`)},
	{"PHP error", regexp.MustCompile(`(?i)(?:Fatal error|Warning|Notice|Parse error):.{0,80}\bin\b.{0,120}\bon line\b|Stack trace:\s*#0`)},
	{"Python traceback", regexp.MustCompile(`Traceback \(most recent call last\):`)},
	{"ASP.NET error", regexp.MustCompile(`(?i)(?:System\.[\w.]+Exception|Server Error in '/' Application|\[\w+Exception:)`)},
	{"Ruby error", regexp.MustCompile(`(?i)(?:\.rb:\d+:in\s+` + "`" + `|ActionController::|RuntimeError)`)},
	{"Node stack", regexp.MustCompile(`(?:at Object\.<anonymous>|\bat .+\(.+node_modules.+:\d+:\d+\))`)},
	{"SQL error", regexp.MustCompile(`(?i)(?:SQL syntax.*MySQL|Warning.*mysqli?|PostgreSQL.*ERROR|ORA-\d{5}|SQLite3?::|Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark after the character string|SQLSTATE\[)`)},
}

var internalIP = regexp.MustCompile(`\b(?:10\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b`)

var pathLeak = regexp.MustCompile(`(?:[A-Za-z]:\\(?:[\w.\- ]+\\){1,}[\w.\- ]+|/(?:home|var|usr|etc|opt|srv|www)/(?:[\w.\-]+/){1,}[\w.\-]+)`)

var sensitiveParam = regexp.MustCompile(`(?i)(?:^|[?&])(?:pass(?:word|wd)?|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|session(?:id)?|token)=`)

var sqlErrorSig = errorSigs[6].re

var jsEndpoint = regexp.MustCompile(`(?:"|'|` + "`" + `)(/(?:api|v\d|graphql|rest|internal|admin|auth|user|account|oauth)[A-Za-z0-9_./\-]{0,120})(?:"|'|` + "`" + `)`)

var absEndpoint = regexp.MustCompile(`https?://[A-Za-z0-9.\-]+(?:/[A-Za-z0-9_./\-]{0,120})?`)

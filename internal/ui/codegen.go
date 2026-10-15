package ui

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"sift/internal/core"
)

var CodeLangs = []struct{ Key, Label string }{
	{"curl", "cURL"},
	{"curl_win", "cURL (cmd.exe)"},
	{"powershell", "PowerShell"},
	{"python", "Python requests"},
	{"go", "Go net/http"},
	{"fetch", "JavaScript fetch"},
}

var skipInCode = map[string]bool{"Content-Length": true, "Connection": true, "Proxy-Connection": true, "Keep-Alive": true, "Transfer-Encoding": true}

type codeReq struct {
	method, url string
	headers     [][2]string
	body        string
	compressed  bool
}

func requestForCode(f *core.Flow) codeReq {
	f.Lock()
	defer f.Unlock()
	c := codeReq{method: f.Method, url: f.URL()}
	defaultHost := core.HostPort(f.Host, f.Port, f.Scheme)
	for _, h := range harHeaders(f.ReqHeader) {
		switch {
		case skipInCode[h.Name]:
		case h.Name == "Host" && h.Value == defaultHost:
		case h.Name == "Accept-Encoding":
			c.compressed = true
		default:
			c.headers = append(c.headers, [2]string{h.Name, h.Value})
		}
	}
	if len(f.ReqBody) > 0 && !core.IsBinary(f.ReqBody) {
		c.body = string(f.ReqBody)
	}
	return c
}

func shQuote(s string) string  { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
func cmdQuote(s string) string { return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"` }
func psQuote(s string) string  { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func ToCode(f *core.Flow, lang string) string {
	c := requestForCode(f)
	var b strings.Builder
	switch lang {
	case "curl", "curl_win":
		q, join := shQuote, " \\\n  "
		if lang == "curl_win" {
			q, join = cmdQuote, " ^\n  "
		}
		parts := []string{"curl"}
		if c.method != "GET" || c.body != "" {
			parts = append(parts, "-X", c.method)
		}
		parts = append(parts, q(c.url))
		for _, h := range c.headers {
			parts = append(parts, "-H", q(h[0]+": "+h[1]))
		}
		if c.body != "" {
			parts = append(parts, "--data-raw", q(c.body))
		}
		if c.compressed {
			parts = append(parts, "--compressed")
		}
		return strings.Join(parts, join)
	case "powershell":
		b.WriteString("$headers = @{\n")
		for _, h := range c.headers {
			if h[0] != "Content-Type" && h[0] != "User-Agent" {
				fmt.Fprintf(&b, "    %s = %s\n", psQuote(h[0]), psQuote(h[1]))
			}
		}
		b.WriteString("}\n\n$response = Invoke-WebRequest -Uri " + psQuote(c.url) + " -Method " + c.method + " -Headers $headers")
		for _, h := range c.headers {
			if h[0] == "Content-Type" {
				b.WriteString(" -ContentType " + psQuote(h[1]))
			}
			if h[0] == "User-Agent" {
				b.WriteString(" -UserAgent " + psQuote(h[1]))
			}
		}
		if c.body != "" {
			b.WriteString(" -Body " + psQuote(c.body))
		}
		b.WriteString("\n$response.Content")
	case "python":
		b.WriteString("import requests\n\n")
		b.WriteString("url = " + strconv.Quote(c.url) + "\nheaders = {\n")
		for _, h := range c.headers {
			fmt.Fprintf(&b, "    %s: %s,\n", strconv.Quote(h[0]), strconv.Quote(h[1]))
		}
		b.WriteString("}\n")
		args := ""
		if c.body != "" {
			b.WriteString("data = " + strconv.Quote(c.body) + "\n")
			args = ", data=data"
		}
		fmt.Fprintf(&b, "\nresponse = requests.request(%s, url, headers=headers%s)\nprint(response.status_code)\nprint(response.text)", strconv.Quote(c.method), args)
	case "go":
		b.WriteString("package main\n\nimport (\n\t\"fmt\"\n\t\"io\"\n\t\"net/http\"\n")
		if c.body != "" {
			b.WriteString("\t\"strings\"\n")
		}
		b.WriteString(")\n\nfunc main() {\n")
		body := "nil"
		if c.body != "" {
			body = "strings.NewReader(" + strconv.Quote(c.body) + ")"
		}
		fmt.Fprintf(&b, "\treq, err := http.NewRequest(%s, %s, %s)\n\tif err != nil {\n\t\tpanic(err)\n\t}\n", strconv.Quote(c.method), strconv.Quote(c.url), body)
		for _, h := range c.headers {
			if h[0] == "Host" {
				fmt.Fprintf(&b, "\treq.Host = %s\n", strconv.Quote(h[1]))
				continue
			}
			fmt.Fprintf(&b, "\treq.Header.Set(%s, %s)\n", strconv.Quote(h[0]), strconv.Quote(h[1]))
		}
		b.WriteString("\n\tresp, err := http.DefaultClient.Do(req)\n\tif err != nil {\n\t\tpanic(err)\n\t}\n\tdefer resp.Body.Close()\n\tdata, _ := io.ReadAll(resp.Body)\n\tfmt.Println(resp.Status)\n\tfmt.Println(string(data))\n}")
	case "fetch":
		hdrs := map[string]string{}
		for _, h := range c.headers {
			if h[0] != "Host" && h[0] != "User-Agent" {
				hdrs[h[0]] = h[1]
			}
		}
		opts := map[string]any{"method": c.method, "headers": hdrs}
		if c.body != "" {
			opts["body"] = c.body
		}
		js, _ := json.MarshalIndent(opts, "", "  ")
		u, _ := json.Marshal(c.url)
		b.WriteString("const response = await fetch(" + string(u) + ", " + string(js) + ");\nconsole.log(await response.text());")
	}
	return b.String()
}

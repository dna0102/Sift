package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The detail pane is rendered here as an HTML fragment; the browser just inserts it.

const (
	textLimit   = 2 << 20   // characters shown inline
	prettyLimit = 1 << 20   // syntax highlighting limit
	treeLimit   = 512 << 10 // JSON tree limit
	hexLimit    = 64 << 10
)

var esc = html.EscapeString

func fmtSize(n int64) string {
	switch {
	case n < 1024:
		return strconv.FormatInt(n, 10) + " B"
	case n < 1<<20:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	case n < 1<<30:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	}
	return fmt.Sprintf("%.2f GB", float64(n)/(1<<30))
}

func fmtDur(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		return "<1 ms"
	case d < time.Second:
		return strconv.FormatInt(d.Milliseconds(), 10) + " ms"
	case d < time.Minute:
		return fmt.Sprintf("%.2f s", d.Seconds())
	}
	return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
}

type DetailOpts struct{ ReqTab, ResTab, ReqMode, ResMode string }

// snapshot copies what rendering needs so the flow lock isn't held while formatting.
type snapshot struct {
	Flow
	url string
	dur time.Duration
}

func snap(f *Flow) *snapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := &snapshot{url: f.URL()}
	s.ID, s.Kind, s.Start, s.End, s.State, s.App = f.ID, f.Kind, f.Start, f.End, f.State, f.App
	s.Method, s.Scheme, s.Host, s.Port, s.Path, s.Proto = f.Method, f.Scheme, f.Host, f.Port, f.Path, f.Proto
	s.Client, s.Server = f.Client, f.Server
	s.ReqHeader, s.ReqBody, s.ReqSize, s.ReqTrunc = f.ReqHeader.Clone(), f.ReqBody, f.ReqSize, f.ReqTrunc
	s.Status, s.StatusText, s.ResProto, s.ResHeader, s.ResTrailer = f.Status, f.StatusText, f.ResProto, f.ResHeader.Clone(), f.ResTrailer.Clone()
	s.ResBody, s.ResSize, s.ResTrunc, s.Decoded = f.ResBody, f.ResSize, f.ResTrunc, f.Decoded
	s.Err, s.Note, s.Tags, s.MappedFrom, s.Timing = f.Err, f.Note, append([]string(nil), f.Tags...), f.MappedFrom, f.Timing
	s.WS, s.WSCount = f.WS, f.WSCount
	s.BytesUp.Store(f.BytesUp.Load())
	s.BytesDown.Store(f.BytesDown.Load())
	end := f.End
	if end.IsZero() {
		end = time.Now()
	}
	s.dur = end.Sub(f.Start)
	return s
}

// body returns the decoded request or response body and its content type.
func (s *snapshot) body(side string) ([]byte, string) {
	if side == "req" {
		return s.ReqBody, s.ReqHeader.Get("Content-Type")
	}
	if s.ResHeader == nil {
		return nil, ""
	}
	b := s.ResBody
	if !s.Decoded {
		b, _ = decodeBody(b, s.ResHeader.Get("Content-Encoding"))
	}
	return b, s.ResHeader.Get("Content-Type")
}

func statusClass(status int, state string) string {
	switch {
	case state == "error" && status == 0:
		return "c5"
	case state == "paused":
		return "c5"
	case status == 0:
		return "c0"
	}
	return "c" + strconv.Itoa(min(status/100, 5))
}

func RenderDetail(f *Flow, o DetailOpts, app *App) string {
	s := snap(f)
	var b strings.Builder
	if s.Kind == "tunnel" || s.Kind == "tls" {
		renderTunnel(&b, s, app)
		return b.String()
	}
	status := "…"
	if s.Status > 0 {
		status = strconv.Itoa(s.Status) + " " + s.StatusText
	} else if s.State == "error" {
		status = "Failed"
	} else if s.State == "paused" {
		status = "Paused"
	}
	id := strconv.FormatInt(s.ID, 10)
	fmt.Fprintf(&b, `<div class="dh"><div class="dh-url"><b>%s</b><span data-copy="%s" title="Click to copy">%s</span></div>`, esc(s.Method), esc(s.url), esc(s.url))
	fmt.Fprintf(&b, `<div class="dh-meta"><span class="%s">%s</span>`, statusClass(s.Status, s.State), esc(status))
	for _, v := range []string{s.ResProto, fmtDur(s.dur), fmtSize(s.ResSize), s.App} {
		if v != "" && v != "0 B" {
			fmt.Fprintf(&b, `<span>%s</span>`, esc(v))
		}
	}
	for _, t := range s.Tags {
		fmt.Fprintf(&b, `<span class="tag">%s</span>`, esc(t))
	}
	b.WriteString(`<span class="grow"></span>`)
	if s.Kind == "http" {
		fmt.Fprintf(&b, `<button data-post="/api/flows/%s/replay" title="Send again (R)">Replay</button>`, id)
		fmt.Fprintf(&b, `<button data-modal="/ui/modal/compose?from=%s" title="Edit and send (E)">Edit</button>`, id)
		b.WriteString(`<details class="menu right"><summary>Copy as</summary><div>`)
		for _, l := range CodeLangs {
			fmt.Fprintf(&b, `<button data-modal="/ui/modal/code?id=%s&lang=%s">%s</button>`, id, l.Key, esc(l.Label))
		}
		b.WriteString(`</div></details>`)
	}
	moreMenu(&b, s, app)
	b.WriteString(`</div>`)
	if s.Err != "" {
		fmt.Fprintf(&b, `<div class="dh-note bad">%s</div>`, esc(s.Err))
	}
	if s.MappedFrom != "" {
		fmt.Fprintf(&b, `<div class="dh-note">Mapped from %s</div>`, esc(s.MappedFrom))
	}
	if s.State == "paused" {
		b.WriteString(`<div class="dh-note bad">Paused at a breakpoint.</div>`)
	}
	b.WriteString(`</div><div class="panes">`)
	renderPane(&b, s, "req", o.ReqTab, o.ReqMode)
	renderPane(&b, s, "res", o.ResTab, o.ResMode)
	b.WriteString(`</div>`)
	return b.String()
}

func moreMenu(b *strings.Builder, s *snapshot, app *App) {
	id := strconv.FormatInt(s.ID, 10)
	cfg := app.cfg.Get()
	pinned, excluded := contains(cfg.Pinned, s.Host), contains(cfg.SSLExclude, s.Host)
	host := url.QueryEscape(s.Host)
	b.WriteString(`<details class="menu right"><summary title="More">•••</summary><div>`)
	if s.Kind == "http" || s.Kind == "ws" {
		for _, t := range []struct{ typ, label string }{
			{"breakpoint", "Add breakpoint…"}, {"map_local", "Map local…"}, {"map_remote", "Map remote…"},
			{"rewrite", "Rewrite…"}, {"block", "Block this URL…"},
		} {
			fmt.Fprintf(b, `<button data-modal="/ui/modal/rules?type=%s&from=%s">%s</button>`, t.typ, id, t.label)
		}
	}
	fmt.Fprintf(b, `<button data-modal="/ui/modal/rules?type=block&host=%s">Block %s…</button><hr>`, host, esc(s.Host))
	fmt.Fprintf(b, `<button data-post="/api/hosts/pin?host=%s">%s %s</button>`, host, map[bool]string{true: "Unpin", false: "Pin"}[pinned], esc(s.Host))
	fmt.Fprintf(b, `<button data-post="/api/hosts/decrypt?host=%s">%s %s</button>`, host,
		map[bool]string{true: "Decrypt", false: "Don't decrypt"}[excluded], esc(s.Host))
	if s.App != "" && s.App != "Sift" {
		fmt.Fprintf(b, `<button data-post="/api/apps/decrypt?app=%s">%s %s</button>`, url.QueryEscape(s.App),
			map[bool]string{true: "Decrypt", false: "Don't decrypt"}[contains(cfg.SSLExcludeApps, s.App)], esc(s.App))
	}
	b.WriteString(`<hr>`)
	if s.Kind == "http" || s.Kind == "ws" {
		fmt.Fprintf(b, `<a href="/export/har?ids=%s" download>Export as HAR</a>`, id)
	}
	fmt.Fprintf(b, `<button data-post="/api/flows/delete?ids=%s">Delete</button></div></details>`, id)
}

func renderTunnel(b *strings.Builder, s *snapshot, app *App) {
	title, text := "Not decrypted", "Only the connection is visible: host, app, timing and bytes, not the requests inside."
	if s.Note != "" {
		title = "Not decrypted: " + s.Note
	}
	if s.Kind == "tls" {
		title, text = "TLS handshake failed", s.Err
	}
	fmt.Fprintf(b, `<div class="dh"><div class="dh-url"><b>%s</b><span>%s:%d</span></div><div class="dh-meta"><span class="grow"></span>`, esc(s.Method), esc(s.Host), s.Port)
	moreMenu(b, s, app)
	fmt.Fprintf(b, `</div></div><div class="panes one"><section class="pane"><div class="pane-body"><h3 class="ph">%s</h3><p class="explain">%s</p>`, title, esc(text))
	host := url.QueryEscape(s.Host)
	b.WriteString(`<p class="btnrow">`)
	switch {
	case s.Kind == "tls":
		b.WriteString(`<button class="btn" data-modal="/ui/modal/cert">Certificate setup</button>`)
	case strings.Contains(s.Note, "known to pin"): // controlled by the HTTPS settings toggle below
	case strings.Contains(s.Note, "certificate"):
		fmt.Fprintf(b, `<button class="btn" data-post="/ui/pins/forget?host=%s">Try decrypting again</button>`, host)
	case strings.Contains(s.Note, "is excluded"):
		fmt.Fprintf(b, `<button class="btn" data-post="/api/apps/decrypt?app=%s">Decrypt %s again</button>`, url.QueryEscape(s.App), esc(s.App))
	case strings.Contains(s.Note, "host excluded"):
		fmt.Fprintf(b, `<button class="btn" data-post="/api/hosts/decrypt?host=%s">Decrypt this host again</button>`, host)
	}
	b.WriteString(`<button class="btn" data-modal="/ui/modal/ssl">HTTPS settings</button></p>`)
	dur := fmtDur(s.dur)
	if s.End.IsZero() {
		dur += " (open)"
	}
	kvTable(b, [][2]string{{"Host", s.Host + ":" + strconv.Itoa(s.Port)}, {"App", dash(s.App)}, {"Server", dash(s.Server)},
		{"Started", s.Start.Format("15:04:05.000")}, {"Duration", dur},
		{"Sent", fmtSize(s.BytesUp.Load())}, {"Received", fmtSize(s.BytesDown.Load())}})
	b.WriteString(`</div></section></div>`)
}

func protocols(app, server string) string {
	if server == "" || server == app {
		return dash(app)
	}
	return app + " from the app, " + server + " to the server"
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func kvTable(b *strings.Builder, rows [][2]string) {
	b.WriteString(`<table class="kv">`)
	for _, r := range rows {
		fmt.Fprintf(b, `<tr><th>%s</th><td data-copy="%s">%s</td></tr>`, esc(r[0]), esc(r[1]), esc(r[1]))
	}
	b.WriteString(`</table>`)
}

func headerRows(h http.Header) [][2]string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var rows [][2]string
	for _, k := range keys {
		for _, v := range h[k] {
			rows = append(rows, [2]string{k, v})
		}
	}
	return rows
}

type tab struct{ key, label, count string }

func tabsFor(s *snapshot, side string) []tab {
	if side == "req" {
		q, _ := url.ParseQuery(strings.SplitN(s.Path+"?", "?", 2)[1])
		return []tab{
			{"headers", "Headers", countStr(len(headerRows(s.ReqHeader)))},
			{"query", "Query", countStr(len(q))},
			{"body", "Body", sizeStr(s.ReqSize)},
			{"cookies", "Cookies", countStr(len((&http.Request{Header: s.ReqHeader}).Cookies()))},
			{"raw", "Raw", ""},
			{"overview", "Overview", ""},
		}
	}
	var t []tab
	if s.Kind == "ws" {
		t = append(t, tab{"messages", "Messages", countStr(s.WSCount)})
	}
	return append(t,
		tab{"headers", "Headers", countStr(len(headerRows(s.ResHeader)))},
		tab{"body", "Body", sizeStr(s.ResSize)},
		tab{"cookies", "Cookies", countStr(len((&http.Response{Header: s.ResHeader}).Cookies()))},
		tab{"raw", "Raw", ""},
		tab{"timing", "Timing", ""},
	)
}

func countStr(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}

func sizeStr(n int64) string {
	if n == 0 {
		return ""
	}
	return fmtSize(n)
}

func renderPane(b *strings.Builder, s *snapshot, side, cur, mode string) {
	tabs := tabsFor(s, side)
	valid := false
	for _, t := range tabs {
		valid = valid || t.key == cur
	}
	if !valid {
		cur = tabs[0].key
		if side == "res" && s.Kind != "ws" {
			cur = "body"
		}
	}
	name := map[string]string{"req": "Request", "res": "Response"}[side]
	fmt.Fprintf(b, `<section class="pane"><nav class="tabs"><span class="pane-name">%s</span>`, name)
	for _, t := range tabs {
		on := ""
		if t.key == cur {
			on = ` class="on"`
		}
		count := ""
		if t.count != "" {
			count = `<i>` + esc(t.count) + `</i>`
		}
		fmt.Fprintf(b, `<button%s data-tab="%s:%s">%s%s</button>`, on, side, t.key, t.label, count)
	}
	b.WriteString(`</nav><div class="pane-body">`)
	defer b.WriteString(`</div></section>`)

	if side == "res" && s.Status == 0 && cur != "timing" && cur != "messages" {
		msg := "Waiting for the response…"
		if s.State == "error" {
			msg = "No response. " + s.Err
		} else if s.State == "paused" {
			msg = "Paused at a breakpoint."
		}
		fmt.Fprintf(b, `<p class="empty">%s</p>`, esc(msg))
		return
	}
	switch cur {
	case "headers":
		if side == "req" {
			fmt.Fprintf(b, `<div class="firstline">%s %s %s</div>`, esc(s.Method), esc(s.Path), esc(s.Proto))
			kvTable(b, headerRows(s.ReqHeader))
		} else {
			fmt.Fprintf(b, `<div class="firstline">%s %d %s</div>`, esc(s.ResProto), s.Status, esc(s.StatusText))
			kvTable(b, headerRows(s.ResHeader))
			if len(s.ResTrailer) > 0 {
				b.WriteString(`<div class="firstline">Trailers</div>`)
				kvTable(b, headerRows(s.ResTrailer))
			}
		}
	case "query":
		rows := orderedQuery(strings.SplitN(s.Path+"?", "?", 2)[1])
		if len(rows) == 0 {
			b.WriteString(`<p class="empty">No query parameters</p>`)
		} else {
			kvTable(b, rows)
		}
	case "cookies":
		renderCookies(b, s, side)
	case "body":
		renderBody(b, s, side, mode)
	case "raw":
		fmt.Fprintf(b, `<div class="bodybar"><span class="grow"></span><button class="ib" data-copy-target="#raw-%s">Copy</button></div><pre class="code wrap" id="raw-%s">%s</pre>`, side, side, esc(rawMessage(s, side)))
	case "overview":
		rows := [][2]string{{"URL", s.url}, {"Status", dash(strings.TrimSpace(strconv.Itoa(s.Status) + " " + s.StatusText))},
			{"Protocol", protocols(s.Proto, s.ResProto)}, {"App", dash(s.App)}, {"Client", dash(s.Client)}, {"Server", dash(s.Server)},
			{"Started", s.Start.Format("2006-01-02 15:04:05.000")}, {"Duration", fmtDur(s.dur)},
			{"Request size", fmtSize(s.ReqSize)}, {"Response size", fmtSize(s.ResSize)}}
		if len(s.Tags) > 0 {
			rows = append(rows, [2]string{"Tags", strings.Join(s.Tags, ", ")})
		}
		if s.MappedFrom != "" {
			rows = append(rows, [2]string{"Mapped from", s.MappedFrom})
		}
		kvTable(b, rows)
	case "timing":
		renderTiming(b, s)
	case "messages":
		renderMessages(b, s)
	}
}

func orderedQuery(q string) [][2]string {
	var rows [][2]string
	for _, part := range strings.Split(q, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		ku, err1 := url.QueryUnescape(k)
		vu, err2 := url.QueryUnescape(v)
		if err1 != nil {
			ku = k
		}
		if err2 != nil {
			vu = v
		}
		rows = append(rows, [2]string{ku, vu})
	}
	return rows
}

func renderCookies(b *strings.Builder, s *snapshot, side string) {
	if side == "req" {
		var rows [][2]string
		for _, c := range (&http.Request{Header: s.ReqHeader}).Cookies() {
			rows = append(rows, [2]string{c.Name, c.Value})
		}
		if len(rows) == 0 {
			b.WriteString(`<p class="empty">No cookies sent</p>`)
			return
		}
		kvTable(b, rows)
		return
	}
	cookies := (&http.Response{Header: s.ResHeader}).Cookies()
	if len(cookies) == 0 {
		b.WriteString(`<p class="empty">No cookies set</p>`)
		return
	}
	b.WriteString(`<table class="kv"><tr><th>Name</th><td class="hd">Value</td><td class="hd">Attributes</td></tr>`)
	for _, c := range cookies {
		raw := c.String()
		attrs := ""
		if i := strings.Index(raw, "; "); i >= 0 {
			attrs = raw[i+2:]
		}
		fmt.Fprintf(b, `<tr><th>%s</th><td data-copy="%s">%s</td><td class="muted">%s</td></tr>`, esc(c.Name), esc(c.Value), esc(c.Value), esc(attrs))
	}
	b.WriteString(`</table>`)
}

// ---------------------------------------------------------------- bodies

var modeLabels = map[string]string{"tree": "Tree", "pretty": "Pretty", "form": "Form", "multipart": "Multipart",
	"graphql": "GraphQL", "preview": "Preview", "text": "Text", "hex": "Hex"}

func bodyModes(data []byte, ctype, side, path string) []string {
	if len(data) == 0 {
		return nil
	}
	ct := strings.ToLower(ctype)
	bin := isBinary(data)
	var modes []string
	trimmed := bytes.TrimSpace(data)
	looksJSON := !bin && (strings.Contains(ct, "json") || (len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')))
	switch {
	case looksJSON && json.Valid(trimmed):
		if side == "req" && (strings.Contains(strings.ToLower(path), "graphql") || bytes.Contains(trimmed[:min(len(trimmed), 200)], []byte(`"query"`))) {
			modes = append(modes, "graphql")
		}
		if len(data) <= treeLimit {
			modes = append(modes, "tree")
		}
		modes = append(modes, "pretty")
	case strings.Contains(ct, "x-www-form-urlencoded") && !bin:
		modes = append(modes, "form")
	case strings.Contains(ct, "multipart/form-data"):
		modes = append(modes, "multipart")
	case !bin && (strings.Contains(ct, "xml") || strings.Contains(ct, "html") || strings.Contains(ct, "svg")):
		modes = append(modes, "pretty")
	}
	if strings.HasPrefix(ct, "image/") || strings.HasPrefix(ct, "video/") || strings.HasPrefix(ct, "audio/") || strings.Contains(ct, "html") || strings.Contains(ct, "pdf") {
		modes = append(modes, "preview")
	}
	if !bin {
		modes = append(modes, "text")
	}
	return append(modes, "hex")
}

func renderBody(b *strings.Builder, s *snapshot, side, mode string) {
	data, ctype := s.body(side)
	modes := bodyModes(data, ctype, side, s.Path)
	if len(modes) == 0 {
		b.WriteString(`<p class="empty">No body</p>`)
		return
	}
	if !contains(modes, mode) {
		mode = modes[0]
	}
	id := strconv.FormatInt(s.ID, 10)
	b.WriteString(`<div class="bodybar"><div class="seg">`)
	for _, m := range modes {
		on := ""
		if m == mode {
			on = ` class="on"`
		}
		fmt.Fprintf(b, `<button%s data-mode="%s:%s">%s</button>`, on, side, m, modeLabels[m])
	}
	info := []string{fmtSize(int64(len(data)))}
	size, trunc, hdr := s.ReqSize, s.ReqTrunc, s.ReqHeader
	if side == "res" {
		size, trunc, hdr = s.ResSize, s.ResTrunc, s.ResHeader
	}
	if enc := hdr.Get("Content-Encoding"); enc != "" && !s.Decoded {
		info = append(info, enc+", "+fmtSize(size)+" transferred")
	}
	if trunc {
		info = append(info, "first "+fmtSize(int64(len(data)))+" of "+fmtSize(size)+" kept")
	}
	if ctype != "" {
		info = append(info, strings.Split(ctype, ";")[0])
	}
	fmt.Fprintf(b, `</div><span class="muted">%s</span><span class="grow"></span>`, esc(strings.Join(info, " · ")))
	fmt.Fprintf(b, `<button class="ib" data-copy-url="/api/flows/%s/body/%s">Copy</button><a class="ib" href="/api/flows/%s/body/%s?download=1">Save</a></div>`, id, side, id, side)

	ct := strings.ToLower(ctype)
	src := "/api/flows/" + id + "/body/" + side
	switch mode {
	case "tree":
		if t, ok := jsonTree(data); ok {
			b.WriteString(`<div class="tree">` + t + `</div>`)
			return
		}
		fallthrough
	case "pretty":
		if len(data) > prettyLimit {
			plain(b, data)
			return
		}
		var out bytes.Buffer
		if json.Indent(&out, bytes.TrimSpace(data), "", "  ") == nil {
			b.WriteString(`<pre class="code">` + highlightJSON(out.Bytes()) + `</pre>`)
		} else {
			b.WriteString(`<pre class="code wrap">` + highlightMarkup(string(data)) + `</pre>`)
		}
	case "form":
		kvTable(b, orderedQuery(string(data)))
	case "multipart":
		renderMultipart(b, data, ctype)
	case "graphql":
		renderGraphQL(b, data)
	case "preview":
		switch {
		case strings.HasPrefix(ct, "image/"):
			fmt.Fprintf(b, `<div class="preview checker"><img src="%s" alt=""></div>`, src)
		case strings.HasPrefix(ct, "video/"):
			fmt.Fprintf(b, `<div class="preview"><video controls src="%s"></video></div>`, src)
		case strings.HasPrefix(ct, "audio/"):
			fmt.Fprintf(b, `<div class="preview"><audio controls src="%s"></audio></div>`, src)
		default:
			fmt.Fprintf(b, `<iframe class="frame" sandbox src="%s?view=1"></iframe>`, src)
		}
	case "hex":
		n := min(len(data), hexLimit)
		b.WriteString(`<pre class="code">` + esc(hexDump(data[:n])) + `</pre>`)
		if n < len(data) {
			fmt.Fprintf(b, `<p class="muted">Showing the first %s of %s.</p>`, fmtSize(int64(n)), fmtSize(int64(len(data))))
		}
	default:
		plain(b, data)
	}
}

func plain(b *strings.Builder, data []byte) {
	n := min(len(data), textLimit)
	b.WriteString(`<pre class="code wrap">` + esc(string(data[:n])) + `</pre>`)
	if n < len(data) {
		b.WriteString(`<p class="muted">Truncated. Use Save to get the whole body.</p>`)
	}
}

func renderMultipart(b *strings.Builder, data []byte, ctype string) {
	_, params, err := mime.ParseMediaType(ctype)
	if err != nil || params["boundary"] == "" {
		plain(b, data)
		return
	}
	r := multipart.NewReader(bytes.NewReader(data), params["boundary"])
	var rows [][2]string
	for {
		part, err := r.NextPart()
		if err != nil {
			break
		}
		v, _ := io.ReadAll(io.LimitReader(part, 64<<10))
		name := part.FormName()
		if fn := part.FileName(); fn != "" {
			name += " (file: " + fn + ")"
		}
		val := string(v)
		if isBinary(v) {
			val = "binary, " + fmtSize(int64(len(v)))
		}
		rows = append(rows, [2]string{name, val})
	}
	if len(rows) == 0 {
		plain(b, data)
		return
	}
	kvTable(b, rows)
}

func renderGraphQL(b *strings.Builder, data []byte) {
	type op struct {
		OperationName string          `json:"operationName"`
		Query         string          `json:"query"`
		Variables     json.RawMessage `json:"variables"`
	}
	var ops []op
	if json.Unmarshal(data, &ops) != nil {
		var one op
		if json.Unmarshal(data, &one) != nil {
			plain(b, data)
			return
		}
		ops = []op{one}
	}
	for _, o := range ops {
		name := o.OperationName
		if name == "" {
			name = "Anonymous operation"
		}
		fmt.Fprintf(b, `<h3 class="ph">%s</h3>`, esc(name))
		if o.Query != "" {
			b.WriteString(`<pre class="code">` + esc(strings.TrimSpace(o.Query)) + `</pre>`)
		}
		if len(o.Variables) > 0 && string(o.Variables) != "null" {
			var out bytes.Buffer
			if json.Indent(&out, o.Variables, "", "  ") == nil {
				b.WriteString(`<div class="firstline">Variables</div><pre class="code">` + highlightJSON(out.Bytes()) + `</pre>`)
			}
		}
	}
}

// highlightJSON colours keys, strings, numbers and literals of already-indented JSON.
func highlightJSON(src []byte) string {
	var b strings.Builder
	b.Grow(len(src) * 2)
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == '"':
			j := i + 1
			for j < len(src) && src[j] != '"' {
				if src[j] == '\\' {
					j++
				}
				j++
			}
			j = min(j+1, len(src))
			k := j
			for k < len(src) && (src[k] == ' ' || src[k] == '\t') {
				k++
			}
			cls := "s"
			if k < len(src) && src[k] == ':' {
				cls = "k"
			}
			b.WriteString(`<span class="` + cls + `">` + esc(string(src[i:j])) + `</span>`)
			i = j
		case c == '-' || (c >= '0' && c <= '9'):
			j := i + 1
			for j < len(src) && strings.IndexByte("0123456789.eE+-", src[j]) >= 0 {
				j++
			}
			b.WriteString(`<span class="n">` + string(src[i:j]) + `</span>`)
			i = j
		case bytes.HasPrefix(src[i:], []byte("true")), bytes.HasPrefix(src[i:], []byte("false")), bytes.HasPrefix(src[i:], []byte("null")):
			n := 4
			if src[i] == 'f' {
				n = 5
			}
			b.WriteString(`<span class="l">` + string(src[i:i+n]) + `</span>`)
			i += n
		default:
			b.WriteString(esc(string(c)))
			i++
		}
	}
	return b.String()
}

var tagRx = regexp.MustCompile(`(?s)(<!--.*?-->)|(</?)([\w:.-]+)((?:\s+[^\s=>/]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?)*)\s*(/?>)`)
var attrRx = regexp.MustCompile(`([^\s=]+)(\s*=\s*)("[^"]*"|'[^']*'|[^\s>]+)?`)

func highlightMarkup(src string) string {
	if len(src) > prettyLimit {
		return esc(src)
	}
	var b strings.Builder
	last := 0
	for _, m := range tagRx.FindAllStringSubmatchIndex(src, -1) {
		b.WriteString(esc(src[last:m[0]]))
		if m[2] >= 0 {
			b.WriteString(`<span class="c">` + esc(src[m[2]:m[3]]) + `</span>`)
		} else {
			b.WriteString(`<span class="t">` + esc(src[m[4]:m[5]]+src[m[6]:m[7]]) + `</span>`)
			attrs := src[m[8]:m[9]]
			al := 0
			for _, a := range attrRx.FindAllStringSubmatchIndex(attrs, -1) {
				b.WriteString(esc(attrs[al:a[0]]))
				b.WriteString(`<span class="k">` + esc(attrs[a[2]:a[3]]) + `</span>`)
				if a[4] >= 0 {
					b.WriteString(esc(attrs[a[4]:a[5]]))
				}
				if a[6] >= 0 {
					b.WriteString(`<span class="s">` + esc(attrs[a[6]:a[7]]) + `</span>`)
				}
				al = a[1]
			}
			b.WriteString(esc(attrs[al:]))
			b.WriteString(`<span class="t">` + esc(src[m[10]:m[11]]) + `</span>`)
		}
		last = m[1]
	}
	b.WriteString(esc(src[last:]))
	return b.String()
}

// jsonTree renders JSON as nested <details> elements (collapsible without any script),
// keeping key order.
func jsonTree(data []byte) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	nodes := 0
	out, err := treeNode(dec, "", false, 0, &nodes)
	return out, err == nil
}

func treeNode(dec *json.Decoder, key string, hasKey bool, depth int, nodes *int) (string, error) {
	*nodes++
	if *nodes > 30000 {
		return "", fmt.Errorf("too large")
	}
	tok, err := dec.Token()
	if err != nil {
		return "", err
	}
	label := ""
	if hasKey {
		label = `<span class="k">` + esc(key) + `</span>: `
	}
	switch t := tok.(type) {
	case json.Delim:
		obj := t == '{'
		open, closer := "[", "]"
		if obj {
			open, closer = "{", "}"
		}
		var kids strings.Builder
		n := 0
		for dec.More() {
			k := strconv.Itoa(n)
			if obj {
				kt, err := dec.Token()
				if err != nil {
					return "", err
				}
				k, _ = kt.(string)
			}
			child, err := treeNode(dec, k, true, depth+1, nodes)
			if err != nil {
				return "", err
			}
			kids.WriteString(child)
			n++
		}
		if _, err := dec.Token(); err != nil {
			return "", err
		}
		if n == 0 {
			return `<div class="leaf">` + label + open + closer + `</div>`, nil
		}
		unit := "items"
		if obj {
			unit = "keys"
		}
		attr := ""
		if depth < 2 && n <= 200 {
			attr = " open"
		}
		return fmt.Sprintf(`<details%s><summary>%s%s<span class="sum"> %d %s %s</span></summary><div class="kids">%s</div><div class="leaf">%s</div></details>`,
			attr, label, open, n, unit, closer, kids.String(), closer), nil
	case string:
		v := t
		if len(v) > 5000 {
			v = v[:5000] + "…"
		}
		q, _ := json.Marshal(v)
		return `<div class="leaf">` + label + `<span class="s">` + esc(string(q)) + `</span></div>`, nil
	case json.Number:
		return `<div class="leaf">` + label + `<span class="n">` + esc(t.String()) + `</span></div>`, nil
	case bool:
		return `<div class="leaf">` + label + `<span class="l">` + strconv.FormatBool(t) + `</span></div>`, nil
	default:
		return `<div class="leaf">` + label + `<span class="l">null</span></div>`, nil
	}
}

func hexDump(data []byte) string {
	var b strings.Builder
	for off := 0; off < len(data); off += 16 {
		chunk := data[off:min(off+16, len(data))]
		fmt.Fprintf(&b, "%08x  ", off)
		for i := range 16 {
			if i < len(chunk) {
				fmt.Fprintf(&b, "%02x ", chunk[i])
			} else {
				b.WriteString("   ")
			}
			if i == 7 {
				b.WriteByte(' ')
			}
		}
		b.WriteString(" ")
		for _, c := range chunk {
			if c >= 32 && c < 127 {
				b.WriteByte(c)
			} else {
				b.WriteByte('.')
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func rawMessage(s *snapshot, side string) string {
	var b strings.Builder
	var data []byte
	if side == "req" {
		fmt.Fprintf(&b, "%s %s %s\n", s.Method, s.Path, s.Proto)
		for _, r := range headerRows(s.ReqHeader) {
			b.WriteString(r[0] + ": " + r[1] + "\n")
		}
		data, _ = s.body("req")
	} else {
		if s.Status == 0 {
			return ""
		}
		fmt.Fprintf(&b, "%s %d %s\n", s.ResProto, s.Status, s.StatusText)
		for _, r := range headerRows(s.ResHeader) {
			b.WriteString(r[0] + ": " + r[1] + "\n")
		}
		data, _ = s.body("res")
	}
	switch {
	case len(data) == 0:
	case isBinary(data):
		b.WriteString("\n(binary body, " + fmtSize(int64(len(data))) + ")")
	default:
		n := min(len(data), 256<<10)
		b.WriteString("\n" + string(data[:n]))
		if n < len(data) {
			b.WriteString("\n…")
		}
	}
	return b.String()
}

func renderTiming(b *strings.Builder, s *snapshot) {
	t := s.Timing
	phases := []struct {
		label string
		d     time.Duration
		cls   string
	}{
		{"DNS lookup", t.DNS, "dns"}, {"TCP connect", t.Connect, "tcp"}, {"TLS handshake", t.TLS, "tls"},
		{"Request sent", t.Send, "send"}, {"Waiting (TTFB)", t.Wait, "wait"}, {"Download", t.Receive, "recv"},
	}
	var total time.Duration
	for _, p := range phases {
		total += p.d
	}
	if total == 0 {
		b.WriteString(`<p class="empty">No timing information.</p>`)
		return
	}
	b.WriteString(`<div class="timing">`)
	var offset time.Duration
	for _, p := range phases {
		if p.d == 0 {
			continue
		}
		left := float64(offset) / float64(total) * 100
		width := max(float64(p.d)/float64(total)*100, 0.5)
		fmt.Fprintf(b, `<div class="tr"><span>%s</span><span class="track"><i class="%s" style="margin-left:%.2f%%;width:%.2f%%"></i></span><span class="tv">%s</span></div>`,
			p.label, p.cls, left, width, fmtDur(p.d))
		offset += p.d
	}
	fmt.Fprintf(b, `<div class="tr total"><span>Total</span><span></span><span class="tv">%s</span></div></div>`, fmtDur(s.dur))
	if t.Reused {
		b.WriteString(`<p class="muted">Reused an existing connection to the server.</p>`)
	}
}

func renderMessages(b *strings.Builder, s *snapshot) {
	msgs := s.WS
	if len(msgs) == 0 {
		b.WriteString(`<p class="empty">No messages yet.</p>`)
		return
	}
	if s.WSCount > len(msgs) {
		fmt.Fprintf(b, `<p class="muted">Showing the latest %d of %d messages.</p>`, len(msgs), s.WSCount)
	}
	b.WriteString(`<div class="msgs">`)
	shown := 0
	for i := len(msgs) - 1; i >= 0 && shown < 500; i-- {
		m := msgs[i]
		shown++
		dir, cls := "↓", "in"
		if m.Out {
			dir, cls = "↑", "out"
		}
		bin := m.Op == 2 || isBinary(m.Data)
		preview := string(m.Data[:min(len(m.Data), 200)])
		if bin {
			preview = "binary " + fmtSize(int64(m.Size))
		}
		fmt.Fprintf(b, `<details class="msg %s"><summary><span class="dir">%s</span><span class="op">%s</span><span class="pv">%s</span><span class="muted">%s</span><span class="muted">%s</span></summary>`,
			cls, dir, wsOpName(m.Op), esc(preview), fmtSize(int64(m.Size)), m.Time.Format("15:04:05.000"))
		var out bytes.Buffer
		switch {
		case bin:
			b.WriteString(`<pre class="code">` + esc(hexDump(m.Data[:min(len(m.Data), 4096)])) + `</pre>`)
		case json.Indent(&out, bytes.TrimSpace(m.Data), "", "  ") == nil:
			b.WriteString(`<pre class="code">` + highlightJSON(out.Bytes()) + `</pre>`)
		default:
			b.WriteString(`<pre class="code wrap">` + esc(string(m.Data)) + `</pre>`)
		}
		b.WriteString(`</details>`)
	}
	b.WriteString(`</div>`)
}

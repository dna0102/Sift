package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// HAR 1.2 types (only the fields Sift writes/reads).
type harNV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type harPost struct {
	MimeType string  `json:"mimeType"`
	Text     string  `json:"text"`
	Encoding string  `json:"_encoding,omitempty"`
	Params   []harNV `json:"params,omitempty"`
}
type harContent struct {
	Size        int64  `json:"size"`
	Compression int64  `json:"compression,omitempty"`
	MimeType    string `json:"mimeType"`
	Text        string `json:"text,omitempty"`
	Encoding    string `json:"encoding,omitempty"`
}
type harRequest struct {
	Method      string   `json:"method"`
	URL         string   `json:"url"`
	HTTPVersion string   `json:"httpVersion"`
	Cookies     []harNV  `json:"cookies"`
	Headers     []harNV  `json:"headers"`
	QueryString []harNV  `json:"queryString"`
	PostData    *harPost `json:"postData,omitempty"`
	HeadersSize int      `json:"headersSize"`
	BodySize    int64    `json:"bodySize"`
}
type harResponse struct {
	Status      int        `json:"status"`
	StatusText  string     `json:"statusText"`
	HTTPVersion string     `json:"httpVersion"`
	Cookies     []harNV    `json:"cookies"`
	Headers     []harNV    `json:"headers"`
	Content     harContent `json:"content"`
	RedirectURL string     `json:"redirectURL"`
	HeadersSize int        `json:"headersSize"`
	BodySize    int64      `json:"bodySize"`
	Error       string     `json:"_error,omitempty"`
}
type harTimings struct {
	Blocked float64 `json:"blocked"`
	DNS     float64 `json:"dns"`
	Connect float64 `json:"connect"`
	SSL     float64 `json:"ssl"`
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}
type harWS struct {
	Type   string  `json:"type"`
	Time   float64 `json:"time"`
	Opcode int     `json:"opcode"`
	Data   string  `json:"data"`
}
type harEntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            float64     `json:"time"`
	Request         harRequest  `json:"request"`
	Response        harResponse `json:"response"`
	Cache           struct{}    `json:"cache"`
	Timings         harTimings  `json:"timings"`
	ServerIP        string      `json:"serverIPAddress,omitempty"`
	ResourceType    string      `json:"_resourceType,omitempty"`
	WSMessages      []harWS     `json:"_webSocketMessages,omitempty"`
}

func harHeaders(h http.Header) []harNV {
	out := []harNV{}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			out = append(out, harNV{k, v})
		}
	}
	return out
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// bodyText returns a body as text, or base64 for binary data.
func bodyText(b []byte) (string, string) {
	if len(b) == 0 {
		return "", ""
	}
	if !isBinary(b) && utf8.Valid(b) {
		return string(b), ""
	}
	return base64.StdEncoding.EncodeToString(b), "base64"
}

func harEntryFor(f *Flow) harEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.URL()
	e := harEntry{StartedDateTime: f.Start.UTC().Format(time.RFC3339Nano)}
	if !f.End.IsZero() {
		e.Time = ms(f.End.Sub(f.Start))
	}
	if f.Kind == "ws" {
		e.ResourceType = "websocket"
		for _, m := range f.WS {
			typ := "receive"
			if m.Out {
				typ = "send"
			}
			text, _ := bodyText(m.Data)
			e.WSMessages = append(e.WSMessages, harWS{typ, float64(m.Time.UnixMicro()) / 1e6, int(m.Op), text})
		}
	}
	reqHdr := f.ReqHeader
	if reqHdr == nil {
		reqHdr = http.Header{}
	}
	e.Request = harRequest{Method: f.Method, URL: u, HTTPVersion: f.Proto, Cookies: []harNV{}, Headers: harHeaders(reqHdr),
		QueryString: []harNV{}, HeadersSize: -1, BodySize: f.ReqSize}
	if pu, err := url.Parse(u); err == nil {
		for k, vs := range pu.Query() {
			for _, v := range vs {
				e.Request.QueryString = append(e.Request.QueryString, harNV{k, v})
			}
		}
	}
	for _, c := range (&http.Request{Header: reqHdr}).Cookies() {
		e.Request.Cookies = append(e.Request.Cookies, harNV{c.Name, c.Value})
	}
	if len(f.ReqBody) > 0 {
		text, enc := bodyText(f.ReqBody)
		e.Request.PostData = &harPost{MimeType: reqHdr.Get("Content-Type"), Text: text, Encoding: enc}
	}
	e.Response = harResponse{Status: f.Status, StatusText: f.StatusText, HTTPVersion: f.ResProto, Cookies: []harNV{},
		Headers: []harNV{}, HeadersSize: -1, BodySize: f.ResSize, Error: f.Err}
	if f.ResHeader != nil {
		e.Response.Headers = harHeaders(f.ResHeader)
		e.Response.RedirectURL = f.ResHeader.Get("Location")
		for _, c := range (&http.Response{Header: f.ResHeader}).Cookies() {
			e.Response.Cookies = append(e.Response.Cookies, harNV{c.Name, c.Value})
		}
		body := f.ResBody
		if !f.Decoded {
			body, _ = decodeBody(body, f.ResHeader.Get("Content-Encoding"))
		}
		text, enc := bodyText(body)
		e.Response.Content = harContent{Size: int64(len(body)), MimeType: f.ResHeader.Get("Content-Type"), Text: text, Encoding: enc}
		if c := int64(len(body)) - f.ResSize; c > 0 {
			e.Response.Content.Compression = c
		}
	}
	t := f.Timing
	e.Timings = harTimings{Blocked: -1, DNS: ms(t.DNS), Connect: ms(t.Connect + t.TLS), SSL: ms(t.TLS), Send: ms(t.Send), Wait: ms(t.Wait), Receive: ms(t.Receive)}
	if t.Reused {
		e.Timings.DNS, e.Timings.Connect, e.Timings.SSL = -1, -1, -1
	}
	if host, _, ok := strings.Cut(f.Server, ":"); ok {
		e.ServerIP = strings.Trim(host, "[]")
	}
	return e
}

// WriteHAR streams a HAR file entry by entry, so exporting thousands of requests uses
// almost no extra memory.
func WriteHAR(w io.Writer, flows []*Flow) error {
	bw := bufio.NewWriterSize(w, 256<<10)
	bw.WriteString(`{"log":{"version":"1.2","creator":{"name":"Sift","version":"` + Version + `"},"pages":[],"entries":[`)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	first := true
	for _, f := range flows {
		if f.Kind == "tunnel" || f.Kind == "tls" {
			continue
		}
		if !first {
			bw.WriteByte(',')
		}
		first = false
		if err := enc.Encode(harEntryFor(f)); err != nil {
			return err
		}
	}
	bw.WriteString("]}}\n")
	return bw.Flush()
}

// ReadHAR turns a HAR file (from Sift, browser DevTools, Proxyman, Charles…) into flows.
func ReadHAR(r io.Reader, maxBody int) ([]*Flow, error) {
	var doc struct {
		Log struct {
			Entries []harEntry `json:"entries"`
		} `json:"log"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, err
	}
	var out []*Flow
	for _, e := range doc.Log.Entries {
		u, err := url.Parse(e.Request.URL)
		if err != nil || u.Host == "" {
			continue
		}
		start, _ := time.Parse(time.RFC3339Nano, e.StartedDateTime)
		scheme := strings.ToLower(u.Scheme)
		host, port := splitHostPort(u.Host, defaultPort(scheme))
		f := &Flow{Kind: "http", Start: start, End: start.Add(time.Duration(e.Time * float64(time.Millisecond))), State: "done",
			Method: e.Request.Method, Scheme: scheme, Host: host, Port: port, Path: u.RequestURI(), Proto: e.Request.HTTPVersion,
			Status: e.Response.Status, StatusText: e.Response.StatusText, ResProto: e.Response.HTTPVersion,
			Tags: []string{"imported"}, Decoded: true, maxBody: maxBody, Err: e.Response.Error}
		if e.ResourceType == "websocket" || scheme == "ws" || scheme == "wss" {
			f.Kind = "ws"
			for _, m := range e.WSMessages {
				f.WS = append(f.WS, WSMessage{Out: m.Type == "send", Op: byte(m.Opcode), Time: time.UnixMicro(int64(m.Time * 1e6)), Size: len(m.Data), Data: []byte(m.Data)})
			}
			f.WSCount = len(f.WS)
		}
		f.ReqHeader = http.Header{}
		for _, h := range e.Request.Headers {
			if !strings.HasPrefix(h.Name, ":") {
				f.ReqHeader.Add(h.Name, h.Value)
			}
		}
		if f.ReqHeader.Get("Host") == "" {
			f.ReqHeader.Set("Host", u.Host)
		}
		if pd := e.Request.PostData; pd != nil {
			f.ReqBody = decodeHARText(pd.Text, pd.Encoding)
		}
		f.ReqSize = int64(len(f.ReqBody))
		f.ResHeader = http.Header{}
		for _, h := range e.Response.Headers {
			if !strings.HasPrefix(h.Name, ":") {
				f.ResHeader.Add(h.Name, h.Value)
			}
		}
		f.ResBody = decodeHARText(e.Response.Content.Text, e.Response.Content.Encoding)
		if len(f.ResBody) > maxBody {
			f.ResBody, f.ResTrunc = f.ResBody[:maxBody], true
		}
		f.ResSize = int64(len(f.ResBody))
		t := e.Timings
		f.Timing = Timing{DNS: harDur(t.DNS), Connect: harDur(t.Connect - max(t.SSL, 0)), TLS: harDur(t.SSL), Send: harDur(t.Send), Wait: harDur(t.Wait), Receive: harDur(t.Receive)}
		if e.ServerIP != "" {
			f.Server = e.ServerIP
		}
		out = append(out, f)
	}
	return out, nil
}

func harDur(v float64) time.Duration {
	if v <= 0 {
		return 0
	}
	return time.Duration(v * float64(time.Millisecond))
}

func decodeHARText(text, enc string) []byte {
	if enc == "base64" {
		if b, err := base64.StdEncoding.DecodeString(text); err == nil {
			return b
		}
	}
	return []byte(text)
}

// WritePostman writes a Postman v2.1 collection, one folder per host.
func WritePostman(w io.Writer, flows []*Flow) error {
	type kv struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	type item struct {
		Name    string `json:"name"`
		Request any    `json:"request"`
	}
	folders := map[string][]item{}
	var order []string
	for _, f := range flows {
		if f.Kind != "http" {
			continue
		}
		f.mu.Lock()
		u, _ := url.Parse(f.URL())
		var hdrs []kv
		for _, h := range harHeaders(f.ReqHeader) {
			if k := strings.ToLower(h.Name); k != "host" && k != "content-length" && k != "connection" {
				hdrs = append(hdrs, kv{h.Name, h.Value})
			}
		}
		req := map[string]any{"method": f.Method, "header": hdrs, "url": map[string]any{
			"raw": f.URL(), "protocol": u.Scheme, "host": strings.Split(u.Hostname(), "."), "port": u.Port(),
			"path": strings.Split(strings.Trim(u.Path, "/"), "/"), "query": queryKV(u),
		}}
		if len(f.ReqBody) > 0 && !isBinary(f.ReqBody) {
			req["body"] = map[string]any{"mode": "raw", "raw": string(f.ReqBody)}
		}
		name := f.Method + " " + u.Path
		host := f.Host
		f.mu.Unlock()
		if _, ok := folders[host]; !ok {
			order = append(order, host)
		}
		folders[host] = append(folders[host], item{name, req})
	}
	var items []any
	for _, h := range order {
		items = append(items, map[string]any{"name": h, "item": folders[h]})
	}
	doc := map[string]any{
		"info": map[string]any{"name": "Sift export " + time.Now().Format("2006-01-02 15:04"),
			"schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
		"item": items,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	return enc.Encode(doc)
}

func queryKV(u *url.URL) []map[string]string {
	out := []map[string]string{}
	for k, vs := range u.Query() {
		for _, v := range vs {
			out = append(out, map[string]string{"key": k, "value": v})
		}
	}
	return out
}

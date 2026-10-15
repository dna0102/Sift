package sender

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"sift/internal/core"
)

type ProbeReq struct {
	Method  string
	URL     string
	Header  http.Header
	Body    []byte
	Route   string
	Profile string
	Tag     string
}

type ProbeRes struct {
	Status   int
	Header   http.Header
	Body     []byte
	Proto    string
	Duration int64
	FlowID   int64
	Err      string
}

func (s *Sender) Probe(ctx context.Context, in ProbeReq) (*ProbeRes, error) {
	u, err := url.Parse(in.URL)
	if err != nil || u.Host == "" {
		return nil, errors.New("invalid target URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, errors.New("target must be http or https")
	}
	host, port := core.SplitHostPort(u.Host, core.DefaultPort(scheme))

	header := in.Header.Clone()
	if header == nil {
		header = http.Header{}
	}
	p := &parsedRaw{Method: strings.ToUpper(in.Method), Path: u.RequestURI(), Proto: "HTTP/1.1", Header: header}
	if p.Method == "" {
		p.Method = "GET"
	}
	for k := range header {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") {
			continue
		}
		p.Order = append(p.Order, k)
	}
	p.Body = in.Body

	rt := s.route(in.Route).withProfile(in.Profile)
	hostHeader := header.Get("Host")
	if hostHeader == "" {
		hostHeader = core.HostPort(host, port, scheme)
	}
	clen := int64(len(in.Body))
	maxBody := s.cfg.Get().MaxBody()

	tag := in.Tag
	if tag == "" {
		tag = "scan"
	}
	f := &core.Flow{Kind: "http", Start: time.Now(), State: "pending", Method: p.Method, Scheme: scheme,
		Host: host, Port: port, Path: p.Path, Proto: p.Proto, App: "Sift", Tags: []string{"scan", tag},
		ReqHeader: header.Clone(), MaxBody: maxBody}
	f.ReqHeader.Set("Host", hostHeader)
	f.ReqBody, f.ReqSize = in.Body[:min(len(in.Body), maxBody)], clen
	f.ReqTrunc = len(in.Body) > maxBody
	s.store.Add(f)

	target := scheme + "://" + core.HostPort(host, port, scheme) + p.Path
	call := &outgoing{route: rt, parsed: p, target: target, host: hostHeader, clen: clen, flow: f}

	start := time.Now()
	var res *rawResponse
	if rt.Profile != "" {
		res, err = s.doImpersonate(ctx, call)
	} else {
		res, err = s.doStdlib(ctx, call)
	}
	dur := time.Since(start).Milliseconds()
	out := &ProbeRes{Duration: dur, FlowID: f.ID}
	if err != nil {
		msg := s.explain(err, rt, host, port)
		out.Err = msg
		f.Fail(msg)
		f.Lock()
		f.End = time.Now()
		f.Unlock()
		s.store.Finished(f)
		return out, nil
	}

	decoded := res.Body
	if encd := res.Header.Get("Content-Encoding"); encd != "" {
		if d, ok := core.DecodeBody(res.Body, encd); ok {
			decoded = d
		}
	}
	if res.ReadErr != nil && !errors.Is(res.ReadErr, io.EOF) {
		out.Err = "response truncated: " + res.ReadErr.Error()
	}
	out.Status, out.Header, out.Body, out.Proto = res.Status, res.Header, decoded, res.Proto

	f.Lock()
	f.Status, f.StatusText, f.ResProto = res.Status, http.StatusText(res.Status), res.Proto
	f.ResHeader = res.Header.Clone()
	f.ResBody = decoded[:min(len(decoded), maxBody)]
	f.ResSize, f.ResTrunc, f.Decoded = int64(len(res.Body)), len(decoded) > maxBody, true
	f.ResHeader.Del("Content-Encoding")
	f.End, f.State = time.Now(), "done"
	f.Unlock()
	s.store.Finished(f)
	return out, nil
}

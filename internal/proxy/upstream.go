package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"sift/internal/core"
)

type Upstream struct {
	cfg      *core.Config
	dialer   *net.Dialer
	secure   *http.Transport
	insecure *http.Transport
	h2c      *http.Transport
}

type ctxH2C struct{}

func NewUpstream(cfg *core.Config) *Upstream {
	u := &Upstream{cfg: cfg, dialer: &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}}
	u.secure = u.transport(false)
	u.insecure = u.transport(true)
	u.h2c = &http.Transport{Proxy: nil, DialContext: u.dialer.DialContext, DisableCompression: true, Protocols: new(http.Protocols)}
	u.h2c.Protocols.SetUnencryptedHTTP2(true)
	return u
}

func (u *Upstream) transport(insecure bool) *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           u.dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1024,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
		ReadBufferSize:        64 << 10,
		WriteBufferSize:       64 << 10,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure, MinVersion: tls.VersionTLS10,
			CipherSuites: AllCipherSuites(), ClientSessionCache: tls.NewLRUClientSessionCache(1024)},
	}
}

func (u *Upstream) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "http" && req.Context().Value(ctxH2C{}) != nil {
		return u.h2c.RoundTrip(req)
	}
	if u.cfg.Get().VerifyUpstream {
		return u.secure.RoundTrip(req)
	}
	return u.insecure.RoundTrip(req)
}

func AllCipherSuites() []uint16 {
	var ids []uint16
	for _, c := range tls.CipherSuites() {
		ids = append(ids, c.ID)
	}
	for _, c := range tls.InsecureCipherSuites() {
		ids = append(ids, c.ID)
	}
	return ids
}

func (u *Upstream) dialTLS(ctx context.Context, addr, serverName string, alpn []string, verify bool) (net.Conn, error) {
	raw, err := u.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, &tls.Config{ServerName: serverName, NextProtos: alpn, InsecureSkipVerify: !verify,
		MinVersion: tls.VersionTLS10, CipherSuites: AllCipherSuites()})
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return tc, nil
}

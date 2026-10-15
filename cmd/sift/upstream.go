package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// Upstream sends requests to the real servers. Old TLS versions and ciphers are allowed so
// legacy servers and local devices (routers, printers, old intranet apps) still work; the
// strongest option both sides support is always chosen.
type Upstream struct {
	app      *App
	dialer   *net.Dialer
	secure   *http.Transport // verifies server certificates
	insecure *http.Transport // "Verify server certificates" off
	h2c      *http.Transport // HTTP/2 without TLS (prior knowledge), for h2c apps such as gRPC
}

type ctxH2C struct{} // set on requests that arrived as unencrypted HTTP/2

func NewUpstream(app *App) *Upstream {
	u := &Upstream{app: app, dialer: &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}}
	u.secure = u.transport(false)
	u.insecure = u.transport(true)
	u.h2c = &http.Transport{Proxy: nil, DialContext: u.dialer.DialContext, DisableCompression: true, Protocols: new(http.Protocols)}
	u.h2c.Protocols.SetUnencryptedHTTP2(true)
	return u
}

func (u *Upstream) transport(insecure bool) *http.Transport {
	return &http.Transport{
		Proxy:                 nil, // never loop back through the system proxy
		DialContext:           u.dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1024,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true, // pass bodies through exactly as sent
		ReadBufferSize:        64 << 10,
		WriteBufferSize:       64 << 10,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure, MinVersion: tls.VersionTLS10,
			CipherSuites: allCipherSuites(), ClientSessionCache: tls.NewLRUClientSessionCache(1024)},
	}
}

func (u *Upstream) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "http" && req.Context().Value(ctxH2C{}) != nil {
		return u.h2c.RoundTrip(req)
	}
	if u.app.cfg.Get().VerifyUpstream {
		return u.secure.RoundTrip(req)
	}
	return u.insecure.RoundTrip(req)
}

// allCipherSuites enables every cipher Go supports, including old ones that are off by
// default, so ancient servers and apps still work.
func allCipherSuites() []uint16 {
	var ids []uint16
	for _, c := range tls.CipherSuites() {
		ids = append(ids, c.ID)
	}
	for _, c := range tls.InsecureCipherSuites() {
		ids = append(ids, c.ID)
	}
	return ids
}

// dialTLS is used for WebSockets and raw TLS relays.
func (u *Upstream) dialTLS(ctx context.Context, addr, serverName string, alpn []string, verify bool) (net.Conn, error) {
	raw, err := u.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, &tls.Config{ServerName: serverName, NextProtos: alpn, InsecureSkipVerify: !verify,
		MinVersion: tls.VersionTLS10, CipherSuites: allCipherSuites()})
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return tc, nil
}

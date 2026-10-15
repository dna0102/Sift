package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func isWebSocket(r *http.Request) bool {
	return r.ProtoMajor == 1 && strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// handleWebSocket relays a WebSocket connection and records every message.
// Compression is switched off for the session (Sec-WebSocket-Extensions is dropped)
// so messages are readable.
func (p *Proxy) handleWebSocket(w http.ResponseWriter, r *http.Request, ci *connInfo, scheme, host string, port int, s *Settings) {
	secure := scheme == "https"
	f := &Flow{Kind: "ws", Start: time.Now(), State: "pending", Method: r.Method, Scheme: map[bool]string{true: "wss", false: "ws"}[secure],
		Host: host, Port: port, Path: r.URL.RequestURI(), Proto: r.Proto, Client: ci.client.addr, App: ci.client.App(), maxBody: s.MaxBody()}
	f.ReqHeader = r.Header.Clone()
	f.ReqHeader.Set("Host", r.Host)
	m := matchRules(s.Rules, f.Method, f.URL(), host, port)
	if s.Recording && !(m.AllowActive && !m.Allowed) {
		p.app.store.Add(f)
	}
	defer p.finish(f)
	if m.Block != nil {
		f.tag("blocked")
		f.mu.Lock()
		f.Status, f.StatusText = 403, "Forbidden"
		f.mu.Unlock()
		http.Error(w, "Blocked by Sift", http.StatusForbidden)
		return
	}
	if m.MapRemote != nil {
		f.mu.Lock()
		if applyMapRemote(f, m.MapRemote) {
			f.Tags = appendTag(f.Tags, "map remote")
		}
		host, port, secure = f.Host, f.Port, f.Scheme == "https" || f.Scheme == "wss"
		f.mu.Unlock()
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	up, err := p.dialer.DialContext(r.Context(), "tcp", addr)
	if err == nil && secure {
		tc := tls.Client(up, &tls.Config{ServerName: host, NextProtos: []string{"http/1.1"}, InsecureSkipVerify: !s.VerifyUpstream})
		if err = tc.HandshakeContext(r.Context()); err == nil {
			up = tc
		}
	}
	if err != nil {
		msg := describeErr(err, host, port)
		f.fail(msg)
		http.Error(w, "Sift: "+msg, http.StatusBadGateway)
		return
	}
	defer up.Close()
	f.mu.Lock()
	f.Server = up.RemoteAddr().String()
	hdr := f.ReqHeader.Clone()
	path := f.Path
	f.mu.Unlock()
	hostHeader := hdr.Get("Host")
	hdr.Del("Host")
	for _, k := range []string{"Proxy-Connection", "Proxy-Authorization", "Keep-Alive", "Sec-Websocket-Extensions"} {
		hdr.Del(k)
	}

	bw := bufio.NewWriter(up)
	fmt.Fprintf(bw, "%s %s HTTP/1.1\r\nHost: %s\r\n", r.Method, path, hostHeader)
	hdr.Write(bw)
	bw.WriteString("\r\n")
	if err := bw.Flush(); err != nil {
		f.fail("Couldn't send the WebSocket handshake: " + err.Error())
		http.Error(w, "Sift: "+err.Error(), http.StatusBadGateway)
		return
	}
	upReader := bufio.NewReaderSize(up, 64<<10)
	resp, err := http.ReadResponse(upReader, r)
	if err != nil {
		f.fail("The server didn't answer the WebSocket handshake: " + err.Error())
		http.Error(w, "Sift: "+err.Error(), http.StatusBadGateway)
		return
	}
	f.mu.Lock()
	f.Status, f.StatusText, f.ResProto, f.ResHeader = resp.StatusCode, http.StatusText(resp.StatusCode), resp.Proto, resp.Header.Clone()
	f.mu.Unlock()

	hj, ok := w.(http.Hijacker)
	if !ok {
		f.fail("WebSockets need HTTP/1.1")
		return
	}
	client, clientBuf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	head := bufio.NewWriter(client)
	fmt.Fprintf(head, "HTTP/1.1 %s\r\n", resp.Status)
	resp.Header.Write(head)
	head.WriteString("\r\n")
	if err := head.Flush(); err != nil {
		return
	}
	if resp.StatusCode != http.StatusSwitchingProtocols { // refused: pass the body through and stop
		b, _ := io.ReadAll(io.LimitReader(resp.Body, int64(f.maxBody)))
		f.capture(true, b)
		client.Write(b)
		return
	}

	f.mu.Lock()
	f.State = "open"
	f.mu.Unlock()
	p.app.store.Touch(f)

	toServer := &wsParser{onMsg: func(op byte, data []byte, size int) { p.wsMessage(f, true, op, data, size) }}
	toClient := &wsParser{onMsg: func(op byte, data []byte, size int) { p.wsMessage(f, false, op, data, size) }}
	done := make(chan struct{})
	go func() {
		relay(up, clientBuf.Reader, toServer)
		up.Close()
		client.Close()
		close(done)
	}()
	relay(client, upReader, toClient)
	up.Close()
	client.Close()
	<-done
}

func relay(dst io.Writer, src io.Reader, parser *wsParser) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			parser.feed(buf[:n])
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

const (
	wsKeep     = 5000       // messages kept per connection
	wsMaxStore = 256 << 10  // bytes kept per message
	wsMaxFrame = 64 << 20   // give up parsing beyond this
)

func (p *Proxy) wsMessage(f *Flow, out bool, op byte, data []byte, size int) {
	if len(data) > wsMaxStore {
		data = data[:wsMaxStore]
	}
	f.mu.Lock()
	f.WSCount++
	f.WS = append(f.WS, WSMessage{Out: out, Op: op, Time: time.Now(), Size: size, Data: append([]byte(nil), data...)})
	if len(f.WS) > wsKeep {
		f.WS = f.WS[len(f.WS)-wsKeep:]
	}
	if out {
		f.ReqSize += int64(size)
	} else {
		f.ResSize += int64(size)
	}
	f.mu.Unlock()
	p.app.store.Touch(f)
}

// wsParser splits a byte stream into WebSocket messages (unmasking client frames and
// joining fragments). It only observes; the bytes are forwarded unchanged.
type wsParser struct {
	buf    []byte
	frag   []byte
	fragOp byte
	dead   bool
	onMsg  func(op byte, data []byte, size int)
}

func (p *wsParser) feed(b []byte) {
	if p.dead {
		return
	}
	p.buf = append(p.buf, b...)
	for {
		buf := p.buf
		if len(buf) < 2 {
			return
		}
		fin := buf[0]&0x80 != 0
		op := buf[0] & 0x0f
		masked := buf[1]&0x80 != 0
		length := uint64(buf[1] & 0x7f)
		off := 2
		switch length {
		case 126:
			if len(buf) < 4 {
				return
			}
			length, off = uint64(binary.BigEndian.Uint16(buf[2:4])), 4
		case 127:
			if len(buf) < 10 {
				return
			}
			length, off = binary.BigEndian.Uint64(buf[2:10]), 10
		}
		if length > wsMaxFrame {
			p.dead, p.buf = true, nil
			return
		}
		var mask []byte
		if masked {
			if len(buf) < off+4 {
				return
			}
			mask = buf[off : off+4]
			off += 4
		}
		end := off + int(length)
		if len(buf) < end {
			return
		}
		payload := append([]byte(nil), buf[off:end]...)
		for i := range payload {
			if mask != nil {
				payload[i] ^= mask[i&3]
			}
		}
		p.buf = append(p.buf[:0], buf[end:]...)
		switch {
		case op >= 8: // control frames: close, ping, pong
			p.onMsg(op, payload, len(payload))
		case op == 0: // continuation
			p.frag = append(p.frag, payload...)
			if fin {
				p.onMsg(p.fragOp, p.frag, len(p.frag))
				p.frag = nil
			}
		case !fin:
			p.fragOp, p.frag = op, payload
		default:
			p.onMsg(op, payload, len(payload))
		}
	}
}

func wsOpName(op byte) string {
	switch op {
	case 1:
		return "text"
	case 2:
		return "binary"
	case 8:
		return "close"
	case 9:
		return "ping"
	case 10:
		return "pong"
	}
	return "op" + strconv.Itoa(int(op))
}

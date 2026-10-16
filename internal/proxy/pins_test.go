package proxy

import "testing"

func TestUntrustingClientIsNotPinning(t *testing.T) {
	p := NewPinTracker()
	p.Failed("a.com", true, true)
	p.Learned("emulator", "a.com")
	if d, _ := p.Rejected("emulator", "a.com"); d {
		t.Fatal("one host should not mark the client as distrusting")
	}
	p.Rejected("emulator", "b.com")
	d, unlearn := p.Rejected("emulator", "c.com")
	if !d || len(unlearn) != 1 || unlearn[0] != "a.com" {
		t.Fatalf("distrusts=%v unlearn=%v, want true [a.com]", d, unlearn)
	}
	if r := p.Reason("a.com"); r != untrustedPass {
		t.Errorf("a.com reason = %q, want %q", r, untrustedPass)
	}
	if !p.Succeeded("emulator") {
		t.Error("a success after distrust should report recovery")
	}
	p.ClearUntrusted()
	if p.Has("a.com") {
		t.Error("untrusted pass should be cleared once the client trusts Sift")
	}
}

func TestPinningAppWithWorkingHostsStaysPinning(t *testing.T) {
	p := NewPinTracker()
	p.Succeeded("app")
	for _, h := range []string{"a.com", "b.com", "c.com", "d.com"} {
		if d, _ := p.Rejected("app", h); d {
			t.Fatalf("%s: a client that completed a handshake recently is pinning, not distrusting", h)
		}
	}
}

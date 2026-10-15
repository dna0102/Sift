package sender

import (
	"strings"
	"testing"
)

func TestProfilesAreUsable(t *testing.T) {
	groups := Profiles()
	if len(groups) == 0 {
		t.Fatal("no TLS fingerprint groups")
	}
	total := 0
	for _, g := range groups {
		if g.Label == "" {
			t.Error("group with no label")
		}
		for _, name := range g.Names {
			if _, ok := profileFor(name); !ok {
				t.Errorf("%s/%s does not resolve to a client profile", g.Label, name)
			}
			total++
		}
	}
	if total < 20 {
		t.Errorf("only %d profiles exposed, expected the full set", total)
	}
	if _, ok := profileFor("definitely-not-a-browser"); ok {
		t.Error("an unknown name should not resolve")
	}
}

func TestProfilesGroupedAndNewestFirst(t *testing.T) {
	var chrome []string
	for _, g := range Profiles() {
		if g.Label == "Chrome" {
			chrome = g.Names
		}
		for _, n := range g.Names {
			if g.Label == "Chrome" && !strings.HasPrefix(n, "chrome") {
				t.Errorf("%q filed under Chrome", n)
			}
			if g.Label == "Firefox" && !strings.HasPrefix(n, "firefox") {
				t.Errorf("%q filed under Firefox", n)
			}
		}
	}
	if len(chrome) < 2 {
		t.Fatal("expected several Chrome profiles")
	}
	if versionOf(chrome[0]) < versionOf(chrome[len(chrome)-1]) {
		t.Errorf("Chrome profiles should be newest first, got %v", chrome[:3])
	}
}

func TestParseRawKeepsHeaderOrder(t *testing.T) {
	p, err := parseRaw("GET / HTTP/1.1\nHost: a.test\nUser-Agent: x\nAccept: */*\nAccept-Language: en\n\n")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"Host", "User-Agent", "Accept", "Accept-Language"}
	if len(p.Order) != len(want) {
		t.Fatalf("order = %v, want %v", p.Order, want)
	}
	for i := range want {
		if p.Order[i] != want[i] {
			t.Errorf("order[%d] = %q, want %q", i, p.Order[i], want[i])
		}
	}
}

func TestRawRequestTextFollowsTypedOrder(t *testing.T) {
	p, err := parseRaw("GET / HTTP/1.1\nHost: a.test\nZulu: 1\nAlpha: 2\n\n")
	if err != nil {
		t.Fatal(err)
	}
	got := string(rawRequestText(p, "a.test", 0))
	zulu, alpha := strings.Index(got, "Zulu"), strings.Index(got, "Alpha")
	if zulu < 0 || alpha < 0 {
		t.Fatalf("headers missing:\n%s", got)
	}
	if zulu > alpha {
		t.Errorf("headers were sorted instead of kept in typed order:\n%s", got)
	}
}

func TestWithProfileOverride(t *testing.T) {
	base := &Route{ID: "r", Profile: "chrome_131"}
	if got := base.withProfile(""); got.Profile != "chrome_131" {
		t.Errorf("empty override should keep the route's profile, got %q", got.Profile)
	}
	if got := base.withProfile("firefox_135"); got.Profile != "firefox_135" {
		t.Errorf("override = %q", got.Profile)
	}
	if got := base.withProfile("none"); got.Profile != "" {
		t.Errorf(`"none" should clear the profile, got %q`, got.Profile)
	}
	if base.Profile != "chrome_131" {
		t.Error("the original route was modified")
	}
}

func TestProxyURL(t *testing.T) {
	s := &Sender{port: 9090}
	cases := []struct {
		route *Route
		want  string
	}{
		{&Route{Kind: "direct"}, ""},
		{&Route{Kind: "sift"}, "http://127.0.0.1:9090"},
		{&Route{Kind: "http", Host: "10.0.0.1", Port: 8888}, "http://10.0.0.1:8888"},
		{&Route{Kind: "socks5", Host: "10.0.0.2"}, "socks5://10.0.0.2:1080"},
		{&Route{Kind: "socks5", Host: "p.test", Port: 1081, User: "bob", Pass: "s3cret"}, "socks5://bob:s3cret@p.test:1081"},
	}
	for _, c := range cases {
		if got := s.proxyURL(c.route); got != c.want {
			t.Errorf("%s -> %q, want %q", c.route.Kind, got, c.want)
		}
	}
}

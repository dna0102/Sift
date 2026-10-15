package scan

import (
	"net/url"
	"strings"

	"sift/internal/core"
)

type Scope struct {
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}

func (s Scope) InScope(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return false
	}
	host, port := core.SplitHostPort(u.Host, core.DefaultPort(strings.ToLower(u.Scheme)))
	return s.inScopeHost(host, port)
}

func (s Scope) inScopeHost(host string, port int) bool {
	if core.HostMatches(s.Exclude, host, port) {
		return false
	}
	if len(nonEmpty(s.Include)) == 0 {
		return false
	}
	return core.HostMatches(s.Include, host, port)
}

func nonEmpty(list []string) []string {
	out := list[:0:0]
	for _, v := range list {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}

type Intensity string

const (
	IntensityLight    Intensity = "light"
	IntensityNormal   Intensity = "normal"
	IntensityThorough Intensity = "thorough"
	IntensityInsane   Intensity = "insane"
)

type Options struct {
	Scope       Scope     `json:"scope"`
	Checks      []string  `json:"checks"`
	Intensity   Intensity `json:"intensity"`
	Concurrency int       `json:"concurrency"`
	RateLimit   int       `json:"rateLimit"`
	TimeoutSec  int       `json:"timeoutSec"`
	Route       string    `json:"route"`
	Profile     string    `json:"profile"`
	Passive     bool      `json:"passive"`
	Active      bool      `json:"active"`
	Discover    bool      `json:"discover"`
	Destructive bool      `json:"destructive"`
	Blind       bool      `json:"blind"`
	Collab      string    `json:"collab"`
	Seeds       []int64   `json:"seeds"`
	MaxRequests int       `json:"maxRequests"`
}

func (o Options) normalize() Options {
	if o.Intensity == "" {
		o.Intensity = IntensityNormal
	}
	if o.Concurrency <= 0 {
		o.Concurrency = intensityConcurrency(o.Intensity)
	}
	if o.Concurrency > 64 {
		o.Concurrency = 64
	}
	if o.TimeoutSec <= 0 {
		o.TimeoutSec = 20
	}
	if o.MaxRequests <= 0 {
		o.MaxRequests = intensityBudget(o.Intensity)
	}
	if o.Route == "" {
		o.Route = "direct"
	}
	if len(o.Checks) == 0 {
		o.Checks = AllCheckIDs()
	}
	return o
}

func (o Options) wants(id string) bool {
	for _, c := range o.Checks {
		if c == id || c == "all" {
			return true
		}
	}
	return false
}

func intensityConcurrency(i Intensity) int {
	switch i {
	case IntensityLight:
		return 4
	case IntensityThorough:
		return 20
	case IntensityInsane:
		return 40
	}
	return 10
}

func intensityBudget(i Intensity) int {
	switch i {
	case IntensityLight:
		return 2000
	case IntensityThorough:
		return 50000
	case IntensityInsane:
		return 500000
	}
	return 15000
}

func payloadDepth(i Intensity) int {
	switch i {
	case IntensityLight:
		return 1
	case IntensityThorough:
		return 3
	case IntensityInsane:
		return 5
	}
	return 2
}

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// Settings are saved to ~/.sift/config.json (same file and keys the Python version used).
type Settings struct {
	ProxyPort      int      `json:"proxy_port"`
	UIPort         int      `json:"ui_port"`
	Recording      bool     `json:"recording"`
	SystemProxy    bool     `json:"system_proxy"`
	SSLMode        string   `json:"ssl_mode"` // all | list | off
	SSLInclude     []string `json:"ssl_include"`
	SSLExclude     []string `json:"ssl_exclude"`
	SSLExcludeApps []string `json:"ssl_exclude_apps"`  // apps whose HTTPS is never decrypted
	AutoPassPinned bool     `json:"auto_pass_pinned"`  // pass hosts through after an app rejects the certificate
	SkipKnown      bool     `json:"skip_known_pinned"` // pass through services known to pin
	LearnedPins    []string `json:"learned_pins"`      // hosts detected as pinned (remembered)
	VerifyUpstream bool     `json:"verify_upstream"`
	NoCache        bool     `json:"no_cache"`
	AllowLAN       bool     `json:"allow_lan"`
	Bypass         string   `json:"bypass"`
	MaxFlows       int      `json:"max_flows"`
	MaxBodyMB      int      `json:"max_body_mb"`
	MaxMemoryMB    int      `json:"max_memory_mb"`
	ShowTunnels    bool     `json:"show_tunnels"`
	Theme          string   `json:"theme"` // system | dark | light
	Throttle       Throttle `json:"throttle"`
	Rules          []Rule   `json:"rules"`
	Pinned         []string `json:"pinned"`
}

type Throttle struct {
	Preset  string `json:"preset"`
	Latency int    `json:"latency"` // ms
	Down    int    `json:"down"`    // kbit/s
	Up      int    `json:"up"`      // kbit/s
	Hosts   string `json:"hosts"`
}

type ThrottlePreset struct {
	Key, Label          string
	Latency, Down, Up   int
}

var ThrottlePresets = []ThrottlePreset{
	{"off", "Off", 0, 0, 0},
	{"edge", "EDGE", 840, 240, 200},
	{"3g", "3G", 200, 780, 330},
	{"4g", "4G / LTE", 50, 4000, 3000},
	{"dsl", "DSL", 40, 2000, 256},
	{"wifi", "Wi-Fi", 5, 30000, 15000},
	{"custom", "Custom", 0, 0, 0},
}

func defaultSettings() Settings {
	return Settings{
		ProxyPort: 9090, UIPort: 9091, Recording: true, SSLMode: "all", VerifyUpstream: true,
		AutoPassPinned: true, SkipKnown: true,
		Bypass: "localhost;127.*;[::1];<local>", MaxFlows: 10000, MaxBodyMB: 10, MaxMemoryMB: 512,
		ShowTunnels: true, Theme: "system",
		Throttle: Throttle{Preset: "off", Latency: 200, Down: 780, Up: 330},
	}
}

type Config struct {
	mu    sync.RWMutex
	s     Settings
	path  string
	timer *time.Timer
}

func LoadConfig(home string) *Config {
	c := &Config{s: defaultSettings(), path: filepath.Join(home, "config.json")}
	if data, err := os.ReadFile(c.path); err == nil {
		_ = json.Unmarshal(data, &c.s)
	}
	if c.s.MaxMemoryMB <= 0 {
		c.s.MaxMemoryMB = 512
	}
	if c.s.Theme == "" {
		c.s.Theme = "system"
	}
	return c
}

// Get returns a snapshot. Slices inside are never modified in place, so sharing them is safe.
func (c *Config) Get() Settings {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.s
}

// Update changes settings and schedules a save.
func (c *Config) Update(fn func(s *Settings)) {
	c.mu.Lock()
	s := c.s
	s.SSLInclude = slices.Clone(s.SSLInclude)
	s.SSLExclude = slices.Clone(s.SSLExclude)
	s.SSLExcludeApps = slices.Clone(s.SSLExcludeApps)
	s.LearnedPins = slices.Clone(s.LearnedPins)
	s.Rules = slices.Clone(s.Rules)
	s.Pinned = slices.Clone(s.Pinned)
	fn(&s)
	c.s = s
	if c.timer != nil {
		c.timer.Stop()
	}
	c.timer = time.AfterFunc(200*time.Millisecond, c.Save)
	c.mu.Unlock()
}

func (c *Config) Save() {
	c.mu.RLock()
	data, _ := json.MarshalIndent(c.s, "", "  ")
	c.mu.RUnlock()
	tmp := c.path + ".tmp"
	if os.WriteFile(tmp, data, 0o644) == nil {
		_ = os.Rename(tmp, c.path)
	}
}

// ThrottleProfile returns latency and bytes/second limits, or ok=false when throttling is off.
func (s Settings) ThrottleProfile() (latency time.Duration, down, up int, ok bool) {
	t := s.Throttle
	if t.Preset == "" || t.Preset == "off" {
		return 0, 0, 0, false
	}
	l, d, u := t.Latency, t.Down, t.Up
	for _, p := range ThrottlePresets {
		if p.Key == t.Preset && p.Key != "custom" {
			l, d, u = p.Latency, p.Down, p.Up
		}
	}
	return time.Duration(l) * time.Millisecond, d * 125, u * 125, true
}

func (s Settings) MaxBody() int {
	if s.MaxBodyMB <= 0 {
		return 10 << 20
	}
	return s.MaxBodyMB << 20
}

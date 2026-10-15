package scan

import (
	"crypto/sha1"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

type Confidence string

const (
	ConfCertain   Confidence = "certain"
	ConfFirm      Confidence = "firm"
	ConfTentative Confidence = "tentative"
)

type Evidence struct {
	Label   string `json:"label"`
	Flow    int64  `json:"flow,omitempty"`
	Request string `json:"request,omitempty"`
	Snippet string `json:"snippet,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

type Finding struct {
	ID         string     `json:"id"`
	Type       string     `json:"type"`
	Title      string     `json:"title"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	CWE        string     `json:"cwe,omitempty"`
	Passive    bool       `json:"passive"`

	Method string `json:"method,omitempty"`
	URL    string `json:"url"`
	Host   string `json:"host"`
	Param  string `json:"param,omitempty"`
	Where  string `json:"where,omitempty"`

	Payload     string     `json:"payload,omitempty"`
	Detail      string     `json:"detail"`
	Remediation string     `json:"remediation,omitempty"`
	Repro       []string   `json:"repro,omitempty"`
	Evidence    []Evidence `json:"evidence,omitempty"`
	Flows       []int64    `json:"flows,omitempty"`

	Job   string `json:"job,omitempty"`
	First int64  `json:"first"`
	Last  int64  `json:"last"`
	Count int    `json:"count"`

	AITriage string `json:"aiTriage,omitempty"`
}

func (f *Finding) key() string {
	h := sha1.Sum([]byte(f.Type + "|" + f.Host + "|" + normPath(f.URL) + "|" + f.Param + "|" + f.Where))
	return hex.EncodeToString(h[:8])
}

func (f *Finding) stamp() {
	now := time.Now().UnixMilli()
	if f.First == 0 {
		f.First = now
	}
	f.Last = now
	if f.Count == 0 {
		f.Count = 1
	}
	if f.ID == "" {
		f.ID = f.key()
	}
}

func normPath(rawURL string) string {
	s := rawURL
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i]
	}
	return s
}

var sevRank = map[Severity]int{SevCritical: 0, SevHigh: 1, SevMedium: 2, SevLow: 3, SevInfo: 4}
var confRank = map[Confidence]int{ConfCertain: 0, ConfFirm: 1, ConfTentative: 2}

func (s Severity) Score() int {
	switch s {
	case SevCritical:
		return 10
	case SevHigh:
		return 8
	case SevMedium:
		return 5
	case SevLow:
		return 3
	}
	return 1
}

func sortFindings(f []*Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		if sevRank[f[i].Severity] != sevRank[f[j].Severity] {
			return sevRank[f[i].Severity] < sevRank[f[j].Severity]
		}
		if confRank[f[i].Confidence] != confRank[f[j].Confidence] {
			return confRank[f[i].Confidence] < confRank[f[j].Confidence]
		}
		return f[i].Last > f[j].Last
	})
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

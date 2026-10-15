package scan

import (
	"math"
	"strings"
)

type baseline struct {
	status  int
	length  int
	body    string
	lenVar  int
	words   int
	lines   int
	hadErr  bool
	ok      bool
	timings []int64
}

func newBaseline(resps []*Response) *baseline {
	b := &baseline{}
	if len(resps) == 0 {
		return b
	}
	first := resps[0]
	b.status = first.Status
	b.body = string(first.Body)
	b.length = len(first.Body)
	b.words = len(strings.Fields(b.body))
	b.lines = strings.Count(b.body, "\n")
	for _, s := range errorSigs {
		if s.re.MatchString(b.body) {
			b.hadErr = true
			break
		}
	}
	minL, maxL := b.length, b.length
	for _, r := range resps {
		if len(r.Body) < minL {
			minL = len(r.Body)
		}
		if len(r.Body) > maxL {
			maxL = len(r.Body)
		}
		b.timings = append(b.timings, r.Duration)
	}
	b.lenVar = maxL - minL
	b.ok = true
	return b
}

func (b *baseline) medianTime() int64 {
	if len(b.timings) == 0 {
		return 0
	}
	sum := int64(0)
	for _, t := range b.timings {
		sum += t
	}
	return sum / int64(len(b.timings))
}

func (b *baseline) statusChanged(r *Response) bool {
	return b.ok && r.Status != b.status && !(r.Status == 0)
}

func (b *baseline) lengthAnomaly(r *Response) bool {
	if !b.ok {
		return false
	}
	delta := int(math.Abs(float64(len(r.Body) - b.length)))
	return delta > b.lenVar+32 && delta > b.length/20
}

func (b *baseline) newError(r *Response) (string, bool) {
	if b.hadErr {
		return "", false
	}
	body := string(r.Body)
	for _, s := range errorSigs {
		if m := s.re.FindString(body); m != "" {
			return m, true
		}
	}
	return "", false
}

func reflects(body, marker string) bool {
	return strings.Contains(body, marker)
}

func countOccur(body, marker string) int {
	return strings.Count(body, marker)
}

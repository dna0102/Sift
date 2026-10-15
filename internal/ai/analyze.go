package ai

import (
	"context"
	"encoding/json"
	"strings"
)

const systemPrompt = `You are a senior web application security analyst assisting with an authorised penetration test and bug-bounty engagement. You are reviewing output from Sift, a proxy and scanner. Be precise, evidence-based and concise. Judge findings on the evidence given, call out likely false positives plainly, and never invent evidence. Prioritise genuine, high-impact issues. When you suggest further tests, keep them specific and safe for an authorised scope.`

type TriageItem struct {
	ID        string   `json:"id"`
	Verdict   string   `json:"verdict"`
	Priority  string   `json:"priority"`
	Rationale string   `json:"rationale"`
	NextSteps []string `json:"nextSteps"`
}

type TriageResult struct {
	Items []TriageItem `json:"items"`
	Meta  *RunResult   `json:"meta,omitempty"`
}

func stripFences(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			s = s[i+1:]
		}
		s = strings.TrimSuffix(strings.TrimSpace(s), "```")
	}
	if i := strings.IndexByte(s, '{'); i > 0 {
		s = s[i:]
	}
	return strings.TrimSpace(s)
}

func (m *Manager) Triage(ctx context.Context, findingsJSON string) (*TriageResult, error) {
	prompt := `Here are scan findings as JSON. For each one, decide whether it is a genuine issue, a likely false positive, or needs manual verification, and give it a priority.

Return ONLY JSON of the form:
{"items":[{"id":"<finding id>","verdict":"confirmed|likely|false-positive|needs-verification","priority":"critical|high|medium|low|info","rationale":"one or two sentences","nextSteps":["..."]}]}

Findings:
` + findingsJSON

	res, err := m.Run(ctx, TaskTriage, ChatRequest{System: systemPrompt, Temperature: 0.1, JSON: true,
		Messages: []Message{{Role: "user", Content: prompt}}})
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Items []TriageItem `json:"items"`
	}
	if err := json.Unmarshal([]byte(stripFences(res.Content)), &parsed); err != nil {
		return nil, err
	}
	return &TriageResult{Items: parsed.Items, Meta: res}, nil
}

type TextResult struct {
	Text string     `json:"text"`
	Meta *RunResult `json:"meta,omitempty"`
}

func (m *Manager) runText(ctx context.Context, task, prompt string, history []Message) (*TextResult, error) {
	msgs := append([]Message{}, history...)
	msgs = append(msgs, Message{Role: "user", Content: prompt})
	res, err := m.Run(ctx, task, ChatRequest{System: systemPrompt, Temperature: 0.2, Messages: msgs})
	if err != nil {
		return nil, err
	}
	return &TextResult{Text: res.Content, Meta: res}, nil
}

func (m *Manager) Correlate(ctx context.Context, findingsJSON, trafficSummary string) (*TextResult, error) {
	prompt := `Review these findings and the traffic summary. Identify issues that chain together or imply higher impact than any single finding (for example an IDOR plus weak auth, or SSRF reachable from a user-controlled URL). Call out the single most promising lead. Be brief and concrete.

Findings:
` + findingsJSON + "\n\nTraffic summary:\n" + trafficSummary
	return m.runText(ctx, TaskCorrelate, prompt, nil)
}

func (m *Manager) Recommend(ctx context.Context, contextJSON string) (*TextResult, error) {
	prompt := `Based on the endpoints, parameters and findings below, recommend the next tests that are most likely to surface a high-impact vulnerability, and name the attack surface worth focusing on. Give a short ranked list with a one-line reason each.

Context:
` + contextJSON
	return m.runText(ctx, TaskRecommend, prompt, nil)
}

func (m *Manager) Verify(ctx context.Context, findingJSON string) (*TextResult, error) {
	prompt := `Assess whether this finding is genuinely exploitable, how confident you are, and the exact steps or request needed to prove it. If it looks like a false positive, say so and why.

Finding:
` + findingJSON
	return m.runText(ctx, TaskVerify, prompt, nil)
}

func (m *Manager) Chat(ctx context.Context, history []Message, question, contextJSON string) (*TextResult, error) {
	prompt := question
	if contextJSON != "" {
		prompt += "\n\nRelevant context:\n" + contextJSON
	}
	return m.runText(ctx, TaskChat, prompt, history)
}

package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatRequest struct {
	Model       string
	System      string
	Messages    []Message
	Temperature float64
	MaxTokens   int
	JSON        bool
}

type Usage struct {
	In  int `json:"in"`
	Out int `json:"out"`
}

type ChatResponse struct {
	Content string `json:"content"`
	Model   string `json:"model"`
	Usage   Usage  `json:"usage"`
}

type Provider interface {
	Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error)
	Kind() string
}

var httpClient = &http.Client{Timeout: 180 * time.Second}

func postJSON(ctx context.Context, url string, headers map[string]string, body any) ([]byte, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if res.StatusCode >= 400 {
		return nil, fmt.Errorf("%s: %s", res.Status, strings.TrimSpace(clip(string(out), 400)))
	}
	return out, nil
}

type openAIProvider struct {
	baseURL string
	key     string
}

func (p openAIProvider) Kind() string { return "openai" }

func (p openAIProvider) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	msgs := make([]map[string]string, 0, len(req.Messages)+1)
	if req.System != "" {
		msgs = append(msgs, map[string]string{"role": "system", "content": req.System})
	}
	for _, m := range req.Messages {
		msgs = append(msgs, map[string]string{"role": m.Role, "content": m.Content})
	}
	body := map[string]any{"model": req.Model, "messages": msgs}
	if req.Temperature > 0 {
		body["temperature"] = req.Temperature
	}
	if req.MaxTokens > 0 {
		body["max_tokens"] = req.MaxTokens
	}
	if req.JSON {
		body["response_format"] = map[string]string{"type": "json_object"}
	}
	headers := map[string]string{}
	if p.key != "" {
		headers["Authorization"] = "Bearer " + p.key
	}
	out, err := postJSON(ctx, strings.TrimRight(p.baseURL, "/")+"/chat/completions", headers, body)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, err
	}
	if len(parsed.Choices) == 0 {
		return nil, errors.New("no response from model")
	}
	return &ChatResponse{Content: parsed.Choices[0].Message.Content, Model: parsed.Model,
		Usage: Usage{In: parsed.Usage.PromptTokens, Out: parsed.Usage.CompletionTokens}}, nil
}

type anthropicProvider struct {
	baseURL string
	key     string
}

func (p anthropicProvider) Kind() string { return "anthropic" }

func (p anthropicProvider) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	msgs := make([]map[string]any, 0, len(req.Messages))
	for _, m := range req.Messages {
		role := m.Role
		if role != "user" && role != "assistant" {
			role = "user"
		}
		msgs = append(msgs, map[string]any{"role": role, "content": m.Content})
	}
	maxTok := req.MaxTokens
	if maxTok <= 0 {
		maxTok = 4096
	}
	body := map[string]any{"model": req.Model, "messages": msgs, "max_tokens": maxTok}
	if req.System != "" {
		body["system"] = req.System
	}
	if req.Temperature > 0 {
		body["temperature"] = req.Temperature
	}
	base := p.baseURL
	if base == "" {
		base = "https://api.anthropic.com"
	}
	headers := map[string]string{"x-api-key": p.key, "anthropic-version": "2023-06-01"}
	out, err := postJSON(ctx, strings.TrimRight(base, "/")+"/v1/messages", headers, body)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Model   string `json:"model"`
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, err
	}
	var sb strings.Builder
	for _, c := range parsed.Content {
		sb.WriteString(c.Text)
	}
	return &ChatResponse{Content: sb.String(), Model: parsed.Model,
		Usage: Usage{In: parsed.Usage.InputTokens, Out: parsed.Usage.OutputTokens}}, nil
}

type geminiProvider struct {
	baseURL string
	key     string
}

func (p geminiProvider) Kind() string { return "gemini" }

func (p geminiProvider) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	var contents []map[string]any
	for _, m := range req.Messages {
		role := "user"
		if m.Role == "assistant" {
			role = "model"
		}
		contents = append(contents, map[string]any{"role": role, "parts": []map[string]string{{"text": m.Content}}})
	}
	body := map[string]any{"contents": contents}
	gen := map[string]any{}
	if req.Temperature > 0 {
		gen["temperature"] = req.Temperature
	}
	if req.MaxTokens > 0 {
		gen["maxOutputTokens"] = req.MaxTokens
	}
	if req.JSON {
		gen["responseMimeType"] = "application/json"
	}
	if len(gen) > 0 {
		body["generationConfig"] = gen
	}
	if req.System != "" {
		body["systemInstruction"] = map[string]any{"parts": []map[string]string{{"text": req.System}}}
	}
	base := p.baseURL
	if base == "" {
		base = "https://generativelanguage.googleapis.com"
	}
	url := strings.TrimRight(base, "/") + "/v1beta/models/" + req.Model + ":generateContent?key=" + p.key
	out, err := postJSON(ctx, url, nil, body)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
		UsageMetadata struct {
			PromptTokenCount     int `json:"promptTokenCount"`
			CandidatesTokenCount int `json:"candidatesTokenCount"`
		} `json:"usageMetadata"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, err
	}
	if len(parsed.Candidates) == 0 {
		return nil, errors.New("no response from model")
	}
	var sb strings.Builder
	for _, part := range parsed.Candidates[0].Content.Parts {
		sb.WriteString(part.Text)
	}
	return &ChatResponse{Content: sb.String(), Model: req.Model,
		Usage: Usage{In: parsed.UsageMetadata.PromptTokenCount, Out: parsed.UsageMetadata.CandidatesTokenCount}}, nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

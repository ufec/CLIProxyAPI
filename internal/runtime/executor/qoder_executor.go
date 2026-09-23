package executor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	qoderauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/qoder"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

// QoderExecutor is a stateless executor for the Qoder provider
// (api3.qoder.sh agent_chat_generation SSE API).
//
// Protocol summary (verified end-to-end, see oauth-service/qorder/):
//   - request body = custom-base64 followed by an outer-third swap
//   - envelope headers = COSY (Authorization Bearer COSY..., Cosy-Key, ...)
//   - upstream returns SSE lines: data:{"headers":...,"body":"<openai chunk>",
//     "statusCodeValue":200} and a final data:{"firstTokenDuration":...}.
//   - The inner "body" is a standard OpenAI chat.completion.chunk JSON; we
//     unwrap and forward it unchanged.
type QoderExecutor struct {
	cfg         *config.Config
	upstreamURL string
	// UpstreamURLOverride, when non-empty, replaces the default Qoder endpoint
	// (used by tests that stub the upstream with a local server).
	UpstreamURLOverride string
	// RefreshURLOverride and RefreshHTTPClient support isolated refresh tests.
	RefreshURLOverride string
	RefreshHTTPClient  *http.Client
}

// NewQoderExecutor creates a new Qoder executor.
func NewQoderExecutor(cfg *config.Config) *QoderExecutor {
	return &QoderExecutor{
		cfg:         cfg,
		upstreamURL: qoderauth.APIHost + qoderauth.AgentChatGenerationPath,
	}
}

// Identifier returns the executor identifier.
func (e *QoderExecutor) Identifier() string { return "qoder" }

// RequestToFormat reports the upstream request format.
func (e *QoderExecutor) RequestToFormat(req cliproxyexecutor.Request, opts cliproxyexecutor.Options) sdktranslator.Format {
	return sdktranslator.FormatOpenAIResponse
}

// qoderUserFromAuth extracts the Qoder user identity from auth attributes/metadata.
func qoderUserFromAuth(auth *cliproxyauth.Auth) (*qoderauth.User, bool) {
	if auth == nil {
		return nil, false
	}
	attrs := auth.Attributes
	if attrs == nil {
		attrs = map[string]string{}
	}
	token := strings.TrimSpace(attrs["security_oauth_token"])
	if token == "" {
		token = strings.TrimSpace(attrs["access_token"])
	}
	if token == "" {
		if v, ok := auth.Metadata["access_token"].(string); ok && strings.TrimSpace(v) != "" {
			token = strings.TrimSpace(v)
		}
	}
	if token == "" {
		return nil, false
	}
	uid := strings.TrimSpace(attrs["uid"])
	if uid == "" {
		uid = strings.TrimSpace(attrs["x-gw-user-id"])
	}
	if uid == "" {
		if v, ok := auth.Metadata["uid"].(string); ok && strings.TrimSpace(v) != "" {
			uid = strings.TrimSpace(v)
		}
	}
	if uid == "" {
		return nil, false
	}
	return &qoderauth.User{
		UID:   uid,
		Name:  strings.TrimSpace(attrs["name"]),
		Email: strings.TrimSpace(attrs["email"]),
		Token: token,
	}, true
}

// PrepareRequest injects Qoder COSY credentials into an outgoing request.
// It encodes plaintextBody with the Qoder wire codec and sets that as
// the wire body so
// the signed body and the transmitted body are guaranteed identical. The
// timestamp ts (unix seconds) is used for signature material; pass the same ts
// the caller used to compute the signing window.
func (e *QoderExecutor) PrepareRequest(req *http.Request, auth *cliproxyauth.Auth, ts int64, plaintextBody []byte) error {
	if req == nil {
		return nil
	}
	user, ok := qoderUserFromAuth(auth)
	if !ok {
		return fmt.Errorf("qoder executor: missing qoder user credentials (uid + security_oauth_token)")
	}
	encoded := ""
	if plaintextBody != nil {
		encoded = qoderauth.EncodeRequestBody(plaintextBody)
	}
	if ts == 0 {
		ts = time.Now().Unix()
	}
	headers, err := qoderauth.BuildCosyHeaders(req.URL.String(), user, encoded, ts)
	if err != nil {
		return fmt.Errorf("qoder executor: build cosy headers: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("X-Model-Key", "qfmodel")
	req.Header.Set("X-Model-Source", "system")
	// Set the wire body to the exact encoded payload we signed.
	if encoded != "" {
		req.Body = io.NopCloser(strings.NewReader(encoded))
		req.ContentLength = int64(len(encoded))
	}
	return nil
}

// qoderChatBody builds the plaintext request JSON for agent_chat_generation.
func qoderChatBody(req cliproxyexecutor.Request, opts cliproxyexecutor.Options) ([]byte, error) {
	payload := req.Payload
	if len(payload) == 0 {
		payload = opts.OriginalRequest
	}
	model := strings.TrimSpace(req.Model)
	if model == "" {
		model = "qfmodel"
	}

	// Extract OpenAI-compatible fields from the client payload.
	msgText := ""
	if gjson.ValidBytes(payload) {
		last := gjson.GetBytes(payload, "messages|@reverse|0")
		content := last.Get("content")
		switch content.Type {
		case gjson.String:
			msgText = content.String()
		case gjson.JSON:
			// content may be an array of {type,text}
			var sb strings.Builder
			content.ForEach(func(_, item gjson.Result) bool {
				if item.Get("type").String() == "text" {
					sb.WriteString(item.Get("text").String())
				}
				return true
			})
			msgText = sb.String()
		}
	}
	maxTokens := int64(32000)
	if v := gjson.GetBytes(payload, "max_tokens").Int(); v > 0 {
		maxTokens = v
	}
	if v := gjson.GetBytes(payload, "max_completion_tokens").Int(); v > 0 {
		maxTokens = v
	}
	contextLength := int64(200000)
	if v := gjson.GetBytes(payload, "context_length").Int(); v > 0 {
		contextLength = v
	}
	reasoning := strings.TrimSpace(gjson.GetBytes(payload, "reasoning_effort").String())
	if reasoning == "" {
		reasoning = "medium"
	}
	thinking := true
	if raw := gjson.GetBytes(payload, "enable_thinking"); raw.Exists() {
		thinking = raw.Bool()
	}

	displayName := "Qwen3.8-Flash"
	if model != "" && model != "qfmodel" {
		displayName = model
	}
	modelConfig := map[string]any{
		"key":          "qfmodel",
		"display_name": displayName,
		"model":        "",
		"format":       "openai",
		"is_vl":        true,
		"is_reasoning": true,
		"api_key":      "",
		"url":          "",
		"source":       "system",
	}
	systemPrompt := map[string]any{
		"type": "text",
		"text": "You are a Qoder agent. Use the instructions below and the tools available to you to assist the user.",
	}
	userContent := map[string]any{"type": "text", "text": msgText}
	body := map[string]any{
		"parameters": map[string]any{
			"reasoning_effort": reasoning,
			"enable_thinking":  thinking,
			"max_tokens":       maxTokens,
			"context_length":   contextLength,
		},
		"business": map[string]any{
			"product":  "app",
			"version":  "1.1.49",
			"type":     "agent",
			"id":       qoderauth.NewID(),
			"name":     "CLIProxy API session",
			"begin_at": time.Now().UnixMilli(),
			"stage":    "start",
		},
		"agent_id":     "agent_common",
		"task_id":      "common",
		"session_type": "app",
		"model_config": modelConfig,
		"system":       []any{systemPrompt},
		"messages": []any{
			map[string]any{"role": "system", "content": []any{systemPrompt}},
			map[string]any{"role": "user", "content": []any{userContent}},
		},
	}
	return json.Marshal(body)
}

// Execute performs a non-streaming call (Qoder is SSE-only, so we buffer the
// stream into a single response).
func (e *QoderExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	stream, err := e.ExecuteStream(ctx, auth, req, opts)
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	payload, err := aggregateQoderCompletion(stream.Chunks, req.Model)
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	headers := stream.Headers.Clone()
	headers.Set("Content-Type", "application/json")
	return cliproxyexecutor.Response{Payload: payload, Headers: headers}, nil
}

type qoderCompletionChunk struct {
	ID      string          `json:"id"`
	Created int64           `json:"created"`
	Model   string          `json:"model"`
	Usage   json.RawMessage `json:"usage"`
	Choices []struct {
		Index        int     `json:"index"`
		FinishReason *string `json:"finish_reason"`
		Delta        struct {
			Role             string `json:"role"`
			Content          string `json:"content"`
			ReasoningContent string `json:"reasoning_content"`
			ToolCalls        []struct {
				Index    int    `json:"index"`
				ID       string `json:"id"`
				Type     string `json:"type"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"delta"`
	} `json:"choices"`
}

type qoderAggregatedToolCall struct {
	ID        string
	Type      string
	Name      string
	Arguments strings.Builder
}

type qoderAggregatedChoice struct {
	Role         string
	Content      strings.Builder
	Reasoning    strings.Builder
	FinishReason *string
	ToolCalls    map[int]*qoderAggregatedToolCall
}

func aggregateQoderCompletion(chunks <-chan cliproxyexecutor.StreamChunk, requestedModel string) ([]byte, error) {
	choices := make(map[int]*qoderAggregatedChoice)
	var id, model string
	var created int64
	var usage json.RawMessage
	for chunk := range chunks {
		if chunk.Err != nil {
			return nil, chunk.Err
		}
		data := bytes.TrimSpace(chunk.Payload)
		var part qoderCompletionChunk
		if err := json.Unmarshal(data, &part); err != nil {
			return nil, fmt.Errorf("qoder executor: decode stream chunk: %w", err)
		}
		if id == "" {
			id = part.ID
			created = part.Created
			model = part.Model
		}
		if len(part.Usage) > 0 && string(part.Usage) != "null" {
			usage = part.Usage
		}
		for _, choice := range part.Choices {
			current := choices[choice.Index]
			if current == nil {
				current = &qoderAggregatedChoice{Role: "assistant", ToolCalls: make(map[int]*qoderAggregatedToolCall)}
				choices[choice.Index] = current
			}
			if choice.Delta.Role != "" {
				current.Role = choice.Delta.Role
			}
			current.Content.WriteString(choice.Delta.Content)
			current.Reasoning.WriteString(choice.Delta.ReasoningContent)
			if choice.FinishReason != nil {
				current.FinishReason = choice.FinishReason
			}
			for _, tool := range choice.Delta.ToolCalls {
				target := current.ToolCalls[tool.Index]
				if target == nil {
					target = &qoderAggregatedToolCall{}
					current.ToolCalls[tool.Index] = target
				}
				if tool.ID != "" {
					target.ID = tool.ID
				}
				if tool.Type != "" {
					target.Type = tool.Type
				}
				if tool.Function.Name != "" {
					target.Name = tool.Function.Name
				}
				target.Arguments.WriteString(tool.Function.Arguments)
			}
		}
	}
	if len(choices) == 0 {
		return nil, fmt.Errorf("qoder executor: upstream returned no completion choices")
	}
	indexes := make([]int, 0, len(choices))
	for index := range choices {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	resultChoices := make([]map[string]any, 0, len(indexes))
	for _, index := range indexes {
		choice := choices[index]
		message := map[string]any{"role": choice.Role, "content": choice.Content.String()}
		if choice.Reasoning.Len() > 0 {
			message["reasoning_content"] = choice.Reasoning.String()
		}
		if len(choice.ToolCalls) > 0 {
			toolIndexes := make([]int, 0, len(choice.ToolCalls))
			for toolIndex := range choice.ToolCalls {
				toolIndexes = append(toolIndexes, toolIndex)
			}
			sort.Ints(toolIndexes)
			tools := make([]map[string]any, 0, len(toolIndexes))
			for _, toolIndex := range toolIndexes {
				tool := choice.ToolCalls[toolIndex]
				tools = append(tools, map[string]any{
					"id": tool.ID, "type": tool.Type,
					"function": map[string]any{"name": tool.Name, "arguments": tool.Arguments.String()},
				})
			}
			message["tool_calls"] = tools
		}
		resultChoices = append(resultChoices, map[string]any{
			"index": index, "message": message, "finish_reason": choice.FinishReason,
		})
	}
	if strings.TrimSpace(requestedModel) != "" {
		model = requestedModel
	}
	result := map[string]any{
		"id": id, "object": "chat.completion", "created": created,
		"model": model, "choices": resultChoices,
	}
	if len(usage) > 0 {
		result["usage"] = usage
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("qoder executor: encode completion: %w", err)
	}
	return encoded, nil
}

// ExecuteStream performs the SSE chat call and unwraps OpenAI chunks.
func (e *QoderExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	plaintext, err := qoderChatBody(req, opts)
	if err != nil {
		return nil, fmt.Errorf("qoder executor: build chat body: %w", err)
	}
	// Single shared timestamp: signing material and wire body are produced from
	// the same plaintext+ts inside PrepareRequest.
	ts := time.Now().Unix()

	endpoint := e.upstreamURL
	if e.UpstreamURLOverride != "" {
		endpoint = e.UpstreamURLOverride
	}
	if strings.TrimSpace(endpoint) == "" {
		endpoint = qoderauth.APIHost + qoderauth.AgentChatGenerationPath
	}
	// Body is set inside PrepareRequest after re-encoding plaintext.
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(""))
	if err != nil {
		return nil, fmt.Errorf("qoder executor: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if errPrep := e.PrepareRequest(httpReq, auth, ts, plaintext); errPrep != nil {
		return nil, errPrep
	}

	client := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	resp, errDo := client.Do(httpReq)
	if errDo != nil {
		return nil, fmt.Errorf("qoder executor: request failed: %w", errDo)
	}

	chunks := make(chan cliproxyexecutor.StreamChunk, 32)
	go e.streamSSE(ctx, resp, chunks)
	return &cliproxyexecutor.StreamResult{Headers: resp.Header.Clone(), Chunks: chunks}, nil
}

// streamSSE reads the SSE stream, unwraps the outer envelope, and forwards the
// inner OpenAI chunk JSON. The API handler adds the SSE data framing.
func (e *QoderExecutor) streamSSE(ctx context.Context, resp *http.Response, chunks chan<- cliproxyexecutor.StreamChunk) {
	defer func() {
		_ = resp.Body.Close()
		close(chunks)
	}()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		msg := fmt.Errorf("qoder executor: upstream status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		log.Errorf("qoder executor: non-200 response status=%d ct=%q body=%q", resp.StatusCode, resp.Header.Get("Content-Type"), truncateForLog(string(body), 4096))
		chunks <- cliproxyexecutor.StreamChunk{Err: msg}
		return
	}
	log.Infof("qoder executor: upstream 200 ct=%q clen=%d", resp.Header.Get("Content-Type"), resp.ContentLength)
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64<<10), 4<<20)
	forwarded := 0
	var firstLine string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		if forwarded == 0 && firstLine == "" {
			firstLine = line
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || !gjson.Valid(payload) {
			continue
		}
		// Final block: data:{"firstTokenDuration":...}
		if !gjson.Get(payload, "body").Exists() {
			continue
		}
		inner := gjson.Get(payload, "body").String()
		if inner == "" || !json.Valid([]byte(inner)) {
			continue
		}
		select {
		case chunks <- cliproxyexecutor.StreamChunk{Payload: []byte(inner)}:
			forwarded++
		case <-ctx.Done():
			return
		}
	}
	if errScan := scanner.Err(); errScan != nil {
		select {
		case chunks <- cliproxyexecutor.StreamChunk{Err: fmt.Errorf("qoder executor: read stream: %w", errScan)}:
		default:
		}
		return
	}
	if forwarded == 0 {
		// Upstream returned HTTP 200 but no forwardable payload. Surface a
		// concrete error (with the first data line for diagnosis) instead of
		// letting readStreamBootstrap collapse to a generic empty_stream.
		// If the first data line is a Qoder-style error envelope
		// (event:error + data:{"stackTrace":...,"message":"..."}), extract
		// the human-readable message so users don't have to dig through
		// a Jackson stack trace.
		var diagMsg string
		if firstLine != "" {
			payload := strings.TrimSpace(strings.TrimPrefix(firstLine, "data:"))
			if msg := gjson.Get(payload, "message").String(); msg != "" {
				diagMsg = msg
			} else if msg := gjson.Get(payload, "localizedMessage").String(); msg != "" {
				diagMsg = msg
			} else if msg := gjson.Get(payload, "msgInfo").String(); msg != "" {
				diagMsg = msg
			}
		}
		diag := fmt.Errorf("qoder executor: upstream returned HTTP 200 but no forwardable payload; first_data_line=%q", truncateForLog(firstLine, 256))
		if diagMsg != "" {
			diag = fmt.Errorf("qoder executor: upstream returned HTTP 200 with error payload; upstream_message=%q", truncateForLog(diagMsg, 512))
		}
		log.Errorf("qoder executor: %v", diag)
		log.Errorf("qoder executor: raw upstream first data line=%q", truncateForLog(firstLine, 4096))
		select {
		case chunks <- cliproxyexecutor.StreamChunk{Err: diag}:
		default:
		}
	}
}

// truncateForLog caps a string for log output so error bodies do not flood.
func truncateForLog(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// Refresh rotates the Qoder job token pair using the persisted refresh token.
func (e *QoderExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	if auth == nil {
		return nil, fmt.Errorf("qoder refresh: missing credential")
	}
	refreshToken, _ := auth.Metadata["refresh_token"].(string)
	updated, err := qoderauth.RefreshJobToken(ctx, e.RefreshHTTPClient, e.RefreshURLOverride, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("qoder refresh: %w", err)
	}
	result := auth.Clone()
	if result.Metadata == nil {
		result.Metadata = make(map[string]any)
	}
	result.Metadata["access_token"] = updated.Token
	result.Metadata["security_oauth_token"] = updated.Token
	result.Metadata["refresh_token"] = updated.RefreshToken
	if result.Attributes == nil {
		result.Attributes = make(map[string]string)
	}
	result.Attributes["security_oauth_token"] = updated.Token
	return result, nil
}

// CountTokens reports a best-effort estimate from the plaintext body.
func (e *QoderExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	plaintext, err := qoderChatBody(req, opts)
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	n := len(strings.Fields(string(plaintext)))
	usage := fmt.Sprintf(`{"usage":{"prompt_tokens":%d,"completion_tokens":0,"total_tokens":%d}}`, n, n)
	return cliproxyexecutor.Response{Payload: []byte(usage)}, nil
}

// HttpRequest injects Qoder credentials and executes the supplied request.
func (e *QoderExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("qoder executor: request is nil")
	}
	if ctx == nil {
		ctx = req.Context()
	}
	httpReq := req.WithContext(ctx)
	// Read the plaintext body so PrepareRequest can re-encode it and set the
	// wire body to the exact payload it signs.
	plaintext, err := io.ReadAll(httpReq.Body)
	if err != nil {
		return nil, fmt.Errorf("qoder executor: read body: %w", err)
	}
	if errClose := httpReq.Body.Close(); errClose != nil {
		log.Errorf("qoder executor: close body: %v", errClose)
	}
	ts := time.Now().Unix()
	if errPrep := e.PrepareRequest(httpReq, auth, ts, plaintext); errPrep != nil {
		return nil, errPrep
	}
	client := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	return client.Do(httpReq)
}

// qoderSSEUnwrap unwraps one outer envelope line -> inner chunk (used by tests).
func qoderSSEUnwrap(line string) ([]byte, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "data:") {
		return nil, false
	}
	payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
	if !gjson.Valid(payload) {
		return nil, false
	}
	if !gjson.Get(payload, "body").Exists() {
		return nil, false
	}
	inner := gjson.Get(payload, "body").String()
	if inner == "" {
		return nil, false
	}
	return []byte(inner), true
}

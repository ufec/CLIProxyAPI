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

	codebuddyauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codebuddy"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// CodeBuddyExecutor is a stateless executor for the Tencent CodeBuddy
// (WorkBuddy) copilot service. The upstream speaks the OpenAI chat
// completions protocol at /v2/chat/completions and authenticates with an
// OAuth access token obtained through the state-based plugin auth flow.
// The CN and international (workbuddy.ai) deployments share the protocol and
// only differ in endpoints and branding, selected through a Region.
type CodeBuddyExecutor struct {
	cfg    *config.Config
	region *codebuddyauth.Region
}

// NewCodeBuddyExecutor creates a new CodeBuddy executor for the CN deployment.
func NewCodeBuddyExecutor(cfg *config.Config) *CodeBuddyExecutor {
	return newCodeBuddyExecutorForRegion(cfg, nil)
}

// NewCodeBuddyIntlExecutor creates a new CodeBuddy executor for the
// international (workbuddy.ai) deployment.
func NewCodeBuddyIntlExecutor(cfg *config.Config) *CodeBuddyExecutor {
	return newCodeBuddyExecutorForRegion(cfg, codebuddyauth.RegionIntl)
}

// newCodeBuddyExecutorForRegion creates a CodeBuddy executor for the given
// region; a nil region falls back to the CN deployment.
func newCodeBuddyExecutorForRegion(cfg *config.Config, region *codebuddyauth.Region) *CodeBuddyExecutor {
	if region == nil {
		region = codebuddyauth.RegionCN
	}
	return &CodeBuddyExecutor{cfg: cfg, region: region}
}

// Identifier returns the executor identifier.
func (e *CodeBuddyExecutor) Identifier() string { return e.region.Provider }

// RequestToFormat reports the upstream request format: OpenAI chat completions.
func (e *CodeBuddyExecutor) RequestToFormat(_ cliproxyexecutor.Request, _ cliproxyexecutor.Options) sdktranslator.Format {
	return sdktranslator.FormatOpenAI
}

// codebuddyCreds extracts the access token from an auth record. OAuth tokens
// live in metadata; a manually provisioned token may appear in attributes.
func codebuddyCreds(a *cliproxyauth.Auth) string {
	if a == nil {
		return ""
	}
	if a.Metadata != nil {
		if v, ok := a.Metadata["access_token"].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	if a.Attributes != nil {
		if v := a.Attributes["access_token"]; v != "" {
			return v
		}
		if v := a.Attributes["api_key"]; v != "" {
			return v
		}
	}
	return ""
}

// codebuddyUID returns the account user id used for the X-User-Id header.
func codebuddyUID(a *cliproxyauth.Auth) string {
	if a == nil {
		return ""
	}
	if a.Metadata != nil {
		if v, ok := a.Metadata["uid"].(string); ok {
			return strings.TrimSpace(v)
		}
	}
	if a.Attributes != nil {
		return strings.TrimSpace(a.Attributes["uid"])
	}
	return ""
}

// codebuddyBaseURL resolves the upstream base URL, allowing a per-auth override.
func codebuddyBaseURL(a *cliproxyauth.Auth, region *codebuddyauth.Region) string {
	if a != nil && a.Attributes != nil {
		if base := strings.TrimSpace(a.Attributes["base_url"]); base != "" {
			return base
		}
	}
	if region == nil {
		region = codebuddyauth.RegionCN
	}
	return region.BaseURL
}

// isCodeBuddySSEHeartbeat reports whether the SSE line is an upstream
// keep-alive comment (": heartbeat" or "data: : heartbeat") whose payload is
// not valid JSON and must not be forwarded to downstream clients.
func isCodeBuddySSEHeartbeat(line []byte) bool {
	trimmed := bytes.TrimSpace(line)
	if bytes.HasPrefix(trimmed, []byte(":")) {
		return true
	}
	payload, ok := bytes.CutPrefix(trimmed, []byte("data:"))
	if !ok {
		return false
	}
	return bytes.HasPrefix(bytes.TrimSpace(payload), []byte(":"))
}

// normalizeCodeBuddyUpstreamModel returns the upstream model ID by stripping
// the CLIProxyAPI "codebuddy-" prefix and any Claude Code "[1m]" context
// suffix while preserving a trailing thinking suffix (e.g. "(1024)").
func normalizeCodeBuddyUpstreamModel(model string) string {
	model = strings.TrimSpace(model)
	parsed := thinking.ParseSuffix(model)
	base := strings.TrimSpace(parsed.ModelName)
	if len(base) >= 4 && strings.HasSuffix(strings.ToLower(base), "[1m]") {
		base = base[:len(base)-len("[1m]")]
	}
	prefix := "codebuddy-"
	if len(base) > len(prefix) && strings.HasPrefix(strings.ToLower(base), prefix) {
		base = base[len(prefix):]
	}
	if parsed.HasSuffix {
		return base + "(" + parsed.RawSuffix + ")"
	}
	return base
}

// defaultIntlSystemMessage is injected when a request to the international
// deployment carries no leading system message. Unlike the CN deployment, the
// international upstream rejects conversations whose first message is not a
// system prompt (envelope code 11128).
const defaultIntlSystemMessage = "You are a helpful assistant."

// ensureLeadingSystemMessage prepends a default system message for
// international-deployment requests whose first message is not a system
// prompt. CN requests are returned unchanged.
func (e *CodeBuddyExecutor) ensureLeadingSystemMessage(body []byte) []byte {
	if e.region == nil || e.region.Provider != codebuddyauth.ProviderIntl {
		return body
	}
	messages := gjson.GetBytes(body, "messages")
	if messages.IsArray() {
		firstRole := strings.ToLower(strings.TrimSpace(messages.Array()[0].Get("role").String()))
		if len(messages.Array()) > 0 && firstRole == "system" {
			return body
		}
	}
	newMessages := make([]any, 0, len(messages.Array())+1)
	newMessages = append(newMessages, map[string]any{"role": "system", "content": defaultIntlSystemMessage})
	for _, m := range messages.Array() {
		newMessages = append(newMessages, json.RawMessage(m.Raw))
	}
	updated, errSet := sjson.SetBytes(body, "messages", newMessages)
	if errSet != nil {
		return body
	}
	return updated
}

// PrepareRequest injects CodeBuddy credentials into the outgoing HTTP request.
func (e *CodeBuddyExecutor) PrepareRequest(req *http.Request, auth *cliproxyauth.Auth) error {
	if req == nil {
		return nil
	}
	if token := codebuddyCreds(auth); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	var attrs map[string]string
	if auth != nil {
		attrs = auth.Attributes
	}
	util.ApplyCustomHeadersFromAttrs(req, attrs)
	return nil
}

// HttpRequest injects CodeBuddy credentials into the request and executes it.
func (e *CodeBuddyExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("codebuddy executor: request is nil")
	}
	if ctx == nil {
		ctx = req.Context()
	}
	httpReq := req.WithContext(ctx)
	if err := e.PrepareRequest(httpReq, auth); err != nil {
		return nil, err
	}
	httpClient := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	return httpClient.Do(httpReq)
}

// buildCodeBuddyChatRequest translates the inbound payload into an OpenAI chat
// completions body and prepares the upstream HTTP request with the headers the
// CodeBuddy endpoint requires.
func (e *CodeBuddyExecutor) buildCodeBuddyChatRequest(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, stream bool) (*http.Request, []byte, error) {
	from := opts.SourceFormat
	to := sdktranslator.FormatOpenAI
	baseModel := thinking.ParseSuffix(req.Model).ModelName

	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalTranslated := helps.TranslateRequestWithCodexMultiAgentV2(ctx, opts.Headers, e.cfg, from, to, baseModel, bytes.Clone(originalPayloadSource), stream)
	body := helps.TranslateRequestWithCodexMultiAgentV2(ctx, opts.Headers, e.cfg, from, to, baseModel, bytes.Clone(req.Payload), stream)

	body, errSet := sjson.SetBytes(body, "model", normalizeCodeBuddyUpstreamModel(baseModel))
	if errSet != nil {
		return nil, nil, fmt.Errorf("codebuddy executor: failed to set model in payload: %w", errSet)
	}
	// OpenAI-to-OpenAI translation passes the client's stream flag through, so
	// force it to match the requested mode; the international deployment is
	// stream-only and its non-stream requests are executed as streams.
	if stream {
		if body, errSet = sjson.SetBytes(body, "stream", true); errSet != nil {
			return nil, nil, fmt.Errorf("codebuddy executor: failed to set stream flag: %w", errSet)
		}
	}

	body, err := helps.ApplyThinkingWithSourcePayload(body, req.Payload, originalPayloadSource, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return nil, nil, err
	}

	body = e.ensureLeadingSystemMessage(body)

	if stream {
		body, errSet = sjson.SetBytes(body, "stream_options.include_usage", true)
		if errSet != nil {
			return nil, nil, fmt.Errorf("codebuddy executor: failed to set stream_options in payload: %w", errSet)
		}
	}

	requestedModel := helps.PayloadRequestedModel(opts, req.Model)
	requestPath := helps.PayloadRequestPath(opts)
	body = helps.ApplyPayloadConfigWithRequest(e.cfg, baseModel, to.String(), from.String(), "", body, originalTranslated, requestedModel, requestPath, opts.Headers)

	// The upstream content filter rejects vendor identity phrases in system
	// prompts; rewrite them before sending.
	if sanitized, changed, sanitizeErr := codebuddyauth.SanitizeForContentFilter(body, nil); sanitizeErr != nil {
		log.WithError(sanitizeErr).Warn("codebuddy executor: system prompt sanitize failed, sending original payload")
	} else if changed {
		body = sanitized
	}

	url := codebuddyauth.BuildChatCompletionsURL(codebuddyBaseURL(auth, e.region))
	httpReq, errNew := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if errNew != nil {
		return nil, nil, errNew
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if stream {
		httpReq.Header.Set("Accept", "text/event-stream")
	} else {
		httpReq.Header.Set("Accept", "application/json")
	}
	if token := codebuddyCreds(auth); token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}
	e.region.ApplyChatHeaders(httpReq, codebuddyUID(auth))
	var attrs map[string]string
	if auth != nil {
		attrs = auth.Attributes
	}
	util.ApplyCustomHeadersFromAttrs(httpReq, attrs)
	return httpReq, body, nil
}

// Execute performs a non-streaming chat completion request to CodeBuddy.
// The international deployment only supports streaming, so non-stream
// requests are executed as upstream streams and aggregated into a single
// chat.completion payload.
func (e *CodeBuddyExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (resp cliproxyexecutor.Response, err error) {
	baseModel := thinking.ParseSuffix(req.Model).ModelName
	reporter := helps.NewExecutorUsageReporter(ctx, e, baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	if e.region.Provider == codebuddyauth.ProviderIntl {
		return e.executeIntlAggregated(ctx, auth, req, opts, reporter)
	}

	httpReq, body, err := e.buildCodeBuddyChatRequest(ctx, auth, req, opts, false)
	if err != nil {
		return resp, err
	}

	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	helps.RecordAPIRequest(ctx, e.cfg, helps.UpstreamRequestLog{
		URL:       httpReq.URL.String(),
		Method:    http.MethodPost,
		Headers:   httpReq.Header.Clone(),
		Body:      body,
		Provider:  e.Identifier(),
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
	})

	httpClient := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	httpClient = reporter.TrackHTTPClient(httpClient)
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	defer func() {
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("codebuddy executor: close response body error: %v", errClose)
		}
	}()
	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		b, _ := io.ReadAll(httpResp.Body)
		helps.AppendAPIResponseChunk(ctx, e.cfg, b)
		helps.LogWithRequestID(ctx).Debugf("request error, error status: %d, error message: %s", httpResp.StatusCode, helps.SummarizeErrorBody(httpResp.Header.Get("Content-Type"), b))
		err = statusErr{code: httpResp.StatusCode, msg: string(b)}
		return resp, err
	}
	data, err := io.ReadAll(httpResp.Body)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	helps.AppendAPIResponseChunk(ctx, e.cfg, data)
	reporter.Publish(ctx, helps.ParseOpenAIUsage(data))

	to := sdktranslator.FormatOpenAI
	responseFormat := cliproxyexecutor.ResponseFormatOrSource(opts)
	var param any
	out := sdktranslator.TranslateNonStream(ctx, to, responseFormat, req.Model, opts.OriginalRequest, body, data, &param)
	if responseFormat == sdktranslator.FormatOpenAIResponse {
		out = helps.EnsureResponsesUsageDetails(out)
	}
	resp = cliproxyexecutor.Response{Payload: out, Headers: httpResp.Header.Clone()}
	return resp, nil
}

// executeIntlAggregated serves a non-stream request against the
// stream-only international upstream: it requests an SSE stream, merges the
// deltas into a single chat.completion payload, and translates that payload
// through the regular non-stream path.
func (e *CodeBuddyExecutor) executeIntlAggregated(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, reporter *helps.UsageReporter) (resp cliproxyexecutor.Response, err error) {
	httpReq, body, err := e.buildCodeBuddyChatRequest(ctx, auth, req, opts, true)
	if err != nil {
		return resp, err
	}

	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	helps.RecordAPIRequest(ctx, e.cfg, helps.UpstreamRequestLog{
		URL:       httpReq.URL.String(),
		Method:    http.MethodPost,
		Headers:   httpReq.Header.Clone(),
		Body:      body,
		Provider:  e.Identifier(),
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
	})

	httpClient := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	httpClient = reporter.TrackHTTPClient(httpClient)
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	defer func() {
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("codebuddy executor: close response body error: %v", errClose)
		}
	}()
	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		b, _ := io.ReadAll(httpResp.Body)
		helps.AppendAPIResponseChunk(ctx, e.cfg, b)
		helps.LogWithRequestID(ctx).Debugf("request error, error status: %d, error message: %s", httpResp.StatusCode, helps.SummarizeErrorBody(httpResp.Header.Get("Content-Type"), b))
		err = statusErr{code: httpResp.StatusCode, msg: string(b)}
		return resp, err
	}
	data, err := aggregateIntlStream(httpResp.Body)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	helps.AppendAPIResponseChunk(ctx, e.cfg, data)
	reporter.Publish(ctx, helps.ParseOpenAIUsage(data))

	to := sdktranslator.FormatOpenAI
	responseFormat := cliproxyexecutor.ResponseFormatOrSource(opts)
	var param any
	out := sdktranslator.TranslateNonStream(ctx, to, responseFormat, req.Model, opts.OriginalRequest, body, data, &param)
	if responseFormat == sdktranslator.FormatOpenAIResponse {
		out = helps.EnsureResponsesUsageDetails(out)
	}
	resp = cliproxyexecutor.Response{Payload: out, Headers: httpResp.Header.Clone()}
	return resp, nil
}

// intlAggregatedToolCall accumulates the streamed deltas of a single tool call.
type intlAggregatedToolCall struct {
	ID        string
	Type      string
	Name      string
	Arguments strings.Builder
}

// aggregateIntlStream reads an OpenAI-format SSE chunk stream and merges it
// into a single non-stream chat.completion payload. It is used by the
// international deployment, whose chat endpoint rejects non-stream requests.
func aggregateIntlStream(r io.Reader) ([]byte, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(nil, 1_048_576)
	var (
		id            string
		model         string
		created       int64
		role          string
		finishReason  string
		content       strings.Builder
		reasoning     strings.Builder
		toolCallOrder []int
		toolCalls     = make(map[int]*intlAggregatedToolCall)
		usage         json.RawMessage
	)
	for scanner.Scan() {
		line := scanner.Bytes()
		if isCodeBuddySSEHeartbeat(line) {
			continue
		}
		payload, ok := bytes.CutPrefix(bytes.TrimSpace(line), []byte("data:"))
		if !ok {
			continue
		}
		payload = bytes.TrimSpace(payload)
		if bytes.Equal(payload, []byte("[DONE]")) {
			break
		}
		var chunk struct {
			ID      string `json:"id"`
			Object  string `json:"object"`
			Model   string `json:"model"`
			Created int64  `json:"created"`
			Choices []struct {
				Delta struct {
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
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
			Usage json.RawMessage `json:"usage"`
		}
		if err := json.Unmarshal(payload, &chunk); err != nil {
			continue
		}
		if chunk.ID != "" && id == "" {
			id = chunk.ID
		}
		if chunk.Model != "" {
			model = chunk.Model
		}
		if chunk.Created != 0 && created == 0 {
			created = chunk.Created
		}
		for _, choice := range chunk.Choices {
			if choice.Delta.Role != "" {
				role = choice.Delta.Role
			}
			content.WriteString(choice.Delta.Content)
			reasoning.WriteString(choice.Delta.ReasoningContent)
			for _, tc := range choice.Delta.ToolCalls {
				existing, found := toolCalls[tc.Index]
				if !found {
					existing = &intlAggregatedToolCall{}
					toolCalls[tc.Index] = existing
					toolCallOrder = append(toolCallOrder, tc.Index)
				}
				if tc.ID != "" {
					existing.ID = tc.ID
				}
				if tc.Type != "" {
					existing.Type = tc.Type
				}
				if tc.Function.Name != "" {
					existing.Name = tc.Function.Name
				}
				existing.Arguments.WriteString(tc.Function.Arguments)
			}
			if choice.FinishReason != "" {
				finishReason = choice.FinishReason
			}
		}
		if len(chunk.Usage) > 0 && !bytes.Equal(chunk.Usage, []byte("null")) {
			usage = chunk.Usage
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("codebuddy executor: read intl stream: %w", err)
	}

	if role == "" {
		role = "assistant"
	}
	if finishReason == "" {
		finishReason = "stop"
	}
	message := map[string]any{"role": role}
	if content.Len() > 0 {
		message["content"] = content.String()
	}
	if reasoning.Len() > 0 {
		message["reasoning_content"] = reasoning.String()
	}
	if len(toolCallOrder) > 0 {
		sort.Ints(toolCallOrder)
		tools := make([]map[string]any, 0, len(toolCallOrder))
		for _, idx := range toolCallOrder {
			tc := toolCalls[idx]
			tools = append(tools, map[string]any{
				"id":   tc.ID,
				"type": tc.Type,
				"function": map[string]any{
					"name":      tc.Name,
					"arguments": tc.Arguments.String(),
				},
			})
		}
		message["tool_calls"] = tools
	}
	if len(usage) == 0 {
		usage = json.RawMessage(`{"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}`)
	}
	out := map[string]any{
		"id":      id,
		"object":  "chat.completion",
		"created": created,
		"model":   model,
		"choices": []any{map[string]any{
			"index":         0,
			"message":       message,
			"finish_reason": finishReason,
		}},
		"usage": usage,
	}
	data, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("codebuddy executor: encode intl aggregated response: %w", err)
	}
	return data, nil
}

// ExecuteStream performs a streaming chat completion request to CodeBuddy.
func (e *CodeBuddyExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (_ *cliproxyexecutor.StreamResult, err error) {
	baseModel := thinking.ParseSuffix(req.Model).ModelName
	reporter := helps.NewExecutorUsageReporter(ctx, e, baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	httpReq, body, err := e.buildCodeBuddyChatRequest(ctx, auth, req, opts, true)
	if err != nil {
		return nil, err
	}

	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	helps.RecordAPIRequest(ctx, e.cfg, helps.UpstreamRequestLog{
		URL:       httpReq.URL.String(),
		Method:    http.MethodPost,
		Headers:   httpReq.Header.Clone(),
		Body:      body,
		Provider:  e.Identifier(),
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
	})

	httpClient := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	httpClient = reporter.TrackHTTPClient(httpClient)
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return nil, err
	}
	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		b, _ := io.ReadAll(httpResp.Body)
		helps.AppendAPIResponseChunk(ctx, e.cfg, b)
		helps.LogWithRequestID(ctx).Debugf("request error, error status: %d, error message: %s", httpResp.StatusCode, helps.SummarizeErrorBody(httpResp.Header.Get("Content-Type"), b))
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("codebuddy executor: close response body error: %v", errClose)
		}
		err = statusErr{code: httpResp.StatusCode, msg: string(b)}
		return nil, err
	}

	to := sdktranslator.FormatOpenAI
	responseFormat := cliproxyexecutor.ResponseFormatOrSource(opts)
	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(out)
		defer func() {
			if errClose := httpResp.Body.Close(); errClose != nil {
				log.Errorf("codebuddy executor: close response body error: %v", errClose)
			}
		}()
		scanner := bufio.NewScanner(httpResp.Body)
		scanner.Buffer(nil, 1_048_576) // 1MB
		claudeInputTokens := helps.NewClaudeInputTokenState(opts.SourceFormat, to, responseFormat, bytes.Clone(opts.OriginalRequest))
		var param any
		var streamUsage helps.StreamUsageBuffer
		defer streamUsage.Publish(ctx, reporter)
		for scanner.Scan() {
			line := scanner.Bytes()
			// The upstream emits keep-alive comment lines (": heartbeat") that
			// are not JSON; strict downstream SSE parsers reject them, so drop
			// these lines before translating.
			if isCodeBuddySSEHeartbeat(line) {
				continue
			}
			helps.AppendAPIResponseChunk(ctx, e.cfg, line)
			streamUsage.ObserveOpenAIStream(line)
			chunks := helps.TranslateStreamWithClaudeInputTokens(ctx, to, responseFormat, req.Model, opts.OriginalRequest, body, bytes.Clone(line), &param, claudeInputTokens)
			for i := range chunks {
				select {
				case out <- cliproxyexecutor.StreamChunk{Payload: chunks[i]}:
				case <-ctx.Done():
					return
				}
			}
		}
		doneChunks := helps.TranslateStreamWithClaudeInputTokens(ctx, to, responseFormat, req.Model, opts.OriginalRequest, body, []byte("[DONE]"), &param, claudeInputTokens)
		for i := range doneChunks {
			select {
			case out <- cliproxyexecutor.StreamChunk{Payload: doneChunks[i]}:
			case <-ctx.Done():
				return
			}
		}
		if errScan := scanner.Err(); errScan != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, errScan)
			reporter.PublishFailure(ctx, errScan)
			select {
			case out <- cliproxyexecutor.StreamChunk{Err: errScan}:
			case <-ctx.Done():
			}
		}
	}()
	return &cliproxyexecutor.StreamResult{Headers: httpResp.Header.Clone(), Chunks: out}, nil
}

// CountTokens estimates the token count locally; the upstream has no count endpoint.
func (e *CodeBuddyExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	baseModel := thinking.ParseSuffix(req.Model).ModelName

	from := opts.SourceFormat
	responseFormat := cliproxyexecutor.ResponseFormatOrSource(opts)
	to := sdktranslator.FormatOpenAI
	translated := helps.TranslateRequestWithCodexMultiAgentV2(ctx, opts.Headers, e.cfg, from, to, baseModel, req.Payload, false)

	translated, err := helps.ApplyRequestThinking(translated, req, opts, from.String(), to.String(), e.Identifier())
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}

	enc, err := helps.TokenizerForModel(baseModel)
	if err != nil {
		return cliproxyexecutor.Response{}, fmt.Errorf("codebuddy executor: tokenizer init failed: %w", err)
	}

	count, err := helps.CountOpenAIChatTokens(enc, translated)
	if err != nil {
		return cliproxyexecutor.Response{}, fmt.Errorf("codebuddy executor: token counting failed: %w", err)
	}

	usageJSON := helps.BuildOpenAIUsageJSON(count)
	translatedUsage := sdktranslator.TranslateTokenCount(ctx, to, responseFormat, count, usageJSON)
	return cliproxyexecutor.Response{Payload: translatedUsage}, nil
}

// Refresh rotates the OAuth tokens and re-syncs the account's available models.
func (e *CodeBuddyExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	log.Debugf("codebuddy executor: refresh called")
	if refreshed, handled, err := helps.RefreshAuthViaHome(ctx, e.cfg, auth); handled {
		return refreshed, err
	}
	if auth == nil {
		return nil, fmt.Errorf("codebuddy executor: auth is nil")
	}
	refreshToken := ""
	if auth.Metadata != nil {
		if v, ok := auth.Metadata["refresh_token"].(string); ok {
			refreshToken = strings.TrimSpace(v)
		}
	}
	if refreshToken == "" {
		// Nothing to refresh.
		return auth, nil
	}

	client := codebuddyauth.NewClientForRegion(e.cfg, auth.ProxyURL, e.region)
	token, err := client.RefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["access_token"] = token.AccessToken
	if token.RefreshToken != "" {
		auth.Metadata["refresh_token"] = token.RefreshToken
	}
	if token.TokenType != "" {
		auth.Metadata["token_type"] = token.TokenType
	}
	if token.Domain != "" {
		auth.Metadata["domain"] = token.Domain
	}
	if expiresAt := token.ExpiresAt(); expiresAt > 0 {
		auth.Metadata["expired"] = time.Unix(expiresAt, 0).UTC().Format(time.RFC3339)
	}
	auth.Metadata["type"] = e.region.Provider
	auth.Metadata["last_refresh"] = time.Now().Format(time.RFC3339)

	// Re-sync the account's available models; keep the previous list on failure.
	uid := ""
	if v, ok := auth.Metadata["uid"].(string); ok {
		uid = strings.TrimSpace(v)
	}
	if configData, cfgErr := client.FetchConfig(ctx, token.AccessToken, uid); cfgErr != nil {
		log.WithError(cfgErr).Debugf("codebuddy executor: model config refresh failed for %s", auth.ID)
	} else if models, parseErr := codebuddyauth.ParseModels(configData); parseErr != nil {
		log.WithError(parseErr).Debugf("codebuddy executor: model config parse failed for %s", auth.ID)
	} else if len(models) > 0 {
		ids := make([]string, 0, len(models))
		for _, m := range models {
			ids = append(ids, m.ID)
		}
		auth.Metadata["enabled_models"] = ids
		if raw, marshalErr := json.Marshal(models); marshalErr == nil {
			auth.Metadata["models_meta"] = string(raw)
		}
	}
	return auth, nil
}

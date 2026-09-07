package executor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	dimagentauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/dimagent"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/sjson"
)

// DimAgentExecutor is a stateless executor for the DimAgent (dimagent.cn)
// service. The upstream speaks the OpenAI chat completions protocol at
// /v1/chat/completions and authenticates with an OAuth access token obtained
// through the authorization code + PKCE flow.
type DimAgentExecutor struct {
	cfg *config.Config
}

// NewDimAgentExecutor creates a new DimAgent executor.
func NewDimAgentExecutor(cfg *config.Config) *DimAgentExecutor {
	return &DimAgentExecutor{cfg: cfg}
}

// Identifier returns the executor identifier.
func (e *DimAgentExecutor) Identifier() string { return dimagentauth.ProviderKey }

// RequestToFormat reports the upstream request format: OpenAI chat completions.
func (e *DimAgentExecutor) RequestToFormat(_ cliproxyexecutor.Request, _ cliproxyexecutor.Options) sdktranslator.Format {
	return sdktranslator.FormatOpenAI
}

// dimAgentCreds extracts the access token from an auth record. OAuth tokens
// live in metadata; a manually provisioned token may appear in attributes.
func dimAgentCreds(a *cliproxyauth.Auth) string {
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

// dimAgentBaseURL resolves the upstream base URL, allowing a per-auth override.
func dimAgentBaseURL(a *cliproxyauth.Auth) string {
	if a != nil && a.Attributes != nil {
		if base := strings.TrimSpace(a.Attributes["base_url"]); base != "" {
			return base
		}
	}
	return dimagentauth.DefaultBaseURL
}

// normalizeDimAgentUpstreamModel returns the upstream model ID by stripping
// the CLIProxyAPI "dimagent-" prefix while preserving a trailing thinking
// suffix (e.g. "(high)").
func normalizeDimAgentUpstreamModel(model string) string {
	parsed := thinking.ParseSuffix(model)
	base := strings.TrimSpace(parsed.ModelName)
	base = dimagentauth.NormalizeUpstreamModel(base)
	if parsed.HasSuffix {
		return base + "(" + parsed.RawSuffix + ")"
	}
	return base
}

// applyDimAgentHeaders sets the identity headers the DimAgent upstream expects.
func applyDimAgentHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", dimagentauth.ChatUserAgent)
	req.Header.Set("x-title", dimagentauth.TitleChat)
}

// buildDimAgentChatRequest translates the inbound payload into an OpenAI chat
// completions body and prepares the upstream HTTP request with the headers the
// DimAgent endpoint requires.
func (e *DimAgentExecutor) buildDimAgentChatRequest(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, stream bool) (*http.Request, []byte, error) {
	from := opts.SourceFormat
	to := sdktranslator.FormatOpenAI
	baseModel := thinking.ParseSuffix(req.Model).ModelName

	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalTranslated := helps.TranslateRequestWithCodexMultiAgentV2(ctx, opts.Headers, e.cfg, from, to, baseModel, bytes.Clone(originalPayloadSource), stream)
	body := helps.TranslateRequestWithCodexMultiAgentV2(ctx, opts.Headers, e.cfg, from, to, baseModel, bytes.Clone(req.Payload), stream)

	body, errSet := sjson.SetBytes(body, "model", normalizeDimAgentUpstreamModel(baseModel))
	if errSet != nil {
		return nil, nil, fmt.Errorf("dimagent executor: failed to set model in payload: %w", errSet)
	}

	body, err := helps.ApplyThinkingWithSourcePayload(body, req.Payload, originalPayloadSource, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return nil, nil, err
	}

	if stream {
		body, errSet = sjson.SetBytes(body, "stream_options.include_usage", true)
		if errSet != nil {
			return nil, nil, fmt.Errorf("dimagent executor: failed to set stream_options in payload: %w", errSet)
		}
	}

	requestedModel := helps.PayloadRequestedModel(opts, req.Model)
	requestPath := helps.PayloadRequestPath(opts)
	body = helps.ApplyPayloadConfigWithRequest(e.cfg, baseModel, to.String(), from.String(), "", body, originalTranslated, requestedModel, requestPath, opts.Headers)

	httpReq, errNew := http.NewRequestWithContext(ctx, http.MethodPost, dimagentauth.BuildChatCompletionsURL(dimAgentBaseURL(auth)), bytes.NewReader(body))
	if errNew != nil {
		return nil, nil, errNew
	}
	if stream {
		httpReq.Header.Set("Accept", "text/event-stream")
	} else {
		httpReq.Header.Set("Accept", "application/json")
	}
	if token := dimAgentCreds(auth); token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}
	applyDimAgentHeaders(httpReq)
	var attrs map[string]string
	if auth != nil {
		attrs = auth.Attributes
	}
	util.ApplyCustomHeadersFromAttrs(httpReq, attrs)
	return httpReq, body, nil
}

// PrepareRequest injects DimAgent credentials into the outgoing HTTP request.
func (e *DimAgentExecutor) PrepareRequest(req *http.Request, auth *cliproxyauth.Auth) error {
	if req == nil {
		return nil
	}
	if token := dimAgentCreds(auth); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	var attrs map[string]string
	if auth != nil {
		attrs = auth.Attributes
	}
	util.ApplyCustomHeadersFromAttrs(req, attrs)
	return nil
}

// HttpRequest injects DimAgent credentials into the request and executes it.
func (e *DimAgentExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("dimagent executor: request is nil")
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

// Execute performs a non-streaming chat completion request to DimAgent.
func (e *DimAgentExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (resp cliproxyexecutor.Response, err error) {
	baseModel := thinking.ParseSuffix(req.Model).ModelName
	reporter := helps.NewExecutorUsageReporter(ctx, e, baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	httpReq, body, err := e.buildDimAgentChatRequest(ctx, auth, req, opts, false)
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
			log.Errorf("dimagent executor: close response body error: %v", errClose)
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

// ExecuteStream performs a streaming chat completion request to DimAgent.
func (e *DimAgentExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (_ *cliproxyexecutor.StreamResult, err error) {
	baseModel := thinking.ParseSuffix(req.Model).ModelName
	reporter := helps.NewExecutorUsageReporter(ctx, e, baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	httpReq, body, err := e.buildDimAgentChatRequest(ctx, auth, req, opts, true)
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
			log.Errorf("dimagent executor: close response body error: %v", errClose)
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
				log.Errorf("dimagent executor: close response body error: %v", errClose)
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
func (e *DimAgentExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
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
		return cliproxyexecutor.Response{}, fmt.Errorf("dimagent executor: tokenizer init failed: %w", err)
	}

	count, err := helps.CountOpenAIChatTokens(enc, translated)
	if err != nil {
		return cliproxyexecutor.Response{}, fmt.Errorf("dimagent executor: token counting failed: %w", err)
	}

	usageJSON := helps.BuildOpenAIUsageJSON(count)
	translatedUsage := sdktranslator.TranslateTokenCount(ctx, to, responseFormat, count, usageJSON)
	return cliproxyexecutor.Response{Payload: translatedUsage}, nil
}

// Refresh rotates the OAuth tokens and re-syncs the account's available models.
func (e *DimAgentExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	log.Debugf("dimagent executor: refresh called")
	if refreshed, handled, err := helps.RefreshAuthViaHome(ctx, e.cfg, auth); handled {
		return refreshed, err
	}
	if auth == nil {
		return nil, fmt.Errorf("dimagent executor: auth is nil")
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

	client := dimagentauth.NewClient(e.cfg, auth.ProxyURL)
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
	if token.Scope != "" {
		auth.Metadata["scope"] = token.Scope
	}
	auth.Metadata["expired"] = token.ExpirationTime().UTC().Format(time.RFC3339)
	auth.Metadata["type"] = dimagentauth.ProviderKey
	auth.Metadata["last_refresh"] = time.Now().Format(time.RFC3339)

	// Re-sync the account's available models; keep the previous list on failure.
	if modelsData, modelsErr := client.FetchModels(ctx, token.AccessToken); modelsErr != nil {
		log.WithError(modelsErr).Debugf("dimagent executor: models refresh failed for %s", auth.ID)
	} else if models, parseErr := dimagentauth.ParseModels(modelsData); parseErr != nil {
		log.WithError(parseErr).Debugf("dimagent executor: models parse failed for %s", auth.ID)
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

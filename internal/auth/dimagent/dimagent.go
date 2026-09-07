// Package dimagent provides authentication and token management for the
// DimAgent (dimagent.cn) AI service. The upstream authenticates through a
// standard OAuth 2.0 authorization code flow with PKCE (fixed public client
// and a localhost:54321 redirect URI) and exposes an OpenAI-compatible chat
// completions endpoint at /v1/chat/completions.
package dimagent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	log "github.com/sirupsen/logrus"
)

const (
	// ProviderKey is the provider identifier used across the gateway.
	ProviderKey = "dimagent"

	// DefaultBaseURL is the default upstream base URL of the DimAgent API.
	DefaultBaseURL = "https://dimagent.cn"

	// AuthEndpointPath is the OAuth authorization endpoint path.
	AuthEndpointPath = "/oauth/authorize"
	// TokenEndpointPath is the OAuth token endpoint path.
	TokenEndpointPath = "/oauth/token"
	// ModelsPath is the model listing endpoint path (dim-scoped models).
	ModelsPath = "/v1/models?type=dim"
	// ChatCompletionsPath is the OpenAI-compatible chat completions endpoint path.
	ChatCompletionsPath = "/v1/chat/completions"

	// ClientID is the public OAuth client id registered for the desktop app.
	ClientID = "f025fda6d5014fd2b6d4aba45cd8b2b6"
	// RedirectURI is the fixed callback URI registered for the public client.
	// The upstream validates this value, so it cannot be overridden per run.
	RedirectURI = "http://localhost:54321/auth/callback"
	// CallbackPort is the fixed OAuth callback port derived from RedirectURI.
	CallbackPort = 54321
	// Scope is the OAuth scope requested during authorization.
	Scope = "openid profile email market.read remote:delegate"
	// SourceParam is the extra authorize query parameter the upstream expects.
	SourceParam = "app"

	// DesktopUserAgent is the User-Agent expected by the OAuth and model endpoints.
	DesktopUserAgent = "DimAgent-Desktop"
	// ChatUserAgent is the User-Agent observed on chat completions requests.
	ChatUserAgent = "DimAgent/0.9.21"
	// TitleDesktop is the X-Title header value used by the desktop client.
	TitleDesktop = "DimAgent"
	// TitleChat is the x-title header value observed on chat completions requests.
	TitleChat = "DimCode"
	// RefererURL is the HTTP-Referer header value used by the desktop client.
	RefererURL = "https://dimagent.com/"

	// defaultAccessTokenTTL is used when the upstream omits expires_in.
	defaultAccessTokenTTL = 7 * 24 * time.Hour
)

// TokenResponse represents the token payload returned by the OAuth token
// endpoint (authorization code exchange and refresh grant).
type TokenResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	Scope        string `json:"scope,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
}

// ExpirationTime computes the absolute expiration timestamp of the access
// token from expires_in (seconds since now). It falls back to the observed
// seven-day TTL when the upstream omits the field.
func (t *TokenResponse) ExpirationTime() time.Time {
	ttl := time.Duration(t.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = defaultAccessTokenTTL
	}
	return time.Now().Add(ttl)
}

// Client talks to the DimAgent OAuth endpoints and API.
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// NewClient creates a DimAgent client. proxyURL, when non-empty, takes
// precedence over cfg.ProxyURL.
func NewClient(cfg *config.Config, proxyURL string) *Client {
	client := &http.Client{}
	effectiveProxyURL := strings.TrimSpace(proxyURL)
	var sdkCfg config.SDKConfig
	if cfg != nil {
		sdkCfg = cfg.SDKConfig
		if effectiveProxyURL == "" {
			effectiveProxyURL = strings.TrimSpace(cfg.ProxyURL)
		}
	}
	sdkCfg.ProxyURL = effectiveProxyURL
	util.SetProxy(&sdkCfg, client)
	return &Client{
		httpClient: client,
		baseURL:    DefaultBaseURL,
	}
}

// effectiveBaseURL normalizes a base URL override and falls back to the default.
func effectiveBaseURL(override string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(override), "/")
	if trimmed == "" {
		return DefaultBaseURL
	}
	return trimmed
}

// BuildAuthEndpointURL returns the OAuth authorization endpoint URL.
func BuildAuthEndpointURL(baseURL string) string {
	return effectiveBaseURL(baseURL) + AuthEndpointPath
}

// BuildTokenEndpointURL returns the OAuth token endpoint URL.
func BuildTokenEndpointURL(baseURL string) string {
	return effectiveBaseURL(baseURL) + TokenEndpointPath
}

// BuildModelsURL returns the model listing URL.
func BuildModelsURL(baseURL string) string {
	return effectiveBaseURL(baseURL) + ModelsPath
}

// BuildChatCompletionsURL returns the chat completions URL.
func BuildChatCompletionsURL(baseURL string) string {
	return effectiveBaseURL(baseURL) + ChatCompletionsPath
}

// GenerateAuthURL constructs the OAuth authorization URL for the browser flow.
func (c *Client) GenerateAuthURL(state string, pkce *PKCECodes) (string, error) {
	if pkce == nil || strings.TrimSpace(pkce.CodeChallenge) == "" {
		return "", fmt.Errorf("dimagent: pkce codes are required")
	}
	if strings.TrimSpace(state) == "" {
		return "", fmt.Errorf("dimagent: state is required")
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", ClientID)
	q.Set("redirect_uri", RedirectURI)
	q.Set("scope", Scope)
	q.Set("code_challenge", pkce.CodeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	q.Set("source", SourceParam)
	return BuildAuthEndpointURL(c.baseURL) + "?" + q.Encode(), nil
}

// applyOAuthHeaders sets the headers the DimAgent OAuth token endpoint expects.
func applyOAuthHeaders(h http.Header) {
	h.Set("Content-Type", "application/x-www-form-urlencoded")
	h.Set("Accept", "*/*")
	h.Set("User-Agent", DesktopUserAgent)
	h.Set("X-Title", TitleDesktop)
	h.Set("HTTP-Referer", RefererURL)
}

// decodeTokenResponse reads and decodes the OAuth token endpoint response.
func decodeTokenResponse(resp *http.Response, action string) (*TokenResponse, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("dimagent %s: read response: %w", action, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("dimagent %s: HTTP %d: %s", action, resp.StatusCode, sanitizeErrorBody(body))
	}
	var token TokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("dimagent %s: invalid json: %w", action, err)
	}
	if strings.TrimSpace(token.AccessToken) == "" {
		return nil, fmt.Errorf("dimagent %s: missing access_token: %s", action, sanitizeErrorBody(body))
	}
	return &token, nil
}

// sanitizeErrorBody trims and truncates an upstream error body for logging.
func sanitizeErrorBody(body []byte) string {
	s := strings.TrimSpace(string(body))
	if len(s) > 512 {
		s = s[:512] + "..."
	}
	return s
}

// ExchangeCodeForTokens exchanges an authorization code for OAuth tokens using
// the PKCE code verifier.
func (c *Client) ExchangeCodeForTokens(ctx context.Context, code string, pkce *PKCECodes) (*TokenResponse, error) {
	if strings.TrimSpace(code) == "" {
		return nil, fmt.Errorf("dimagent: code is required")
	}
	if pkce == nil || strings.TrimSpace(pkce.CodeVerifier) == "" {
		return nil, fmt.Errorf("dimagent: pkce codes are required")
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", RedirectURI)
	form.Set("client_id", ClientID)
	form.Set("code_verifier", pkce.CodeVerifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, BuildTokenEndpointURL(c.baseURL), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("dimagent: build exchange request: %w", err)
	}
	applyOAuthHeaders(req.Header)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dimagent exchange request failed: %w", err)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("dimagent exchange: close body error: %v", errClose)
		}
	}()
	return decodeTokenResponse(resp, "token exchange")
}

// RefreshToken exchanges a refresh token for a fresh token pair.
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return nil, fmt.Errorf("dimagent: refresh token is required")
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", ClientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, BuildTokenEndpointURL(c.baseURL), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("dimagent: build refresh request: %w", err)
	}
	// Match the desktop client's refresh request exactly (observed in the
	// shipped Electron build): it identifies as the DimCode service and sends
	// only the referer, not the desktop User-Agent/Accept used for the code
	// exchange.
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HTTP-Referer", RefererURL)
	req.Header.Set("X-Title", TitleChat)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dimagent refresh request failed: %w", err)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("dimagent refresh: close body error: %v", errClose)
		}
	}()
	return decodeTokenResponse(resp, "token refresh")
}

// FetchModels retrieves the raw JSON model listing for the authenticated account.
func (c *Client) FetchModels(ctx context.Context, accessToken string) ([]byte, error) {
	if strings.TrimSpace(accessToken) == "" {
		return nil, fmt.Errorf("dimagent: access token is required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, BuildModelsURL(c.baseURL), nil)
	if err != nil {
		return nil, fmt.Errorf("dimagent: build models request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("User-Agent", DesktopUserAgent)
	req.Header.Set("X-Title", TitleDesktop)
	req.Header.Set("HTTP-Referer", RefererURL)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dimagent models request failed: %w", err)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("dimagent models: close body error: %v", errClose)
		}
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("dimagent models: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("dimagent models: HTTP %d: %s", resp.StatusCode, sanitizeErrorBody(body))
	}
	return body, nil
}

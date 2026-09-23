package qoder

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// DeviceTokenResponse is the dt- device token payload.
type DeviceTokenResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	UserID       string `json:"user_id"`
}

// JobTokenResponse is the jt- task token payload.
type JobTokenResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

// RefreshJobToken exchanges a job refresh token for a new job token pair.
func RefreshJobToken(ctx context.Context, client *http.Client, endpoint, refreshToken string) (*JobTokenResponse, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return nil, fmt.Errorf("qoder job token refresh: missing refresh token; sign in again")
	}
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	if endpoint == "" {
		endpoint = OpenAPIHost + JobTokenRefreshPath
	}
	body, err := json.Marshal(map[string]string{"refresh_token": refreshToken})
	if err != nil {
		return nil, fmt.Errorf("qoder job token refresh: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("qoder job token refresh: create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("qoder job token refresh: request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("qoder job token refresh: status %d", resp.StatusCode)
	}
	var token JobTokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&token); err != nil {
		return nil, fmt.Errorf("qoder job token refresh: decode: %w", err)
	}
	if strings.TrimSpace(token.Token) == "" {
		return nil, fmt.Errorf("qoder job token refresh: empty token in response")
	}
	if strings.TrimSpace(token.RefreshToken) == "" {
		return nil, fmt.Errorf("qoder job token refresh: empty refresh token in response")
	}
	return &token, nil
}

// OAuthDeviceFlow implements Qoder's device flow (dt- -> jt-), verified live.
type OAuthDeviceFlow struct {
	httpClient *http.Client
	clientID   string
}

// NewOAuthDeviceFlow creates a device-flow helper.
func NewOAuthDeviceFlow(cfgHTTPClient *http.Client) *OAuthDeviceFlow {
	client := cfgHTTPClient
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	return &OAuthDeviceFlow{httpClient: client, clientID: ClientID}
}

// HTTPClient returns the underlying HTTP client used by the device flow. It is
// non-nil after NewOAuthDeviceFlow, so callers can reuse it for model fetches.
func (f *OAuthDeviceFlow) HTTPClient() *http.Client {
	if f == nil || f.httpClient == nil {
		return &http.Client{Timeout: 20 * time.Second}
	}
	return f.httpClient
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

func base64URLNoPadBytes(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// AuthorizationURL returns (url, verifier, nonce) for the device flow page.
func (f *OAuthDeviceFlow) AuthorizationURL() (string, string, string, error) {
	raw, err := randomBytes(64)
	if err != nil {
		return "", "", "", fmt.Errorf("qoder auth url: random verifier: %w", err)
	}
	verifier := base64URLNoPadBytes(raw)
	challenge := base64URLNoPadBytes(sha256Digest([]byte(verifier)))
	nonce := uuid.NewString()
	params := url.Values{}
	params.Set("challenge", challenge)
	params.Set("challenge_method", "S256")
	params.Set("nonce", nonce)
	params.Set("machine_id", uuid.NewString())
	params.Set("client_id", f.clientID)
	params.Set("redirect_uri", RedirectURI)
	authURL := DeviceFlowHost + DeviceSelectAccountsPath + "?" + params.Encode()
	return authURL, verifier, nonce, nil
}

// PollDeviceToken polls deviceToken/poll until a dt- token arrives.
func (f *OAuthDeviceFlow) PollDeviceToken(ctx context.Context, nonce, verifier string, pollInterval time.Duration) (*DeviceTokenResponse, error) {
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}
	endpoint := OpenAPIHost + DeviceTokenPollPath
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("qoder device poll: %w", ctx.Err())
		default:
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("qoder device poll: create request: %w", err)
		}
		q := req.URL.Query()
		q.Set("nonce", nonce)
		q.Set("verifier", verifier)
		q.Set("challenge_method", "S256")
		req.URL.RawQuery = q.Encode()
		req.Header.Set("Accept", "application/json")

		resp, errDo := f.httpClient.Do(req)
		if errDo != nil {
			return nil, fmt.Errorf("qoder device poll: request failed: %w", errDo)
		}
		bodyBytes, errRead := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if errRead != nil {
			return nil, fmt.Errorf("qoder device poll: read response: %w", errRead)
		}
		if resp.StatusCode == http.StatusOK {
			var token DeviceTokenResponse
			if errDecode := json.Unmarshal(bodyBytes, &token); errDecode != nil {
				return nil, fmt.Errorf("qoder device poll: decode response: %w", errDecode)
			}
			if strings.TrimSpace(token.Token) != "" {
				return &token, nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("qoder device poll: %w", ctx.Err())
		case <-time.After(pollInterval):
		}
	}
}

// JobToken exchanges a dt- device token for a jt- task token.
func (f *OAuthDeviceFlow) JobToken(ctx context.Context, deviceToken string) (*JobTokenResponse, error) {
	payload := map[string]string{"clientId": f.clientID}
	rawBody, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return nil, fmt.Errorf("qoder job token: marshal: %w", errMarshal)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, OpenAPIHost+JobTokenPath, strings.NewReader(string(rawBody)))
	if err != nil {
		return nil, fmt.Errorf("qoder job token: create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+deviceToken)

	resp, errDo := f.httpClient.Do(req)
	if errDo != nil {
		return nil, fmt.Errorf("qoder job token: request failed: %w", errDo)
	}
	bodyBytes, errRead := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if errRead != nil {
		return nil, fmt.Errorf("qoder job token: read response: %w", errRead)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("qoder job token: status %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}
	var token JobTokenResponse
	if errDecode := json.Unmarshal(bodyBytes, &token); errDecode != nil {
		return nil, fmt.Errorf("qoder job token: decode: %w", errDecode)
	}
	if strings.TrimSpace(token.Token) == "" {
		return nil, fmt.Errorf("qoder job token: empty token in response")
	}
	return &token, nil
}

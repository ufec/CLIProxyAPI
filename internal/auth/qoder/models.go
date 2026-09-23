// Package qoder model discovery. Models are fetched live from
// GET /algo/api/v2/model/list?Encode=1 with COSY envelope headers, mirroring
// the Qoder desktop client. This avoids depending on the embedded models.json
// catalog, which the remote updater overwrites with a file that has no qoder
// section.
package qoder

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ModelInfo is one entry of the /algo/api/v2/model/list response "chat" list.
// Only the fields the gateway uses are retained.
type ModelInfo struct {
	Key            string  `json:"key"`
	Format         string  `json:"format,omitempty"`
	Source         string  `json:"source,omitempty"`
	Enable         bool    `json:"enable"`
	DisplayName    string  `json:"display_name,omitempty"`
	IsVL           bool    `json:"is_vl,omitempty"`
	IsReasoning    bool    `json:"is_reasoning,omitempty"`
	IsDefault      bool    `json:"is_default,omitempty"`
	PriceFactor    float64 `json:"price_factor,omitempty"`
	MaxInputTokens int     `json:"max_input_tokens,omitempty"`
	// MaxOutputTokens is populated from context_config when present.
	MaxOutputTokens int `json:"-"`
}

// FormatPriceFactorCredits formats the Qoder billing multiplier for the model UI.
// A missing price_factor decodes to zero and means the model is free.
func FormatPriceFactorCredits(priceFactor float64) string {
	return fmt.Sprintf("x%.2f credits", priceFactor)
}

// ModelsResponse is the envelope of the model listing endpoint. It carries a
// "chat" array (the primary chat models) plus other sections (assistant,
// inline, quest, ...) that the gateway does not expose.
type ModelsResponse struct {
	Chat []ModelInfo `json:"chat"`
}

// ListModelsPath is the live model listing endpoint (Encode=1 => JSON body).
const ListModelsPath = "/algo/api/v2/model/list?Encode=1"

// BuildModelsURL returns the model listing URL on the inference API host.
func BuildModelsURL(baseURL string) string {
	return strings.TrimRight(baseURL, "/") + ListModelsPath
}

// FetchModels retrieves the raw JSON model listing for the authenticated user.
// The request is signed with the same COSY envelope headers the Qoder client
// uses for every /algo API call.
func FetchModels(ctx context.Context, httpClient *http.Client, baseURL, uid, token string) ([]byte, error) {
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	if strings.TrimSpace(token) == "" || strings.TrimSpace(uid) == "" {
		return nil, fmt.Errorf("qoder: uid and token are required to fetch models")
	}
	url := BuildModelsURL(baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("qoder: build models request: %w", err)
	}
	cosyHeaders, err := BuildCosyHeaders(url, &User{UID: uid, Token: token}, "", 0)
	if err != nil {
		return nil, fmt.Errorf("qoder: build cosy headers: %w", err)
	}
	for k, v := range cosyHeaders {
		req.Header.Set(k, v)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("qoder models request failed: %w", err)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			_ = errClose
		}
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("qoder models: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("qoder models: HTTP %d: %s", resp.StatusCode, sanitizeBody(body))
	}
	return body, nil
}

func sanitizeBody(body []byte) string {
	s := strings.TrimSpace(string(body))
	if len(s) > 512 {
		s = s[:512] + "..."
	}
	return s
}

// ParseModels decodes the model listing body and returns only the chat models
// that are enabled and routable.
func ParseModels(body []byte) ([]ModelInfo, error) {
	var resp ModelsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("qoder: invalid models json: %w", err)
	}
	out := make([]ModelInfo, 0, len(resp.Chat))
	for _, m := range resp.Chat {
		if !m.Enable {
			continue
		}
		if !IsRoutableModel(m.Key) {
			continue
		}
		out = append(out, m)
	}
	return out, nil
}

// IsRoutableModel reports whether the given model key is usable as a routable
// model entry. Placeholder/aggregate entries are not routable.
func IsRoutableModel(key string) bool {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return false
	}
	if trimmed == "auto" || trimmed == "default" {
		return false
	}
	return true
}

// ID returns the gateway model id for a Qoder model key (e.g. "qfmodel" ->
// "qoder/qfmodel").
func (m *ModelInfo) ID() string {
	return "qoder/" + strings.TrimSpace(m.Key)
}

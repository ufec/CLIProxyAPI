package dimagent

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ModelInfo is one entry of the /v1/models?type=dim response.
type ModelInfo struct {
	ID         string   `json:"id"`
	Object     string   `json:"object,omitempty"`
	Created    int64    `json:"created,omitempty"`
	OwnedBy    string   `json:"owned_by,omitempty"`
	Root       string   `json:"root,omitempty"`
	Parent     *string  `json:"parent,omitempty"`
	Dim        *DimInfo `json:"dim,omitempty"`
	Rate       float64  `json:"rate,omitempty"`
	BaseRate   float64  `json:"base_rate,omitempty"`
	Permission []any    `json:"permission,omitempty"`
}

// DimInfo carries the DimAgent-specific model metadata.
type DimInfo struct {
	ID          string    `json:"id,omitempty"`
	Name        string    `json:"name,omitempty"`
	DisplayName string    `json:"displayName,omitempty"`
	Status      string    `json:"status,omitempty"`
	Limit       *DimLimit `json:"limit,omitempty"`
	// Modalities is preserved as raw JSON because the upstream returns either a
	// flat string array (["text","image"]) or an object with separate
	// input/output arrays ({"input":[...],"output":[...]}). Keeping the raw
	// value means parsing never fails on either shape.
	Modalities json.RawMessage `json:"modalities,omitempty"`
	Vision     *bool           `json:"vision,omitempty"`
	Reasoning  *DimReasoning   `json:"reasoning,omitempty"`
}

// DimLimit holds the context/output token limits of a model.
type DimLimit struct {
	Context int `json:"context,omitempty"`
	Output  int `json:"output,omitempty"`
}

// DimReasoning describes the reasoning (thinking) capabilities of a model.
type DimReasoning struct {
	Supported        bool     `json:"supported,omitempty"`
	DefaultEnabled   bool     `json:"defaultEnabled,omitempty"`
	Mode             string   `json:"mode,omitempty"`
	Effort           string   `json:"effort,omitempty"`
	EffortOptions    []string `json:"effortOptions,omitempty"`
	Interleaved      bool     `json:"interleaved,omitempty"`
	InterleavedField string   `json:"interleavedField,omitempty"`
}

// ModelsResponse is the envelope of the model listing endpoint.
type ModelsResponse struct {
	Success bool        `json:"success"`
	Data    []ModelInfo `json:"data"`
}

// DisplayName returns the best available display name for the model.
func (m *ModelInfo) DisplayName() string {
	if m == nil {
		return ""
	}
	if m.Dim != nil {
		if m.Dim.DisplayName != "" {
			return m.Dim.DisplayName
		}
		if m.Dim.Name != "" {
			return m.Dim.Name
		}
	}
	return m.ID
}

// ContextLimit returns the model context limit when known.
func (m *ModelInfo) ContextLimit() int {
	if m == nil || m.Dim == nil || m.Dim.Limit == nil {
		return 0
	}
	return m.Dim.Limit.Context
}

// OutputLimit returns the model output limit when known.
func (m *ModelInfo) OutputLimit() int {
	if m == nil || m.Dim == nil || m.Dim.Limit == nil {
		return 0
	}
	return m.Dim.Limit.Output
}

// SupportsVision reports whether the model accepts image input.
func (m *ModelInfo) SupportsVision() bool {
	if m == nil || m.Dim == nil || m.Dim.Vision == nil {
		return false
	}
	return *m.Dim.Vision
}

// ParseModels decodes the model listing response body.
func ParseModels(body []byte) ([]ModelInfo, error) {
	var resp ModelsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("dimagent: invalid models json: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("dimagent: models response success=false")
	}
	models := make([]ModelInfo, 0, len(resp.Data))
	for _, m := range resp.Data {
		if !IsRoutableModel(m.ID) {
			continue
		}
		models = append(models, m)
	}
	return models, nil
}

// IsRoutableModel reports whether the given model ID is usable as a
// routable model entry.
func IsRoutableModel(id string) bool {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return false
	}
	// Placeholder/aggregate entries are not routable.
	if trimmed == "auto" || trimmed == "default" {
		return false
	}
	return true
}

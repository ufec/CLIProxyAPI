package dimagent

import (
	"strings"
	"testing"
)

const sampleModelsBody = `{
  "data": [
    {
      "id": "deepseek-v4-flash",
      "object": "model",
      "created": 1626777600,
      "owned_by": "custom",
      "permission": [{"id": "modelperm-test", "object": "model_permission"}],
      "root": "deepseek-v4-flash",
      "parent": null,
      "dim": {
        "id": "deepseek-v4-flash",
        "name": "DeepSeek-V4-Flash",
        "displayName": "DeepSeek-V4-Flash",
        "status": "active",
        "limit": {"context": 1000000, "output": 384000},
        "modalities": ["text"],
        "vision": false,
        "reasoning": {
          "supported": true,
          "defaultEnabled": true,
          "mode": "effort",
          "effort": "high",
          "effortOptions": ["high", "max"],
          "interleaved": true,
          "interleavedField": "reasoning_content"
        }
      },
      "rate": 1
    },
    {
      "id": "glm-5.3",
      "object": "model",
      "created": 1626777600,
      "owned_by": "custom",
      "root": "glm-5.3",
      "parent": null,
      "dim": null,
      "rate": 0.3,
      "base_rate": 0.5
    },
    {
      "id": "seed-2.1-pro",
      "object": "model",
      "created": 1626777600,
      "owned_by": "custom",
      "root": "seed-2.1-pro",
      "parent": null,
      "dim": {
        "id": "seed-2.1-pro",
        "name": "Seed 2.1 Pro",
        "displayName": "Seed 2.1 Pro",
        "status": "active",
        "limit": {"context": 262144, "output": 262144},
        "modalities": ["text", "image", "video"],
        "vision": true
      },
      "rate": 1
    },
    {"id": "auto", "object": "model", "root": "auto", "parent": null}
  ],
  "success": true
}`

func TestParseModels(t *testing.T) {
	models, err := ParseModels([]byte(sampleModelsBody))
	if err != nil {
		t.Fatalf("ParseModels: %v", err)
	}
	if len(models) != 3 {
		t.Fatalf("expected 3 routable models (auto excluded), got %d", len(models))
	}

	flash := models[0]
	if flash.ID != "deepseek-v4-flash" {
		t.Errorf("first id = %q", flash.ID)
	}
	if flash.DisplayName() != "DeepSeek-V4-Flash" {
		t.Errorf("display name = %q", flash.DisplayName())
	}
	if flash.ContextLimit() != 1000000 || flash.OutputLimit() != 384000 {
		t.Errorf("limits = ctx %d out %d", flash.ContextLimit(), flash.OutputLimit())
	}
	if flash.SupportsVision() {
		t.Error("flash should not support vision")
	}

	glm := models[1]
	if glm.Dim != nil {
		t.Errorf("glm dim should be nil, got %+v", glm.Dim)
	}
	if glm.DisplayName() != "glm-5.3" {
		t.Errorf("glm display name should fall back to id, got %q", glm.DisplayName())
	}

	seed := models[2]
	if !seed.SupportsVision() {
		t.Error("seed-2.1-pro should support vision")
	}
}

func TestParseModelsObjectModalities(t *testing.T) {
	// The upstream returns `modalities` either as a flat string array or as an
	// object with input/output arrays. Both must parse without error.
	body := `{
	  "data": [
	    {
	      "id": "deepseek-v4-flash-vision-exp",
	      "object": "model",
	      "root": "deepseek-v4-flash-vision-exp",
	      "parent": null,
	      "dim": {
	        "id": "deepseek-v4-flash-vision-exp",
	        "name": "DSV4 Flash Vision Exp",
	        "status": "active",
	        "modalities": {"input": ["text", "image"], "output": ["text"]},
	        "vision": true
	      },
	      "rate": 1
	    }
	  ],
	  "success": true
	}`
	models, err := ParseModels([]byte(body))
	if err != nil {
		t.Fatalf("ParseModels with object modalities: %v", err)
	}
	if len(models) != 1 {
		t.Fatalf("expected 1 model, got %d", len(models))
	}
	if models[0].Dim == nil {
		t.Fatal("dim should not be nil")
	}
	if len(models[0].Dim.Modalities) == 0 {
		t.Error("modalities should be preserved")
	}
	if !models[0].SupportsVision() {
		t.Error("model should support vision")
	}
}

func TestParseModelsErrors(t *testing.T) {
	if _, err := ParseModels([]byte(`not json`)); err == nil {
		t.Error("expected error for invalid json")
	}
	if _, err := ParseModels([]byte(`{"data":[],"success":false}`)); err == nil {
		t.Error("expected error for success=false")
	}
	if _, err := ParseModels(nil); err == nil {
		t.Error("expected error for empty body")
	}
}

func TestIsRoutableModel(t *testing.T) {
	for id, want := range map[string]bool{
		"deepseek-v4-flash": true,
		"glm-5.3":           true,
		"":                  false,
		"  ":                false,
		"auto":              false,
		"default":           false,
	} {
		if got := IsRoutableModel(id); got != want {
			t.Errorf("IsRoutableModel(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestNormalizeUpstreamModel(t *testing.T) {
	for in, want := range map[string]string{
		"dimagent-deepseek-v4-flash": "deepseek-v4-flash",
		"deepseek-v4-flash":          "deepseek-v4-flash",
		"dimagent-kimi-k3":           "kimi-k3",
		"":                           "",
	} {
		if got := NormalizeUpstreamModel(in); got != want {
			t.Errorf("NormalizeUpstreamModel(%q) = %q, want %q", in, got, want)
		}
	}
	if strings.Contains(NormalizeUpstreamModel("dimagent-x"), "dimagent-") {
		t.Error("prefix should be stripped")
	}
}

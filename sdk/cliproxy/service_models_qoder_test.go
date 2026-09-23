package cliproxy

import (
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestBuildQoderAuthModelsFromMetadata(t *testing.T) {
	auth := &coreauth.Auth{
		Provider: "qoder",
		Metadata: map[string]any{
			"enabled_models": []any{"qoder/qfmodel", "qoder/qmodel_38max"},
			"models_meta": `[
				{"key":"qfmodel","display_name":"Qwen3.8-Flash","enable":true,"is_vl":true,"max_input_tokens":180000},
				{"key":"qmodel_38max","display_name":"Qwen3.8-Max","enable":true,"is_reasoning":true,"max_input_tokens":180000,"price_factor":0.5}
			]`,
		},
	}

	models := buildQoderAuthModels(auth)
	if len(models) != 2 {
		t.Fatalf("unexpected model count: %d", len(models))
	}
	if models[0].ID != "qoder/qfmodel" || models[0].DisplayName != "Qwen3.8-Flash" {
		t.Errorf("first model mismatch: %+v", models[0])
	}
	if models[0].OwnedBy != "qoder" || models[0].Type != "qoder" {
		t.Errorf("owned_by/type not qoder: %+v", models[0])
	}
	if models[0].Credits != "x0.00 credits" || models[1].Credits != "x0.50 credits" {
		t.Errorf("price factors not mapped: %q, %q", models[0].Credits, models[1].Credits)
	}
	if models[0].ContextLength != 180000 || models[0].MaxContextLength != 180000 {
		t.Errorf("context limits not mapped: %+v", models[0])
	}
	if len(models[0].SupportedInputModalities) != 1 || models[0].SupportedInputModalities[0] != "image" {
		t.Errorf("VL modality not mapped: %v", models[0].SupportedInputModalities)
	}
}

func TestBuildQoderAuthModelsNoMetadata(t *testing.T) {
	auth := &coreauth.Auth{Provider: "qoder"}
	if models := buildQoderAuthModels(auth); models != nil {
		t.Fatalf("expected nil when no metadata, got %d models", len(models))
	}

	auth = &coreauth.Auth{Provider: "qoder", Metadata: map[string]any{"type": "qoder"}}
	if models := buildQoderAuthModels(auth); models != nil {
		t.Fatalf("expected nil when no models_meta, got %d models", len(models))
	}
}

func TestBuildQoderAuthModelsFiltersDisabled(t *testing.T) {
	auth := &coreauth.Auth{
		Provider: "qoder",
		Metadata: map[string]any{
			"models_meta": `[
				{"key":"qfmodel","display_name":"Qwen3.8-Flash","enable":true,"max_input_tokens":180000},
				{"key":"ultimate","display_name":"Ultimate","enable":false,"max_input_tokens":1000000},
				{"key":"auto","display_name":"Auto","enable":true,"max_input_tokens":200000}
			]`,
		},
	}

	models := buildQoderAuthModels(auth)
	if len(models) != 1 {
		t.Fatalf("expected only enabled routable model, got %d", len(models))
	}
	if models[0].ID != "qoder/qfmodel" {
		t.Fatalf("unexpected model: %+v", models[0])
	}
}

package qoder

import (
	"strings"
	"testing"
)

func TestParseModelsFiltersEnabledRoutable(t *testing.T) {
	body := `{"chat":[
		{"key":"auto","display_name":"Auto","enable":true,"max_input_tokens":200000},
		{"key":"qfmodel","display_name":"Qwen3.8-Flash","enable":true,"is_vl":true,"max_input_tokens":180000},
		{"key":"qmodel_38max","display_name":"Qwen3.8-Max","enable":true,"max_input_tokens":180000,"is_reasoning":true},
		{"key":"ultimate","display_name":"Ultimate","enable":false,"max_input_tokens":1000000}
	],"assistant":[]}`

	models, err := ParseModels([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(models) != 2 {
		t.Fatalf("expected 2 enabled routable models, got %d: %+v", len(models), models)
	}
	if models[0].Key != "qfmodel" || models[0].ID() != "qoder/qfmodel" {
		t.Fatalf("unexpected first model: %+v id=%s", models[0], models[0].ID())
	}
	if !models[0].IsVL {
		t.Fatal("qfmodel should be VL")
	}
	if models[0].DisplayName != "Qwen3.8-Flash" {
		t.Fatalf("display name = %q", models[0].DisplayName)
	}
}

func TestParseModelsEmptyChat(t *testing.T) {
	models, err := ParseModels([]byte(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(models) != 0 {
		t.Fatalf("expected 0 models, got %d", len(models))
	}
}

func TestParseModelsInvalidJSON(t *testing.T) {
	if _, err := ParseModels([]byte(`not json`)); err == nil {
		t.Fatal("expected error for invalid json")
	}
}

func TestIsRoutableModel(t *testing.T) {
	if IsRoutableModel("") {
		t.Fatal("empty should not be routable")
	}
	if IsRoutableModel("auto") {
		t.Fatal("auto should not be routable")
	}
	if IsRoutableModel("default") {
		t.Fatal("default should not be routable")
	}
	if !IsRoutableModel("qfmodel") {
		t.Fatal("qfmodel should be routable")
	}
}

func TestModelIDFormat(t *testing.T) {
	m := ModelInfo{Key: "  qfmodel  "}
	if got := m.ID(); got != "qoder/qfmodel" {
		t.Fatalf("id = %q, want qoder/qfmodel", got)
	}
}

func TestBuildModelsURL(t *testing.T) {
	got := BuildModelsURL("https://api3.qoder.sh")
	if !strings.HasSuffix(got, "/algo/api/v2/model/list?Encode=1") {
		t.Fatalf("unexpected url: %s", got)
	}
	if !strings.HasPrefix(got, "https://api3.qoder.sh") {
		t.Fatalf("unexpected host: %s", got)
	}
}

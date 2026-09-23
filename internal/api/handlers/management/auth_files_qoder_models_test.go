package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestAppendMissingCatalogModelsQoder(t *testing.T) {
	metadata := map[string]any{
		"type": "qoder",
		"models_meta": `[
			{"key":"auto","display_name":"Auto","enable":false},
			{"key":"qmodel_38max","display_name":"Qwen3.8-Max","enable":true},
			{"key":"qfmodel","display_name":"Qwen3.8-Flash","enable":true}
		]`,
	}
	result := appendMissingCatalogModels(nil, metadata, map[string]struct{}{
		"qoder/qmodel_38max": {},
	})
	if len(result) != 1 {
		t.Fatalf("models = %v, want only the missing enabled model", result)
	}
	if result[0]["id"] != "qoder/qfmodel" || result[0]["display_name"] != "Qwen3.8-Flash" {
		t.Fatalf("unexpected Qoder model: %v", result[0])
	}
	if result[0]["type"] != "qoder" || result[0]["owned_by"] != "qoder" {
		t.Fatalf("missing Qoder provider metadata: %v", result[0])
	}
}

func TestGetAuthFileModelsQoderMetadataWithoutRegistry(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	fileName := "qoder-management-models-test.json"
	_, err := manager.Register(context.Background(), &coreauth.Auth{
		ID:       fileName,
		FileName: fileName,
		Provider: "qoder",
		Metadata: map[string]any{
			"type":        "qoder",
			"models_meta": `[{"key":"qfmodel","display_name":"Qwen3.8-Flash","enable":true}]`,
		},
	})
	if err != nil {
		t.Fatalf("register auth: %v", err)
	}
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files/models?name="+fileName, nil)
	h.GetAuthFileModels(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Models []map[string]any `json:"models"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Models) != 1 || response.Models[0]["id"] != "qoder/qfmodel" {
		t.Fatalf("models = %v", response.Models)
	}
}

func TestGetAuthFileModelsBackfillsQoderCredentials(t *testing.T) {
	authDir := t.TempDir()
	fileName := "qoder-backfill-test.json"
	manager := coreauth.NewManager(nil, nil, nil)
	_, err := manager.Register(context.Background(), &coreauth.Auth{
		ID:       fileName,
		FileName: fileName,
		Provider: "qoder",
		Metadata: map[string]any{
			"type":                 "qoder",
			"uid":                  "test-user",
			"security_oauth_token": "test-token",
		},
	})
	if err != nil {
		t.Fatalf("register auth: %v", err)
	}
	originalFetcher := fetchQoderModels
	fetchQoderModels = func(_ context.Context, _ *http.Client, _, uid, token string) ([]byte, error) {
		if uid != "test-user" || token != "test-token" {
			t.Fatalf("unexpected Qoder credentials passed to model fetch")
		}
		return []byte(`{"chat":[{"key":"auto","enable":false},{"key":"qfmodel","display_name":"Qwen3.8-Flash","enable":true},{"key":"qmodel_38max","display_name":"Qwen3.8-Max","enable":true}]}`), nil
	}
	t.Cleanup(func() { fetchQoderModels = originalFetcher })

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files/models?name="+fileName, nil)
	h.GetAuthFileModels(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Models []map[string]any `json:"models"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Models) != 2 {
		t.Fatalf("models = %v, want two enabled chat models", response.Models)
	}
	data, err := os.ReadFile(filepath.Join(authDir, fileName))
	if err != nil {
		t.Fatalf("read saved auth file: %v", err)
	}
	var saved map[string]any
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatalf("decode saved auth file: %v", err)
	}
	if saved["models_meta"] == nil || saved["enabled_models"] == nil {
		t.Fatalf("Qoder model metadata was not persisted")
	}
}

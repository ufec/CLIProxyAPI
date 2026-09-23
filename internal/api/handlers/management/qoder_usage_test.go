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
	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/qoder"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestGetQoderUsageRefreshesDeviceToken(t *testing.T) {
	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	name := "qoder-usage-test.json"
	_, err := manager.Register(context.Background(), &coreauth.Auth{
		ID: name, FileName: name, Provider: "qoder",
		Metadata: map[string]any{"type": "qoder", "access_token": "jt-chat", "device_token": "dt-old", "device_refresh_token": "drt-old"},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case qoder.AccountUsagePath:
			if r.Header.Get("Authorization") == "Bearer dt-old" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.Header.Get("Authorization") != "Bearer dt-new" {
				t.Error("unexpected usage token")
			}
			_, _ = w.Write([]byte(`{"displayMode":"qoder","qoderUsage":{"userType":"pro","userQuota":{"total":100,"used":30}}}`))
		case qoder.DeviceTokenRefreshPath:
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["refresh_token"] != "drt-old" {
				t.Error("wrong device refresh body")
			}
			_, _ = w.Write([]byte(`{"token":"dt-new","refresh_token":"drt-new"}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
	h.qoderUsageClient = server.Client()
	h.qoderUsageBaseURL = server.URL
	h.qoderDeviceRefreshURL = server.URL + qoder.DeviceTokenRefreshPath
	h.SetPostAuthPersistHook(func(ctx context.Context, auth *coreauth.Auth) error {
		_, err := manager.Register(ctx, auth)
		return err
	})
	index := manager.List()[0].Index
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/v0/management/qoder/usage?auth_index="+index, nil)
	h.GetQoderUsage(c)
	if rec.Code != http.StatusOK || !json.Valid(rec.Body.Bytes()) {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	stored, err := os.ReadFile(filepath.Join(authDir, name))
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string]any
	if err := json.Unmarshal(stored, &saved); err != nil || saved["device_token"] != "dt-new" || saved["device_refresh_token"] != "drt-new" || saved["access_token"] != "jt-chat" {
		t.Fatal("device token rotation did not persist or changed the chat token")
	}
}

func TestGetQoderUsageLegacyCredentialRequiresLogin(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	_, err := manager.Register(context.Background(), &coreauth.Auth{ID: "old.json", Provider: "qoder", Metadata: map[string]any{"access_token": "jt-only"}})
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/v0/management/qoder/usage?auth_index="+manager.List()[0].Index, nil)
	h.GetQoderUsage(c)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want conflict", rec.Code)
	}
}

func TestGetQoderUsageRefreshFailureStatus(t *testing.T) {
	for _, tc := range []struct {
		name          string
		refreshStatus int
		wantStatus    int
	}{
		{name: "rejected", refreshStatus: http.StatusUnauthorized, wantStatus: http.StatusConflict},
		{name: "temporary outage", refreshStatus: http.StatusServiceUnavailable, wantStatus: http.StatusBadGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager := coreauth.NewManager(nil, nil, nil)
			_, err := manager.Register(context.Background(), &coreauth.Auth{
				ID: "qoder.json", Provider: "qoder",
				Metadata: map[string]any{"device_token": "dt-old", "device_refresh_token": "drt-old"},
			})
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == qoder.DeviceTokenRefreshPath {
					w.WriteHeader(tc.refreshStatus)
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
			}))
			defer server.Close()
			h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
			h.qoderUsageClient = server.Client()
			h.qoderUsageBaseURL = server.URL
			h.qoderDeviceRefreshURL = server.URL + qoder.DeviceTokenRefreshPath
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodGet, "/v0/management/qoder/usage?auth_index="+manager.List()[0].Index, nil)
			h.GetQoderUsage(c)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

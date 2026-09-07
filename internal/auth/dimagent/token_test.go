package dimagent

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func makeTestJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return enc(header) + "." + enc(payload) + ".testsig"
}

func TestParseJWTClaims(t *testing.T) {
	token := makeTestJWT(t, map[string]any{
		"sub":                "1741",
		"uid":                "u_TestUser",
		"name":               "4647_test",
		"preferred_username": "4647_test",
	})
	claims, err := parseJWTClaims(token)
	if err != nil {
		t.Fatalf("parseJWTClaims: %v", err)
	}
	if claims.Sub != "1741" || claims.UID != "u_TestUser" || claims.PreferredUsername != "4647_test" {
		t.Errorf("unexpected claims: %+v", claims)
	}
	if _, err := parseJWTClaims("not-a-jwt"); err == nil {
		t.Error("expected error for non-jwt input")
	}
	if _, err := parseJWTClaims(""); err == nil {
		t.Error("expected error for empty input")
	}
}

func TestNewTokenStorageFromResponse(t *testing.T) {
	idToken := makeTestJWT(t, map[string]any{
		"sub":                "1741",
		"uid":                "u_TestUser",
		"preferred_username": "test_user",
	})
	token := &TokenResponse{
		AccessToken:  "access-123",
		RefreshToken: "refresh-456",
		IDToken:      idToken,
		TokenType:    "Bearer",
		Scope:        "openid profile",
		ExpiresIn:    604800,
	}
	storage := NewTokenStorage(token)

	if storage.AccessToken != "access-123" || storage.RefreshToken != "refresh-456" {
		t.Errorf("unexpected tokens: %+v", storage)
	}
	if storage.Type != "dimagent" {
		t.Errorf("type = %q, want dimagent", storage.Type)
	}
	if storage.UID != "u_TestUser" || storage.Sub != "1741" || storage.Nickname != "test_user" {
		t.Errorf("unexpected claims: uid=%q sub=%q nickname=%q", storage.UID, storage.Sub, storage.Nickname)
	}
	if storage.Expired == "" {
		t.Error("expired should be set")
	}
	exp, err := time.Parse(time.RFC3339, storage.Expired)
	if err != nil {
		t.Fatalf("expired is not RFC3339: %v", err)
	}
	// 7 days minus a small tolerance.
	delta := exp.Sub(time.Now())
	if delta < 6*24*time.Hour || delta > 7*24*time.Hour {
		t.Errorf("expiration delta = %v, want ~7d", delta)
	}
	if storage.IsExpired() {
		t.Error("fresh token should not be expired")
	}
}

func TestNewTokenStorageFallbacks(t *testing.T) {
	storage := NewTokenStorage(nil)
	if storage.Type != "dimagent" {
		t.Errorf("nil response should still produce dimagent type, got %q", storage.Type)
	}

	storage = NewTokenStorage(&TokenResponse{AccessToken: "a"})
	if storage.TokenType != "Bearer" {
		t.Errorf("token type default = %q, want Bearer", storage.TokenType)
	}
	if storage.Expired == "" {
		t.Error("expired should default from TTL")
	}
}

func TestTokenStorageSaveAndIsExpired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dimagent-test.json")

	storage := NewTokenStorage(&TokenResponse{
		AccessToken:  "access-123",
		RefreshToken: "refresh-456",
		ExpiresIn:    604800,
	})
	storage.EnabledModels = []string{"dimagent-deepseek-v4-flash"}
	storage.ModelsMeta = `[{"id":"deepseek-v4-flash"}]`
	if err := storage.SaveTokenToFile(path); err != nil {
		t.Fatalf("SaveTokenToFile: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved file: %v", err)
	}
	var saved map[string]any
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatalf("unmarshal saved file: %v", err)
	}
	if saved["type"] != "dimagent" {
		t.Errorf("saved type = %v, want dimagent", saved["type"])
	}
	if saved["access_token"] != "access-123" {
		t.Errorf("saved access_token = %v", saved["access_token"])
	}
	if saved["refresh_token"] != "refresh-456" {
		t.Errorf("saved refresh_token = %v", saved["refresh_token"])
	}

	expired := &TokenStorage{Type: "dimagent", Expired: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)}
	if !expired.IsExpired() {
		t.Error("past-expiry token should be expired")
	}
	future := &TokenStorage{Type: "dimagent", Expired: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	if future.IsExpired() {
		t.Error("future-expiry token should not be expired")
	}
	bad := &TokenStorage{Type: "dimagent", Expired: "not-a-time"}
	if !bad.IsExpired() {
		t.Error("unparseable expiry should be treated as expired")
	}
}

func TestAccountLabel(t *testing.T) {
	if got := (&TokenStorage{Nickname: "alice"}).AccountLabel(); got != "dimagent:alice" {
		t.Errorf("nickname label = %q", got)
	}
	if got := (&TokenStorage{Sub: "1741"}).AccountLabel(); got != "dimagent:1741" {
		t.Errorf("sub label = %q", got)
	}
	if got := (&TokenStorage{}).AccountLabel(); got != "dimagent" {
		t.Errorf("fallback label = %q", got)
	}
	if got := (*TokenStorage)(nil).AccountLabel(); got != "dimagent" {
		t.Errorf("nil label = %q", got)
	}
}

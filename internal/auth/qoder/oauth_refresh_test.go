package qoder

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRefreshJobToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != JobTokenRefreshPath {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("unexpected Authorization header")
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if body["refresh_token"] != "old-refresh" {
			t.Errorf("unexpected refresh token")
		}
		_, _ = w.Write([]byte(`{"token":"new-job","refresh_token":"new-refresh"}`))
	}))
	defer server.Close()

	token, err := RefreshJobToken(context.Background(), server.Client(), server.URL+JobTokenRefreshPath, "old-refresh")
	if err != nil {
		t.Fatal(err)
	}
	if token.Token != "new-job" || token.RefreshToken != "new-refresh" {
		t.Fatal("token pair was not rotated")
	}
}

func TestRefreshJobTokenMissingCredential(t *testing.T) {
	_, err := RefreshJobToken(context.Background(), nil, "", "")
	if err == nil || !strings.Contains(err.Error(), "sign in again") {
		t.Fatalf("error = %v", err)
	}
}

func TestRefreshDeviceToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != DeviceTokenRefreshPath || r.Header.Get("Authorization") != "" {
			t.Errorf("unexpected device refresh request: %s %s", r.Method, r.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["refresh_token"] != "drt-old" {
			t.Error("device refresh body mismatch")
		}
		_, _ = w.Write([]byte(`{"device_token":"dt-new","refresh_token":"drt-new"}`))
	}))
	defer server.Close()
	token, err := RefreshDeviceToken(context.Background(), server.Client(), server.URL+DeviceTokenRefreshPath, "drt-old")
	if err != nil || token.Token != "dt-new" || token.RefreshToken != "drt-new" {
		t.Fatalf("rotated token = %#v, error = %v", token, err)
	}
}

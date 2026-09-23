package qoder

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchUsage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != AccountUsagePath {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer dt-test" || r.Header.Get("Cosy-ClientType") != "10" {
			t.Error("missing Qoder device authentication headers")
		}
		_, _ = w.Write([]byte(`{"displayMode":"qoder","qoderUsage":{"userType":"pro","userQuota":{"total":100,"used":25}}}`))
	}))
	defer server.Close()
	body, err := FetchUsage(context.Background(), server.Client(), server.URL, "dt-test")
	if err != nil || !strings.Contains(string(body), `"userQuota"`) {
		t.Fatalf("usage = %s, error = %v", body, err)
	}
}

func TestFetchUsageUnauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	_, err := FetchUsage(context.Background(), server.Client(), server.URL, "dt-old")
	var statusErr *UsageHTTPError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("error = %v", err)
	}
}

package configaccess

import (
	"net/http/httptest"
	"testing"
)

func TestProviderAcceptsQoderJWTToken(t *testing.T) {
	p := newProvider("config-inline", []string{"sk-valid-api-key"})
	req := httptest.NewRequest("GET", "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer jt-abcdef0123456789")

	res, authErr := p.Authenticate(req.Context(), req)
	if authErr != nil {
		t.Fatalf("expected Qoder jt-* token to pass auth, got error: %v", authErr)
	}
	if res == nil {
		t.Fatal("expected non-nil result for Qoder jt-* token")
	}
	if res.Principal != "jt-abcdef0123456789" {
		t.Fatalf("principal = %q, want %q", res.Principal, "jt-abcdef0123456789")
	}
	if res.Metadata["source"] != "authorization" {
		t.Fatalf("source = %q, want authorization", res.Metadata["source"])
	}
}

func TestProviderRejectsUnknownKey(t *testing.T) {
	p := newProvider("config-inline", []string{"sk-valid-api-key"})
	req := httptest.NewRequest("GET", "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer sk-unknown-key")

	_, authErr := p.Authenticate(req.Context(), req)
	if authErr == nil {
		t.Fatal("expected auth error for unknown non-jt key")
	}
}

func TestProviderStillAcceptsConfiguredKey(t *testing.T) {
	p := newProvider("config-inline", []string{"sk-valid-api-key"})
	req := httptest.NewRequest("GET", "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer sk-valid-api-key")

	res, authErr := p.Authenticate(req.Context(), req)
	if authErr != nil {
		t.Fatalf("unexpected auth error: %v", authErr)
	}
	if res == nil || res.Principal != "sk-valid-api-key" {
		t.Fatalf("unexpected result: %+v", res)
	}
}

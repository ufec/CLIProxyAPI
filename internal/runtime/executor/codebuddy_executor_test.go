package executor

import (
	"testing"

	codebuddyauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codebuddy"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

func TestNormalizeCodeBuddyUpstreamModel(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "plain id", input: "glm-5.2", want: "glm-5.2"},
		{name: "prefixed id", input: "codebuddy-glm-5.2", want: "glm-5.2"},
		{name: "prefixed id uppercase", input: "CodeBuddy-HY3", want: "HY3"},
		{name: "claude context suffix", input: "codebuddy-hy3[1m]", want: "hy3"},
		{name: "thinking suffix preserved", input: "codebuddy-glm-5.2(1024)", want: "glm-5.2(1024)"},
		{name: "context and thinking suffix", input: "codebuddy-glm-5.2[1m](1024)", want: "glm-5.2(1024)"},
		{name: "double prefix trims once", input: "codebuddy-codebuddy-hy3", want: "codebuddy-hy3"},
		{name: "bare prefix word", input: "codebuddy-", want: "codebuddy-"},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if got := normalizeCodeBuddyUpstreamModel(testCase.input); got != testCase.want {
				t.Errorf("normalizeCodeBuddyUpstreamModel(%q) = %q, want %q", testCase.input, got, testCase.want)
			}
		})
	}
}

func TestCodeBuddyCreds(t *testing.T) {
	if got := codebuddyCreds(nil); got != "" {
		t.Errorf("nil auth should yield empty token, got %q", got)
	}

	metadataAuth := &cliproxyauth.Auth{Attributes: map[string]string{}, Metadata: map[string]any{"access_token": "meta-token"}}
	if got := codebuddyCreds(metadataAuth); got != "meta-token" {
		t.Errorf("metadata token = %q, want meta-token", got)
	}

	attrAuth := &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "attr-key"}, Metadata: map[string]any{}}
	if got := codebuddyCreds(attrAuth); got != "attr-key" {
		t.Errorf("attribute token = %q, want attr-key", got)
	}
}

func TestCodeBuddyUID(t *testing.T) {
	if got := codebuddyUID(nil); got != "" {
		t.Errorf("nil auth should yield empty uid, got %q", got)
	}

	metadataAuth := &cliproxyauth.Auth{Attributes: map[string]string{}, Metadata: map[string]any{"uid": "  u-1  "}}
	if got := codebuddyUID(metadataAuth); got != "u-1" {
		t.Errorf("uid = %q, want u-1", got)
	}

	attrAuth := &cliproxyauth.Auth{Attributes: map[string]string{"uid": "u-2"}, Metadata: map[string]any{}}
	if got := codebuddyUID(attrAuth); got != "u-2" {
		t.Errorf("attribute uid = %q, want u-2", got)
	}
}

func TestCodeBuddyBaseURL(t *testing.T) {
	if got := codebuddyBaseURL(nil, codebuddyauth.RegionCN); got != codebuddyauth.DefaultBaseURL {
		t.Errorf("nil auth base URL = %q, want %q", got, codebuddyauth.DefaultBaseURL)
	}
	if got := codebuddyBaseURL(nil, codebuddyauth.RegionIntl); got != codebuddyauth.IntlBaseURL {
		t.Errorf("intl base URL = %q, want %q", got, codebuddyauth.IntlBaseURL)
	}

	auth := &cliproxyauth.Auth{Attributes: map[string]string{"base_url": "https://example.com/"}, Metadata: map[string]any{}}
	if got := codebuddyBaseURL(auth, codebuddyauth.RegionCN); got != "https://example.com/" {
		t.Errorf("base_url = %q, want https://example.com/", got)
	}
}

func TestIsCodeBuddySSEHeartbeat(t *testing.T) {
	heartbeats := [][]byte{
		[]byte(": heartbeat"),
		[]byte(": keep-alive"),
		[]byte("data: : heartbeat"),
		[]byte("data::heartbeat"),
		[]byte("  : heartbeat  "),
	}
	for _, line := range heartbeats {
		if !isCodeBuddySSEHeartbeat(line) {
			t.Errorf("expected heartbeat detection for %q", line)
		}
	}
	normal := [][]byte{
		[]byte(`data: {"id":"x","choices":[]}`),
		[]byte("data: [DONE]"),
		[]byte("event: message_start"),
		[]byte(""),
	}
	for _, line := range normal {
		if isCodeBuddySSEHeartbeat(line) {
			t.Errorf("unexpected heartbeat detection for %q", line)
		}
	}
}

func TestEnsureLeadingSystemMessage(t *testing.T) {
	newExecutor := func(region *codebuddyauth.Region) *CodeBuddyExecutor {
		return newCodeBuddyExecutorForRegion(nil, region)
	}

	t.Run("intl prepends system message", func(t *testing.T) {
		body := []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`)
		out := newExecutor(codebuddyauth.RegionIntl).ensureLeadingSystemMessage(body)
		roles := gjson.GetBytes(out, "messages.#.role").Array()
		if len(roles) != 2 || roles[0].String() != "system" || roles[1].String() != "user" {
			t.Fatalf("unexpected roles after inject: %v", roles)
		}
		if got := gjson.GetBytes(out, "messages.0.content").String(); got == "" {
			t.Fatal("injected system message must not be empty")
		}
		if got := gjson.GetBytes(out, "messages.1.content").String(); got != "hi" {
			t.Fatalf("user content changed: %q", got)
		}
	})

	t.Run("intl keeps existing system message", func(t *testing.T) {
		body := []byte(`{"model":"m","messages":[{"role":"system","content":"sys"},{"role":"user","content":"hi"}]}`)
		out := newExecutor(codebuddyauth.RegionIntl).ensureLeadingSystemMessage(body)
		if gjson.GetBytes(out, "messages.0.content").String() != "sys" {
			t.Fatal("existing system message must be kept")
		}
		if len(gjson.GetBytes(out, "messages").Array()) != 2 {
			t.Fatal("message count changed")
		}
	})

	t.Run("cn payload unchanged", func(t *testing.T) {
		body := []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`)
		out := newExecutor(codebuddyauth.RegionCN).ensureLeadingSystemMessage(body)
		if gjson.GetBytes(out, "messages.0.role").String() != "user" {
			t.Fatal("CN payload must stay unchanged")
		}
	})
}

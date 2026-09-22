package test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	qoderauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/qoder"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

// qoderUpstreamServer simulates the Qoder agent_chat_generation SSE upstream,
// verifying the custom-base64 body decodes to an OpenAI-compatible chat JSON
// and the COSY envelope is present, then streams OpenAI-style chunks.
func qoderUpstreamServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer COSY.") {
			t.Errorf("missing COSY Authorization header")
		}
		if r.Header.Get("Cosy-User") != "uid-qoder-test-001" {
			t.Errorf("wrong Cosy-User: %q", r.Header.Get("Cosy-User"))
		}
		raw, errRead := io.ReadAll(r.Body)
		if errRead != nil {
			t.Errorf("read body: %v", errRead)
			return
		}
		var plain struct {
			Parameters map[string]any `json:"parameters"`
			Business   map[string]any `json:"business"`
			Messages   []any          `json:"messages"`
		}
		decoded := qoderauth.BodyDecode(string(raw))
		if errDecode := json.Unmarshal(decoded, &plain); errDecode != nil {
			t.Errorf("decoded body is not valid JSON: %v (decoded %d bytes)", errDecode, len(decoded))
			return
		}
		if plain.Business["stage"] != "start" || plain.Business["type"] != "agent" {
			t.Errorf("business stage/type missing: %v", plain.Business)
		}
		if len(plain.Messages) == 0 {
			t.Errorf("messages missing from decoded body")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		chunks := []string{
			`{"choices":[{"delta":{"content":"","reasoning_content":"","role":"assistant"},"index":0}],"created":1700000000,"id":"chatcmpl-qoder-test","model":"auto","object":"chat.completion.chunk"}`,
			`{"choices":[{"delta":{"content":"Hello","reasoning_content":"thinking..."},"index":0}],"created":1700000000,"id":"chatcmpl-qoder-test","model":"auto","object":"chat.completion.chunk"}`,
			`{"choices":[{"delta":{"content":" from Qoder"},"index":0}],"created":1700000000,"id":"chatcmpl-qoder-test","model":"auto","object":"chat.completion.chunk"}`,
			`{"choices":[{"delta":{"content":"","reasoning_content":""},"finish_reason":"stop","index":0}],"created":1700000000,"id":"chatcmpl-qoder-test","model":"auto","object":"chat.completion.chunk"}`,
			`{"choices":[],"created":1700000000,"id":"chatcmpl-qoder-test","model":"auto","object":"chat.completion.chunk","usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`,
		}
		for _, c := range chunks {
			envelope, _ := json.Marshal(map[string]any{
				"headers":         map[string][]string{"Content-Type": {"application/json"}},
				"body":            c,
				"statusCodeValue": 200,
				"statusCode":      "OK",
			})
			if _, errWrite := w.Write([]byte("data: " + string(envelope) + "\n")); errWrite != nil {
				t.Errorf("write sse: %v", errWrite)
			}
		}
		if _, errWrite := w.Write([]byte("data: {\"firstTokenDuration\":50,\"totalDuration\":200,\"serverDuration\":80}\n")); errWrite != nil {
			t.Errorf("write sse: %v", errWrite)
		}
	}))
}

func TestQoderOpenAICompatChatCompletion(t *testing.T) {
	upstream := qoderUpstreamServer(t)
	defer upstream.Close()

	manager := cliproxyauth.NewManager(nil, &cliproxyauth.RoundRobinSelector{}, nil)
	manager.SetRetryConfig(0, 0, 0)
	executor := runtimeexecutor.NewQoderExecutor(&config.Config{})
	executor.UpstreamURLOverride = upstream.URL
	manager.RegisterExecutor(executor)

	const model = "qoder/qwen3.8-flash"
	const authID = "qoder-auth-test"
	registry.GetGlobalRegistry().RegisterClient(authID, "qoder", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(authID) })

	if _, errRegister := manager.Register(context.Background(), &cliproxyauth.Auth{
		ID: authID, Provider: "qoder", Status: cliproxyauth.StatusActive,
		Attributes: map[string]string{
			"uid":                  "uid-qoder-test-001",
			"security_oauth_token": "jt-qoder-test-token",
		},
	}); errRegister != nil {
		t.Fatal(errRegister)
	}

	// OpenAI-compatible chat completion request through the executor path.
	payload := []byte(`{"model":"qoder/qwen3.8-flash","messages":[{"role":"user","content":"ping"}],"max_tokens":1000,"reasoning_effort":"low"}`)
	result, errStream := manager.ExecuteStream(context.Background(), []string{"qoder"}, cliproxyexecutor.Request{
		Model: model, Payload: payload,
	}, cliproxyexecutor.Options{Stream: true, SourceFormat: sdktranslator.FromString("openai.chat")})
	if errStream != nil {
		t.Fatal(errStream)
	}

	var sb strings.Builder
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatal(chunk.Err)
		}
		sb.Write(chunk.Payload)
	}
	streamed := sb.String()
	if !strings.Contains(streamed, `"content":"Hello"`) {
		t.Fatalf("streamed content missing: %q", streamed)
	}
	if !strings.Contains(streamed, `"reasoning_content":"thinking..."`) {
		t.Fatalf("reasoning_content missing: %q", streamed)
	}
	if !strings.Contains(streamed, `"finish_reason":"stop"`) {
		t.Fatalf("finish_reason missing: %q", streamed)
	}
	if !strings.Contains(streamed, `"usage"`) {
		t.Fatalf("usage missing: %q", streamed)
	}
	if !strings.Contains(streamed, `data: `) {
		t.Fatalf("SSE data framing missing: %q", streamed)
	}
}

func TestQoderCountTokens(t *testing.T) {
	executor := runtimeexecutor.NewQoderExecutor(&config.Config{})
	resp, err := executor.CountTokens(context.Background(), &cliproxyauth.Auth{}, cliproxyexecutor.Request{
		Payload: []byte(`{"messages":[{"role":"user","content":"hello world"}]}`),
	}, cliproxyexecutor.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(resp.Payload), `"prompt_tokens"`) {
		t.Fatalf("count tokens response missing usage: %s", resp.Payload)
	}
}

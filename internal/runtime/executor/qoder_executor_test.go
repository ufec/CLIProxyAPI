package executor

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
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func testQoderAuth() *cliproxyauth.Auth {
	return &cliproxyauth.Auth{
		Provider: "qoder",
		Attributes: map[string]string{
			"uid":                  "test-uid-001",
			"name":                 "tester",
			"email":                "t@example.com",
			"security_oauth_token": "jt-secret-token",
		},
	}
}

func TestQoderChatBody(t *testing.T) {
	payload := []byte(`{"model":"qoder/qwen3","messages":[{"role":"user","content":"hello qoder"}],"max_tokens":10000,"reasoning_effort":"high"}`)
	req := cliproxyexecutor.Request{Model: "qoder/qwen3", Payload: payload}
	opts := cliproxyexecutor.Options{OriginalRequest: payload}
	plain, err := qoderChatBody(req, opts)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(plain, &body); err != nil {
		t.Fatalf("plaintext not valid JSON: %v\n%s", err, plain)
	}
	params, ok := body["parameters"].(map[string]any)
	if !ok {
		t.Fatalf("missing parameters: %v", body)
	}
	if params["max_tokens"] != float64(10000) {
		t.Fatalf("max_tokens not propagated: %v", params)
	}
	if params["reasoning_effort"] != "high" {
		t.Fatalf("reasoning_effort not propagated: %v", params)
	}
	biz, ok := body["business"].(map[string]any)
	if !ok {
		t.Fatalf("missing business: %v", body)
	}
	if biz["stage"] != "start" || biz["type"] != "agent" {
		t.Fatalf("business fields wrong: %v", biz)
	}
	if _, hasMessages := body["messages"]; !hasMessages {
		t.Fatalf("missing messages in body")
	}
}

func TestQoderBodyRoundtripViaExecutorBuild(t *testing.T) {
	payload := []byte(`{"messages":[{"role":"user","content":"hi"}]}`)
	req := cliproxyexecutor.Request{Model: "qfmodel", Payload: payload}
	plain, err := qoderChatBody(req, cliproxyexecutor.Options{})
	if err != nil {
		t.Fatal(err)
	}
	enc := qoderauth.EncodeBody(plain)
	if len(enc)%4 != 0 {
		t.Fatalf("encoded body len %%4 != 0: %d", len(enc))
	}
	dec := qoderauth.DecodeBody(enc)
	if string(dec) != string(plain) {
		t.Fatal("executor body encode/decode roundtrip mismatch")
	}
}

func TestQoderSSEUnwrap(t *testing.T) {
	line := `data:{"headers":{"Content-Type":["application/json"]},"body":"{\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}","statusCodeValue":200,"statusCode":"OK"}`
	inner, ok := qoderSSEUnwrap(line)
	if !ok {
		t.Fatal("unwrap failed")
	}
	if string(inner) != `{"choices":[{"delta":{"content":"hi"}}]}` {
		t.Fatalf("unexpected inner: %s", inner)
	}
	// final duration block has no body -> ignored
	if _, ok := qoderSSEUnwrap(`data:{"firstTokenDuration":725,"totalDuration":22466}`); ok {
		t.Fatal("duration block should not unwrap")
	}
	// non-data line ignored
	if _, ok := qoderSSEUnwrap(`event:foo`); ok {
		t.Fatal("non-data line should not unwrap")
	}
}

func TestQoderExecuteStreamUnwraps(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// verify the request body is valid custom-base64 and decodes
		raw, _ := io.ReadAll(r.Body)
		plain := qoderauth.BodyDecode(string(raw))
		if !strings.Contains(string(plain), `"role":"user"`) {
			t.Errorf("upstream body missing user message")
		}
		if r.Header.Get("Authorization") == "" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer COSY.") {
			t.Errorf("missing COSY Authorization header")
		}
		if r.Header.Get("Cosy-User") != "test-uid-001" {
			t.Errorf("wrong Cosy-User: %q", r.Header.Get("Cosy-User"))
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`data:{"headers":{},"body":"{\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}","statusCodeValue":200,"statusCode":"OK"}` + "\n"))
		_, _ = w.Write([]byte(`data:{"headers":{},"body":"{\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}","statusCodeValue":200,"statusCode":"OK"}` + "\n"))
		_, _ = w.Write([]byte(`data:{"firstTokenDuration":1,"totalDuration":2}` + "\n"))
	}))
	defer upstream.Close()

	e := NewQoderExecutor(&config.Config{})
	e.UpstreamURLOverride = upstream.URL
	req := cliproxyexecutor.Request{
		Model:   "qoder/test",
		Payload: []byte(`{"messages":[{"role":"user","content":"hello"}]}`),
	}

	result, err := e.ExecuteStream(context.Background(), testQoderAuth(), req, cliproxyexecutor.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatal(chunk.Err)
		}
		got = append(got, string(chunk.Payload))
	}
	joined := strings.Join(got, "")
	if !strings.Contains(joined, `"content":"Hel"`) || !strings.Contains(joined, `"content":"lo"`) {
		t.Fatalf("streamed chunks missing content: %q", joined)
	}
}

func TestQoderPrepareRequest(t *testing.T) {
	e := NewQoderExecutor(&config.Config{})
	plaintext := []byte(`{"messages":[{"role":"user","content":"x"}]}`)
	req := httptest.NewRequest(http.MethodPost, "https://api3.qoder.sh/algo/api/v2/service/pro/sse/agent_chat_generation", strings.NewReader(string(plaintext)))
	err := e.PrepareRequest(req, testQoderAuth(), 1789964719080, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("X-Model-Key") != "qfmodel" {
		t.Fatalf("missing X-Model-Key")
	}
	if req.Header.Get("Cosy-User") != "test-uid-001" {
		t.Fatalf("missing Cosy-User")
	}
	if !strings.HasPrefix(req.Header.Get("Authorization"), "Bearer COSY.") {
		t.Fatalf("missing COSY auth")
	}
	// missing credentials error
	req2 := httptest.NewRequest(http.MethodPost, "https://api3.qoder.sh/algo/api/v2/service/pro/sse/agent_chat_generation", strings.NewReader(string(plaintext)))
	if err := e.PrepareRequest(req2, &cliproxyauth.Auth{Attributes: map[string]string{}}, 1789964719080, plaintext); err == nil {
		t.Fatal("expected error for missing creds")
	}
}

func TestQoderUserFromAuthMetadata(t *testing.T) {
	a := &cliproxyauth.Auth{
		Attributes: map[string]string{"uid": "u1"},
		Metadata:   map[string]any{"access_token": "jt-from-metadata"},
	}
	user, ok := qoderUserFromAuth(a)
	if !ok {
		t.Fatal("should resolve from metadata")
	}
	if user.Token != "jt-from-metadata" || user.UID != "u1" {
		t.Fatalf("wrong user: %+v", user)
	}
}

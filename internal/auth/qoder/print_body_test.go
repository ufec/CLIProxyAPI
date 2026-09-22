package qoder

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestPrintEncodedBody(t *testing.T) {
	bodyObj := map[string]any{
		"parameters": map[string]any{"reasoning_effort": "low", "enable_thinking": true, "max_tokens": int64(50), "context_length": int64(200000)},
		"business":   map[string]any{"product": "app", "version": "1.1.49", "type": "agent", "id": "test-print", "name": "CLIProxy Print Test", "begin_at": int64(1234567890000), "stage": "start"},
		"agent_id":   "agent_common", "task_id": "common", "session_type": "app",
		"model_config": map[string]any{"key": "qfmodel", "display_name": "Qwen3.8-Flash", "model": "", "format": "openai", "is_vl": true, "is_reasoning": true, "api_key": "", "url": "", "source": "system"},
		"system":      []any{map[string]any{"type": "text", "text": "You are a Qoder agent."}},
		"messages": []any{
			map[string]any{"role": "system", "content": []any{map[string]any{"type": "text", "text": "You are a Qoder agent."}}},
			map[string]any{"role": "user", "content": []any{map[string]any{"type": "text", "text": "say hi"}}}},
	}
	plain, _ := json.Marshal(bodyObj)
	enc := EncodeBody(plain)
	fmt.Printf("=== Encoded body ===\nlen=%d\nfirst120=%q\nlast80=%q\n", len(enc), enc[:min(120, len(enc))], enc[max(0, len(enc)-80):])
}

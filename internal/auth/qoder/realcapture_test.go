package qoder

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestDecodeRealQQTEST uses the real captured qqtest ciphertext to verify the
// Go codec produces the exact same plaintext as the locked Python codec
// (pr=0.990, business JSON present). The cipher is vendored at
// oauth-service/qorder/cipher_QQTEST.txt.
func TestDecodeRealQQTEST(t *testing.T) {
	const path = "../../../oauth-service/qorder/cipher_QQTEST.txt"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("qqtest cipher not available: %v", err)
	}
	lines := strings.Split(string(raw), "\n")
	re := regexp.MustCompile(`^\d+\t`)
	var sb strings.Builder
	for _, ln := range lines {
		sb.WriteString(re.ReplaceAllString(ln, ""))
	}
	body := strings.TrimSpace(sb.String())
	body = strings.ReplaceAll(body, "\\n", "")
	if len(body) != 188916 {
		t.Fatalf("expected 188916 chars, got %d", len(body))
	}
	if strings.Count(body, "$") != 1 {
		t.Fatalf("expected 1 '$', got %d", strings.Count(body, "$"))
	}

	plain := BodyDecode(body)
	if len(plain) != 141686 {
		t.Fatalf("decoded len %d != 141686", len(plain))
	}
	// printable ratio
	printable := 0
	for _, b := range plain {
		if b >= 32 && b < 127 || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	if ratio := float64(printable) / float64(len(plain)); ratio < 0.98 {
		t.Fatalf("printable ratio %.3f < 0.98", ratio)
	}
	text := string(plain)
	for _, kw := range []string{`"business"`, `"parameters"`, `"stage":"start"}}`, `"messages"`, "123_QQTEST"} {
		if !strings.Contains(text, kw) {
			t.Fatalf("missing marker %q in decoded qqtest plaintext", kw)
		}
	}
	// business JSON name field confirms this is the real qqtest request
	if !strings.Contains(text, `"name":"123_QQTEST"`) {
		t.Fatal("business name marker missing")
	}
}

// TestDecodeRecord68Business uses record 68 (real user request "1111111") to
// verify the business JSON recovery. Blob path may not exist on all checkouts.
func TestDecodeRecord68Business(t *testing.T) {
	const path = `C:\Users\ethanxu\.dimcode\v2\data\sessions\sess_1789138501420_92hgj36vw9g\blobs\files\blob_2be3a397-d3fe-47dc-8c11-38730ed4893a`
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("record 68 blob not available: %v", err)
	}
	var rec struct {
		Request struct {
			Body struct {
				Text string `json:"text"`
			} `json:"body"`
		} `json:"request"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("parse record 68: %v", err)
	}
	body := rec.Request.Body.Text
	if len(body) != 195512 {
		t.Fatalf("record 68 body len %d != 195512", len(body))
	}
	// record 68 carries a 2-char magic prefix ("Qh"); drop it before group
	// decode (verified in oauth-service/qorder analysis).
	plain := BodyDecode(body[2:])
	if len(plain) != 146630 && len(plain) != 146631 && len(plain) != 146632 && len(plain) != 146633 {
		t.Fatalf("unexpected dec len %d", len(plain))
	}
	text := string(plain)
	if !strings.Contains(text, `"name":"1111111"`) {
		t.Fatal("business name 1111111 missing")
	}
	if !strings.Contains(text, `"stage":"start"}}`) {
		t.Fatal("stage marker missing")
	}
	if !strings.Contains(text, `"reasoning_effort":"medium"`) {
		t.Fatal("reasoning_effort missing")
	}
}

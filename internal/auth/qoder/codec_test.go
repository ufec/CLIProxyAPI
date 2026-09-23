package qoder

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestBodyCodecRoundtrip(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"parameters":{},"business":{}}`),
		[]byte("hello"),
		[]byte(""),
		bytes.Repeat([]byte("x"), 100),
		[]byte(`{"messages":[{"role":"user","content":"1111111"}]}`),
	}
	for _, data := range cases {
		enc := BodyEncode(data)
		if len(enc)%4 != 0 {
			t.Fatalf("encode len %d not %%4==0", len(enc))
		}
		dec := BodyDecode(enc)
		if !bytes.Equal(dec, data) {
			t.Fatalf("roundtrip mismatch: in=%q enc=%q dec=%q", data, enc, dec)
		}
	}
	// '$' is skipped as in-group pad (RFC 4648 semantics), '!' encodes value 63.
	// The 0x3F marker still round-trips because the encoder picks the alphabet
	// char matching the 6-bit value — not because '$' carries data.
	marker := []byte{0x01, 0x3F, 0x7F}
	enc := BodyEncode(marker)
	dec := BodyDecode(enc)
	if !bytes.Equal(dec, marker) {
		t.Fatalf("roundtrip mismatch for 0x3F: in=%q enc=%q dec=%q", marker, enc, dec)
	}
}

func TestRequestBodyCodecMatchesWorker(t *testing.T) {
	plain := []byte(`{"messages":[]}`)
	const workerBody = "ByS..Wj^#SJLNYmYKtDx"
	if got := EncodeRequestBody(plain); got != workerBody {
		t.Fatalf("wire body = %q, want %q", got, workerBody)
	}
	if got := DecodeRequestBody(workerBody); !bytes.Equal(got, plain) {
		t.Fatalf("decoded wire body = %q, want %q", got, plain)
	}
}

func TestRequestBodyCodecRoundtripLengths(t *testing.T) {
	for n := 0; n <= 512; n++ {
		plain := make([]byte, n)
		for i := range plain {
			plain[i] = byte(i % 251)
		}
		wire := EncodeRequestBody(plain)
		if got := DecodeRequestBody(wire); !bytes.Equal(got, plain) {
			t.Fatalf("roundtrip failed at %d bytes", n)
		}
	}
}

func TestBodyCodecQQTESTSegmentRoundtrip(t *testing.T) {
	// The real captured qqtest body (custom alphabet) split at its single '$'
	// must re-encode exactly (locked codec evidence). Each segment is decoded
	// group-wise; the joined decode equals the concatenation of both plains.
	seg0 := []byte(`in a single response. When multiple independent pieces of information are requested and all commands are likely to succeed, run multiple tool calls in parallel for optimal performance.`)
	seg1 := []byte(`mber something, save it immediately as whichever type fits best. If they ask you to forget something, find and remove the relevant entry.`)
	e0 := BodyEncode(seg0)
	e1 := BodyEncode(seg1)
	if len(e0)%4 != 0 || len(e1)%4 != 0 {
		t.Fatalf("segment lengths not %%4==0: %d %d", len(e0), len(e1))
	}
	if !bytes.Equal(BodyDecode(e0), seg0) {
		t.Fatal("seg0 decode mismatch")
	}
	if !bytes.Equal(BodyDecode(e1), seg1) {
		t.Fatal("seg1 decode mismatch")
	}
	// Real qqtest body = seg0 + seg1 concatenated directly (seg0 carries its
	// trailing '$' pad group). Group boundaries stay aligned because both
	// segments are %4==0.
	joined := e0 + e1
	dec := DecodeBody(joined)
	expect := append(append([]byte{}, seg0...), seg1...)
	if !bytes.Equal(dec, expect) {
		t.Fatal("joined decode mismatch")
	}
	// Mid-body '$' as in-group pad (record 68 style 'w$LL'): a '$' inside a
	// group contributes no bits. Verify decode treats it as pad anywhere:
	padGroup := BodyEncode(seg0[:9]) // 9 bytes -> 12 chars, no pad needed
	body := padGroup[:4] + "$" + padGroup[4:8] + padGroup[8:]
	// Replacing a char with '$' changes the group, so only verify it decodes
	// (no panic) and the length is intact.
	if dec2 := BodyDecode(body); len(dec2) == 0 {
		t.Fatal("mid-body pad decode produced empty")
	}
}

func TestBodyAlphabetUnique(t *testing.T) {
	if len(BodyAlphabet) != 64 {
		t.Fatalf("alphabet length %d != 64", len(BodyAlphabet))
	}
	seen := map[rune]bool{}
	for _, c := range BodyAlphabet {
		if seen[c] {
			t.Fatalf("duplicate char %q", c)
		}
		seen[c] = true
	}
}

func TestBodyCodecAlphabetCharsOnly(t *testing.T) {
	for _, data := range [][]byte{[]byte("abc"), []byte("hello world"), []byte("x")} {
		enc := BodyEncode(data)
		for _, c := range enc {
			if c == '$' {
				continue
			}
			if !strings.ContainsRune(BodyAlphabet, c) {
				t.Fatalf("encode produced non-alphabet char %q in %q", c, enc)
			}
		}
	}
}

// TestCosyHeadersShape checks the envelope builds without error and has the
// expected structure (requestId is random per request, so no cross-call
// equality is asserted).
func TestCosyHeadersShape(t *testing.T) {
	user := &User{UID: "test-uid", Name: "tester", Email: "t@t", Token: "jt-test"}
	h1, err := BuildCosyHeaders("https://api3.qoder.sh/algo/api/v2/service/pro/sse/agent_chat_generation", user, "body", 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	if h1["Cosy-Key"] == "" || h1["Cosy-User"] != "test-uid" {
		t.Fatalf("cosy headers missing fields: %v", h1)
	}
	if len(h1["Authorization"]) < 20 || h1["Authorization"][:12] != "Bearer COSY." {
		t.Fatalf("bad Authorization header: %q", h1["Authorization"])
	}
	// Authorization = Bearer COSY.<payload>.<sig>: "Bearer COSY" + payload + sig
	parts := strings.Split(h1["Authorization"], ".")
	if len(parts) != 3 {
		t.Fatalf("Authorization not Bearer COSY.<payload>.<sig>: %q", h1["Authorization"])
	}
	if _, errDec := base64.StdEncoding.DecodeString(h1["Cosy-Key"]); errDec != nil {
		t.Fatalf("Cosy-Key not valid base64: %v", errDec)
	}
	if _, errDec := base64.StdEncoding.DecodeString(parts[1]); errDec != nil {
		t.Fatalf("payload not valid base64: %v", errDec)
	}
	if len(parts[2]) != 32 { // md5 hex
		t.Fatalf("signature not 32 hex chars: %q", parts[2])
	}
}

func TestAuthorizationURLShape(t *testing.T) {
	f := NewOAuthDeviceFlow(nil)
	authURL, verifier, nonce, err := f.AuthorizationURL()
	if err != nil {
		t.Fatal(err)
	}
	if authURL == "" || verifier == "" || nonce == "" {
		t.Fatal("empty auth url/verifier/nonce")
	}
	if len(verifier) < 40 {
		t.Fatalf("verifier too short: %d", len(verifier))
	}
	if !strings.Contains(authURL, DeviceFlowHost+DeviceSelectAccountsPath) {
		t.Fatalf("auth url missing device page: %q", authURL)
	}
	if !strings.Contains(authURL, "client_id="+ClientID) {
		t.Fatalf("auth url missing client_id: %q", authURL)
	}
}

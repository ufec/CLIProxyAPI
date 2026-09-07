package dimagent

import (
	"strings"
	"testing"
)

// TestS256ChallengeRFC7636Vector verifies the S256 challenge computation
// against the known test vector from RFC 7636 Appendix B.
func TestS256ChallengeRFC7636Vector(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const want = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := S256Challenge(verifier); got != want {
		t.Fatalf("S256Challenge = %q, want %q", got, want)
	}
}

func TestGeneratePKCECodesFormat(t *testing.T) {
	codes, err := GeneratePKCECodes()
	if err != nil {
		t.Fatalf("GeneratePKCECodes: %v", err)
	}
	if len(codes.CodeVerifier) != 86 {
		t.Errorf("verifier length = %d, want 86", len(codes.CodeVerifier))
	}
	if len(codes.CodeChallenge) != 43 {
		t.Errorf("challenge length = %d, want 43", len(codes.CodeChallenge))
	}
	if S256Challenge(codes.CodeVerifier) != codes.CodeChallenge {
		t.Error("challenge does not match S256(verifier)")
	}
	// Two generations must differ.
	other, err := GeneratePKCECodes()
	if err != nil {
		t.Fatalf("GeneratePKCECodes second: %v", err)
	}
	if codes.CodeVerifier == other.CodeVerifier {
		t.Error("two generated verifiers are identical")
	}
}

func TestGenerateStateFormat(t *testing.T) {
	state, err := GenerateState()
	if err != nil {
		t.Fatalf("GenerateState: %v", err)
	}
	if len(state) != 43 {
		t.Errorf("state length = %d, want 43", len(state))
	}
	if strings.ContainsAny(state, "+/=") {
		t.Errorf("state contains non-urlsafe characters: %q", state)
	}
}

func TestGenerateAuthURL(t *testing.T) {
	c := NewClient(nil, "")
	codes, err := GeneratePKCECodes()
	if err != nil {
		t.Fatalf("GeneratePKCECodes: %v", err)
	}
	state, err := GenerateState()
	if err != nil {
		t.Fatalf("GenerateState: %v", err)
	}
	got, err := c.GenerateAuthURL(state, codes)
	if err != nil {
		t.Fatalf("GenerateAuthURL: %v", err)
	}
	for _, want := range []string{
		"https://dimagent.cn/oauth/authorize",
		"response_type=code",
		"client_id=f025fda6d5014fd2b6d4aba45cd8b2b6",
		"redirect_uri=http%3A%2F%2Flocalhost%3A54321%2Fauth%2Fcallback",
		"code_challenge_method=S256",
		"source=app",
		"state=" + state,
		"code_challenge=" + codes.CodeChallenge,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("auth URL missing %q in %q", want, got)
		}
	}
	if _, err := c.GenerateAuthURL("", codes); err == nil {
		t.Error("GenerateAuthURL with empty state should fail")
	}
	if _, err := c.GenerateAuthURL(state, nil); err == nil {
		t.Error("GenerateAuthURL with nil pkce should fail")
	}
}

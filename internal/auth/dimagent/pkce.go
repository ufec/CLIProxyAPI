package dimagent

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// PKCECodes holds the verification codes for the OAuth2 PKCE
// (Proof Key for Code Exchange) flow.
type PKCECodes struct {
	// CodeVerifier is the cryptographically random string used to correlate
	// the authorization request with the token request.
	CodeVerifier string `json:"code_verifier"`
	// CodeChallenge is the S256 transformation of the code verifier.
	CodeChallenge string `json:"code_challenge"`
}

// S256Challenge computes the OAuth 2.0 PKCE S256 challenge for a verifier:
// the unpadded base64url encoding of SHA-256 over the verifier ASCII string.
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// GeneratePKCECodes creates a new PKCE verifier/challenge pair matching the
// DimAgent desktop client behavior: the verifier is the unpadded base64url
// encoding of 64 random bytes (86 chars) and the challenge is the unpadded
// base64url encoding of SHA-256 over the verifier ASCII string (43 chars).
func GeneratePKCECodes() (*PKCECodes, error) {
	verifierBytes := make([]byte, 64)
	if _, err := rand.Read(verifierBytes); err != nil {
		return nil, fmt.Errorf("failed to generate pkce verifier: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)

	return &PKCECodes{
		CodeVerifier:  verifier,
		CodeChallenge: S256Challenge(verifier),
	}, nil
}

// GenerateState creates a random OAuth state value: the unpadded base64url
// encoding of 32 random bytes (43 chars), matching the desktop client.
func GenerateState() (string, error) {
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(stateBytes), nil
}

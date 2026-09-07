package dimagent

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
	log "github.com/sirupsen/logrus"
)

// TokenStorage stores OAuth credentials and account metadata for DimAgent.
type TokenStorage struct {
	// AccessToken is the bearer token used for API requests.
	AccessToken string `json:"access_token"`
	// RefreshToken is used to obtain a new access token.
	RefreshToken string `json:"refresh_token"`
	// TokenType is the token type, typically "Bearer".
	TokenType string `json:"token_type,omitempty"`
	// Scope is the authorization scope granted to the token.
	Scope string `json:"scope,omitempty"`
	// Expired is the RFC3339 timestamp when the access token expires.
	Expired string `json:"expired,omitempty"`
	// Type indicates the provider, always "dimagent" for this storage.
	Type string `json:"type"`
	// UID is the account uid claim from the token JWT.
	UID string `json:"uid,omitempty"`
	// Sub is the account subject claim from the token JWT.
	Sub string `json:"sub,omitempty"`
	// Nickname is the account display name from the id_token.
	Nickname string `json:"nickname,omitempty"`
	// EnabledModels lists the model IDs the account can call, synced from /v1/models.
	EnabledModels []string `json:"enabled_models,omitempty"`
	// ModelsMeta stores the parsed model metadata JSON from /v1/models.
	ModelsMeta string `json:"models_meta,omitempty"`

	// Metadata holds arbitrary key-value pairs injected via hooks.
	// It is not exported to JSON directly to allow flattening during serialization.
	Metadata map[string]any `json:"-"`
}

// SetMetadata allows external callers to inject metadata into the storage before saving.
func (ts *TokenStorage) SetMetadata(meta map[string]any) {
	ts.Metadata = meta
}

// SaveTokenToFile serializes the token storage to a JSON file.
func (ts *TokenStorage) SaveTokenToFile(authFilePath string) error {
	misc.LogSavingCredentials(authFilePath)
	ts.Type = ProviderKey

	if err := os.MkdirAll(filepath.Dir(authFilePath), 0o700); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	data, errMerge := misc.MergeMetadata(ts, ts.Metadata)
	if errMerge != nil {
		return fmt.Errorf("failed to merge metadata: %w", errMerge)
	}

	f, err := os.Create(authFilePath)
	if err != nil {
		return fmt.Errorf("failed to create token file: %w", err)
	}
	defer func() {
		if errClose := f.Close(); errClose != nil {
			log.Errorf("dimagent token storage: close token file error: %v", errClose)
		}
	}()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	if err = encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to write token to file: %w", err)
	}
	return nil
}

// IsExpired checks whether the access token is expired.
func (ts *TokenStorage) IsExpired() bool {
	if ts.Expired == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, ts.Expired)
	if err != nil {
		return true
	}
	return time.Now().After(t)
}

// jwtClaims holds the account claims parsed from the DimAgent token JWTs.
type jwtClaims struct {
	Sub               string `json:"sub"`
	UID               string `json:"uid"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
}

// parseJWTClaims decodes the payload segment of an unsigned-inspection JWT.
// The signature is not verified here; the claims are only used for display
// metadata and expiration bookkeeping.
func parseJWTClaims(token string) (*jwtClaims, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a jwt")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Tolerate padded encodings.
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("decode jwt payload: %w", err)
		}
	}
	var claims jwtClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parse jwt claims: %w", err)
	}
	return &claims, nil
}

// ApplyTokenClaims fills account metadata (uid, sub, nickname) on the storage
// from the id_token (preferred) or access token claims.
func (ts *TokenStorage) ApplyTokenClaims(idToken, accessToken string) {
	for _, candidate := range []string{idToken, accessToken} {
		claims, err := parseJWTClaims(candidate)
		if err != nil {
			continue
		}
		if ts.UID == "" {
			ts.UID = claims.UID
		}
		if ts.Sub == "" {
			ts.Sub = claims.Sub
		}
		if ts.Nickname == "" {
			ts.Nickname = claims.PreferredUsername
			if ts.Nickname == "" {
				ts.Nickname = claims.Name
			}
		}
		if ts.UID != "" && ts.Sub != "" && ts.Nickname != "" {
			return
		}
	}
}

// NewTokenStorage builds a TokenStorage from an OAuth token response.
func NewTokenStorage(token *TokenResponse) *TokenStorage {
	if token == nil {
		return &TokenStorage{Type: ProviderKey}
	}
	storage := &TokenStorage{
		AccessToken:  strings.TrimSpace(token.AccessToken),
		RefreshToken: strings.TrimSpace(token.RefreshToken),
		TokenType:    strings.TrimSpace(token.TokenType),
		Scope:        strings.TrimSpace(token.Scope),
		Expired:      token.ExpirationTime().UTC().Format(time.RFC3339),
		Type:         ProviderKey,
	}
	if storage.TokenType == "" {
		storage.TokenType = "Bearer"
	}
	storage.ApplyTokenClaims(token.IDToken, token.AccessToken)
	return storage
}

// AccountLabel returns a short human-readable label for the account.
func (ts *TokenStorage) AccountLabel() string {
	if ts == nil {
		return ProviderKey
	}
	if ts.Nickname != "" {
		return ProviderKey + ":" + ts.Nickname
	}
	if ts.Sub != "" {
		return ProviderKey + ":" + ts.Sub
	}
	return ProviderKey
}

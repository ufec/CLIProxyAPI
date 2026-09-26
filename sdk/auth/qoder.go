package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/qoder"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/browser"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// QoderAuthenticator implements the Qoder device-flow login (dt- -> jt-).
type QoderAuthenticator struct{}

// NewQoderAuthenticator constructs a new Qoder authenticator.
func NewQoderAuthenticator() Authenticator {
	return &QoderAuthenticator{}
}

// Provider returns the provider key for qoder.
func (QoderAuthenticator) Provider() string {
	return "qoder"
}

// RefreshLead refreshes Qoder job tokens five minutes before expiry.
func (QoderAuthenticator) RefreshLead() *time.Duration {
	return new(5 * time.Minute)
}

// Login initiates the Qoder device flow authentication.
func (a QoderAuthenticator) Login(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*coreauth.Auth, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cliproxy auth: configuration is required")
	}
	if opts == nil {
		opts = &LoginOptions{}
	}

	flow := qoder.NewOAuthDeviceFlow(nil)
	authURL, verifier, nonce, err := flow.AuthorizationURL()
	if err != nil {
		return nil, fmt.Errorf("qoder: build authorization url: %w", err)
	}

	fmt.Printf("\nTo authenticate, please visit:\n%s\n\n", authURL)
	if !opts.NoBrowser {
		if browser.IsAvailable() {
			if errOpen := browser.OpenURL(authURL); errOpen != nil {
				log.Warnf("Failed to open browser automatically: %v", errOpen)
			} else {
				fmt.Println("Browser opened automatically.")
			}
		}
	}

	fmt.Println("Waiting for authorization...")

	dt, err := flow.PollDeviceToken(ctx, nonce, verifier, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("qoder: device token poll: %w", err)
	}
	jt, err := flow.JobToken(ctx, dt.Token)
	if err != nil {
		return nil, fmt.Errorf("qoder: job token: %w", err)
	}

	uid := strings.TrimSpace(dt.UserID)
	fileName := fmt.Sprintf("qoder-%d.json", time.Now().UnixMilli())

	// Available models are optional; re-synced on login. Fetched live from the
	// provider so the gateway does not depend on the embedded models.json
	// catalog (which the remote updater overwrites without a qoder section).
	var models []qoder.ModelInfo
	if modelsData, modelsErr := qoder.FetchModels(ctx, flow.HTTPClient(), qoder.APIHost, uid, jt.Token); modelsErr != nil {
		log.Warnf("qoder: failed to fetch models: %v", modelsErr)
	} else if parsed, parseErr := qoder.ParseModels(modelsData); parseErr != nil {
		log.Warnf("qoder: failed to parse models: %v", parseErr)
	} else {
		models = parsed
	}

	metadata := map[string]any{
		"type":                  "qoder",
		"access_token":          jt.Token,
		"security_oauth_token":  jt.Token,
		"uid":                   uid,
		"x-gw-user-id":          uid,
		"timestamp":             time.Now().UnixMilli(),
		"expires_in":            jt.ExpiresIn,
		"redirect_uri_protocol": "device",
		"device_token":          dt.Token,
		"device_refresh_token":  dt.RefreshToken,
	}
	if jt.ExpiresIn > 0 {
		metadata["expires_at"] = time.Now().Add(time.Duration(jt.ExpiresIn) * time.Second).UnixMilli()
	}
	if jt.RefreshToken != "" {
		metadata["refresh_token"] = jt.RefreshToken
	}
	if len(models) > 0 {
		ids := make([]string, 0, len(models))
		for _, m := range models {
			ids = append(ids, m.ID())
		}
		metadata["enabled_models"] = ids
		if raw, marshalErr := json.Marshal(models); marshalErr == nil {
			metadata["models_meta"] = string(raw)
		}
	}

	fmt.Println("\nQoder authentication successful!")

	return &coreauth.Auth{
		ID:       fileName,
		Provider: a.Provider(),
		FileName: fileName,
		Label:    "Qoder User",
		Metadata: metadata,
		Attributes: map[string]string{
			"uid":                  uid,
			"security_oauth_token": jt.Token,
		},
	}, nil
}

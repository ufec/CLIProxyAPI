package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/dimagent"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/browser"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// dimagentRefreshLead is the duration before token expiry when refresh should occur.
var dimagentRefreshLead = 24 * time.Hour

// DimAgentAuthenticator implements the OAuth authorization code + PKCE login
// flow for DimAgent (dimagent.cn).
type DimAgentAuthenticator struct{}

// NewDimAgentAuthenticator constructs a new DimAgent authenticator.
func NewDimAgentAuthenticator() Authenticator {
	return &DimAgentAuthenticator{}
}

// Provider returns the provider key for dimagent.
func (DimAgentAuthenticator) Provider() string {
	return dimagent.ProviderKey
}

// RefreshLead returns the duration before token expiry when refresh should occur.
func (DimAgentAuthenticator) RefreshLead() *time.Duration {
	return &dimagentRefreshLead
}

// Login runs the DimAgent OAuth flow: generate PKCE codes and state, start the
// local callback server on the fixed redirect port (54321), open the browser,
// wait for the authorization callback (or a manually pasted callback URL),
// exchange the code for tokens, and fetch the account's model list.
//
// The callback port is fixed by the upstream OAuth registration and therefore
// ignores opts.CallbackPort.
func (a DimAgentAuthenticator) Login(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*coreauth.Auth, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cliproxy auth: configuration is required")
	}
	if opts == nil {
		opts = &LoginOptions{}
	}
	if ctx == nil {
		ctx = context.Background()
	}

	client := dimagent.NewClient(cfg, "")

	pkceCodes, err := dimagent.GeneratePKCECodes()
	if err != nil {
		return nil, fmt.Errorf("dimagent: pkce generation failed: %w", err)
	}
	state, err := dimagent.GenerateState()
	if err != nil {
		return nil, fmt.Errorf("dimagent: state generation failed: %w", err)
	}

	oauthServer := dimagent.NewOAuthServer(dimagent.CallbackPort)
	if err = oauthServer.Start(); err != nil {
		if strings.Contains(err.Error(), "already in use") {
			return nil, fmt.Errorf("dimagent: callback port %d is unavailable; %w", dimagent.CallbackPort, err)
		}
		return nil, fmt.Errorf("dimagent: callback server start failed: %w", err)
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if stopErr := oauthServer.Stop(stopCtx); stopErr != nil {
			log.Warnf("dimagent oauth server stop error: %v", stopErr)
		}
	}()

	authURL, err := client.GenerateAuthURL(state, pkceCodes)
	if err != nil {
		return nil, fmt.Errorf("dimagent: authorization url generation failed: %w", err)
	}

	fmt.Println("Starting DimAgent authentication...")
	if !opts.NoBrowser {
		if !browser.IsAvailable() {
			log.Warn("No browser available; please open the URL manually")
			util.PrintSSHTunnelInstructions(dimagent.CallbackPort)
			fmt.Printf("Visit the following URL to continue authentication:\n%s\n", authURL)
		} else if errOpen := browser.OpenURL(authURL); errOpen != nil {
			log.Warnf("Failed to open browser automatically: %v", errOpen)
			util.PrintSSHTunnelInstructions(dimagent.CallbackPort)
			fmt.Printf("Visit the following URL to continue authentication:\n%s\n", authURL)
		}
	} else {
		util.PrintSSHTunnelInstructions(dimagent.CallbackPort)
		fmt.Printf("Visit the following URL to continue authentication:\n%s\n", authURL)
	}

	fmt.Println("Waiting for DimAgent authentication callback...")

	result, err := waitForDimAgentCallback(ctx, oauthServer, opts)
	if err != nil {
		return nil, err
	}
	if result.Error != "" {
		return nil, fmt.Errorf("dimagent: authorization failed: %s", result.Error)
	}
	if result.State != state {
		return nil, fmt.Errorf("dimagent: state mismatch in callback")
	}

	token, err := client.ExchangeCodeForTokens(ctx, result.Code, pkceCodes)
	if err != nil {
		return nil, fmt.Errorf("dimagent: %w", err)
	}

	storage := dimagent.NewTokenStorage(token)

	// Available models are optional; the executor re-syncs them on refresh.
	var models []dimagent.ModelInfo
	if modelsData, modelsErr := client.FetchModels(ctx, token.AccessToken); modelsErr != nil {
		log.Warnf("dimagent: failed to fetch models: %v", modelsErr)
	} else if parsed, parseErr := dimagent.ParseModels(modelsData); parseErr != nil {
		log.Warnf("dimagent: failed to parse models: %v", parseErr)
	} else {
		models = parsed
	}
	if len(models) > 0 {
		ids := make([]string, 0, len(models))
		for _, m := range models {
			ids = append(ids, m.ID)
		}
		storage.EnabledModels = ids
		if raw, marshalErr := json.Marshal(models); marshalErr == nil {
			storage.ModelsMeta = string(raw)
		}
	}

	metadata := map[string]any{
		"type":          dimagent.ProviderKey,
		"access_token":  storage.AccessToken,
		"refresh_token": storage.RefreshToken,
		"token_type":    storage.TokenType,
		"timestamp":     time.Now().UnixMilli(),
	}
	if storage.Scope != "" {
		metadata["scope"] = storage.Scope
	}
	if storage.UID != "" {
		metadata["uid"] = storage.UID
	}
	if storage.Sub != "" {
		metadata["sub"] = storage.Sub
	}
	if storage.Nickname != "" {
		metadata["nickname"] = storage.Nickname
	}
	if storage.Expired != "" {
		metadata["expired"] = storage.Expired
	}
	if len(storage.EnabledModels) > 0 {
		metadata["enabled_models"] = storage.EnabledModels
	}
	if storage.ModelsMeta != "" {
		metadata["models_meta"] = storage.ModelsMeta
	}

	fileName := fmt.Sprintf("%s-%d.json", dimagent.ProviderKey, time.Now().UnixMilli())

	label := storage.AccountLabel()

	fmt.Println("\nDimAgent authentication successful!")

	return &coreauth.Auth{
		ID:       fileName,
		Provider: a.Provider(),
		FileName: fileName,
		Label:    label,
		Storage:  storage,
		Metadata: metadata,
	}, nil
}

// waitForDimAgentCallback blocks until the local callback server captures the
// OAuth redirect or the user pastes the callback URL manually. It mirrors the
// Codex login flow: after a grace period a manual-paste prompt is offered when
// a prompt function is available.
func waitForDimAgentCallback(ctx context.Context, server *dimagent.OAuthServer, opts *LoginOptions) (*dimagent.OAuthResult, error) {
	callbackCh := make(chan *dimagent.OAuthResult, 1)
	callbackErrCh := make(chan error, 1)
	go func() {
		result, errWait := server.WaitForCallback(5 * time.Minute)
		if errWait != nil {
			callbackErrCh <- errWait
			return
		}
		callbackCh <- result
	}()

	var manualPromptTimer *time.Timer
	var manualPromptC <-chan time.Time
	if opts != nil && opts.Prompt != nil {
		manualPromptTimer = time.NewTimer(15 * time.Second)
		manualPromptC = manualPromptTimer.C
		defer manualPromptTimer.Stop()
	}

	var manualInputCh <-chan string
	var manualInputErrCh <-chan error
	var err error

	for {
		select {
		case result := <-callbackCh:
			return result, nil
		case err = <-callbackErrCh:
			if strings.Contains(err.Error(), "timeout") {
				return nil, fmt.Errorf("dimagent: %w", err)
			}
			return nil, err
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-manualPromptC:
			manualPromptC = nil
			if manualPromptTimer != nil {
				manualPromptTimer.Stop()
			}
			select {
			case result := <-callbackCh:
				return result, nil
			case err = <-callbackErrCh:
				if strings.Contains(err.Error(), "timeout") {
					return nil, fmt.Errorf("dimagent: %w", err)
				}
				return nil, err
			default:
			}
			manualInputCh, manualInputErrCh = misc.AsyncPrompt(opts.Prompt, "Paste the DimAgent callback URL (or press Enter to keep waiting): ")
			continue
		case input := <-manualInputCh:
			manualInputCh = nil
			manualInputErrCh = nil
			parsed, errParse := misc.ParseOAuthCallback(input)
			if errParse != nil {
				return nil, errParse
			}
			if parsed == nil {
				continue
			}
			result := &dimagent.OAuthResult{
				Code:  parsed.Code,
				State: parsed.State,
				Error: parsed.Error,
			}
			if parsed.ErrorDescription != "" && result.Error == "" {
				result.Error = parsed.ErrorDescription
			}
			return result, nil
		case errManual := <-manualInputErrCh:
			return nil, errManual
		}
	}
}

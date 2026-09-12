package cmd

import (
	"context"
	"fmt"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codebuddy"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	log "github.com/sirupsen/logrus"
)

// DoCodeBuddyLogin triggers the state-based authorization flow for CodeBuddy
// CN (WorkBuddy, Tencent copilot) and saves tokens. It generates an
// authorization URL, waits for the user to complete browser authorization,
// and then saves the exchanged tokens together with the account's available
// models.
//
// Parameters:
//   - cfg: The application configuration containing proxy and auth directory settings
//   - options: Login options including browser behavior settings
func DoCodeBuddyLogin(cfg *config.Config, options *LoginOptions) {
	doCodeBuddyLogin(cfg, options, nil)
}

// DoCodeBuddyIntlLogin triggers the state-based authorization flow for the
// CodeBuddy/WorkBuddy international deployment (workbuddy.ai) and saves
// tokens. See DoCodeBuddyLogin for the shared flow description.
func DoCodeBuddyIntlLogin(cfg *config.Config, options *LoginOptions) {
	doCodeBuddyLogin(cfg, options, codebuddy.RegionIntl)
}

// doCodeBuddyLogin runs the region-aware CodeBuddy (WorkBuddy) login flow.
func doCodeBuddyLogin(cfg *config.Config, options *LoginOptions, region *codebuddy.Region) {
	if options == nil {
		options = &LoginOptions{}
	}
	if region == nil {
		region = codebuddy.RegionCN
	}

	manager := newAuthManager()
	authOpts := &sdkAuth.LoginOptions{
		NoBrowser: options.NoBrowser,
		Metadata:  map[string]string{},
		Prompt:    options.Prompt,
	}

	record, savedPath, err := manager.Login(context.Background(), region.Provider, cfg, authOpts)
	if err != nil {
		log.Errorf("%s authentication failed: %v", region.Label, err)
		return
	}

	if savedPath != "" {
		fmt.Printf("Authentication saved to %s\n", savedPath)
	}
	if record != nil && record.Label != "" {
		fmt.Printf("Authenticated as %s\n", record.Label)
	}
	fmt.Printf("%s authentication successful!\n", region.Label)
}

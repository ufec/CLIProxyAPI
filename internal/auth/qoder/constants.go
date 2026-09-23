// Package qoder provides OAuth device-flow authentication and COSY request
// signing for the Qoder provider (api3.qoder.sh agent_chat_generation SSE API).
//
// The protocol was reverse-engineered from the Qoder desktop client and
// verified end-to-end with live captures. See oauth-service/qorder/ in the
// repository root for the Python reference implementation and captured evidence
// (QODER_CODEC_FINAL.md).
package qoder

import (
	"strings"

	"github.com/google/uuid"
)

// OAuth device-flow configuration (verified against live captures).
const (
	// ClientID is Qoder's real device-flow client id (from record 482 jobToken).
	ClientID = "732aef47-9cf2-46a2-95fe-4cebb5d0d1fa"

	// DeviceFlowHost is the device-flow authorization page host.
	DeviceFlowHost = "https://qoder.com"

	// OpenAPIHost is the API host for token polling / job token exchange.
	OpenAPIHost = "https://openapi.qoder.sh"

	// APIHost is the model inference API host.
	APIHost = "https://api3.qoder.sh"

	// RedirectURI is Qoder's app scheme used by the device flow.
	RedirectURI = "qoder-app://"
)

// API endpoints.
const (
	DeviceSelectAccountsPath = "/device/selectAccounts"
	DeviceTokenPollPath      = "/api/v1/deviceToken/poll"
	JobTokenPath             = "/api/v1/me/jobToken"
	JobTokenRefreshPath      = "/api/v1/jobToken/refresh"
	// AgentChatGenerationPath is the SSE chat endpoint (Encode=1 => custom
	// base64 body codec).
	AgentChatGenerationPath = "/algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1"
)

// CredentialFileName returns the filename used to persist Qoder credentials.
func CredentialFileName(email string) string {
	if email == "" {
		return "qoder.json"
	}
	return "qoder-" + email + ".json"
}

// ProviderKey is the provider identifier used across the gateway.
const ProviderKey = "qoder"

// NewID returns a fresh UUID without dashes.
func NewID() string {
	return strings.ReplaceAll(uuid.NewString(), "-", "")
}

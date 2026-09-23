package management

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	qoderauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/qoder"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// GetQoderUsage returns Qoder account usage for a selected auth file.
func (h *Handler) GetQoderUsage(c *gin.Context) {
	index := strings.TrimSpace(c.Query("auth_index"))
	auth := h.authByIndex(index)
	if auth == nil || auth.Provider != qoderauth.ProviderKey {
		c.JSON(http.StatusNotFound, gin.H{"error": "qoder credential not found"})
		return
	}
	deviceToken := qoderMetadataString(auth, "device_token")
	if deviceToken == "" {
		c.JSON(http.StatusConflict, gin.H{"error": "qoder device token missing; sign in again"})
		return
	}
	client := h.qoderUsageClient
	if client == nil {
		client = &http.Client{Transport: h.apiCallTransport(auth, "")}
	}
	usage, err := qoderauth.FetchUsage(c.Request.Context(), client, h.qoderUsageBaseURL, deviceToken)
	if isQoderUsageUnauthorized(err) {
		deviceToken, err = h.refreshQoderDeviceToken(c, index, deviceToken, client)
		if err == nil {
			usage, err = qoderauth.FetchUsage(c.Request.Context(), client, h.qoderUsageBaseURL, deviceToken)
		}
	}
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, errQoderReloginRequired) {
			status = http.StatusConflict
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "application/json", usage)
}

var errQoderReloginRequired = errors.New("qoder device credential expired; sign in again")

func isQoderUsageUnauthorized(err error) bool {
	var upstream *qoderauth.UsageHTTPError
	return errors.As(err, &upstream) && (upstream.StatusCode == http.StatusUnauthorized || upstream.StatusCode == http.StatusForbidden)
}

func qoderMetadataString(auth *coreauth.Auth, key string) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	value, _ := auth.Metadata[key].(string)
	return strings.TrimSpace(value)
}

func (h *Handler) refreshQoderDeviceToken(c *gin.Context, index, attemptedToken string, client *http.Client) (string, error) {
	h.qoderRefreshMu.Lock()
	defer h.qoderRefreshMu.Unlock()

	latest := h.authByIndex(index)
	if latest == nil || latest.Provider != qoderauth.ProviderKey {
		return "", errQoderReloginRequired
	}
	if current := qoderMetadataString(latest, "device_token"); current != "" && current != attemptedToken {
		return current, nil
	}
	refreshToken := qoderMetadataString(latest, "device_refresh_token")
	if refreshToken == "" {
		return "", errQoderReloginRequired
	}
	refreshURL := h.qoderDeviceRefreshURL
	if refreshURL == "" {
		refreshURL = qoderauth.OpenAPIHost + qoderauth.DeviceTokenRefreshPath
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()
	rotated, err := qoderauth.RefreshDeviceToken(ctx, client, refreshURL, refreshToken)
	if err != nil {
		var upstream *qoderauth.DeviceTokenRefreshHTTPError
		if errors.As(err, &upstream) && (upstream.StatusCode == http.StatusBadRequest || upstream.StatusCode == http.StatusUnauthorized || upstream.StatusCode == http.StatusForbidden) {
			return "", errQoderReloginRequired
		}
		return "", err
	}
	updated := latest.Clone()
	if updated.Metadata == nil {
		updated.Metadata = make(map[string]any)
	}
	updated.Metadata["device_token"] = rotated.Token
	updated.Metadata["device_refresh_token"] = rotated.RefreshToken
	if _, err := h.saveTokenRecord(c.Request.Context(), updated); err != nil {
		return "", errors.New("qoder device token refresh could not be saved")
	}
	return rotated.Token, nil
}

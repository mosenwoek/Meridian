package main

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// cloudflareSettingsStatus is the non-secret view of the stored Cloudflare
// credentials. The token itself is never returned, only whether one is stored.
type cloudflareSettingsStatus struct {
	Configured  bool   `json:"configured"`
	ACMEEnabled bool   `json:"acme_enabled"`
	Email       string `json:"email"`
	Provider    string `json:"provider"`
	Error       string `json:"error,omitempty"`
}

func (a *App) cloudflareStatus() (cloudflareSettingsStatus, error) {
	settings, err := a.db.PanelSettings()
	if err != nil {
		return cloudflareSettingsStatus{}, err
	}
	status := cloudflareSettingsStatus{
		Configured: settings.ACMETokenCiphertext != "",
		Email:      settings.ACMEEmail,
		Provider:   "cloudflare",
	}
	if status.Provider == "" {
		status.Provider = "cloudflare"
	}
	status.ACMEEnabled = settings.TLSEnabled && settings.CertificateSource == "acme"
	return status, nil
}

// GET  /api/cloudflare  -> non-secret status
// POST /api/cloudflare  -> save token (encrypted), optional email
func (a *App) handleCloudflareSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Cache-Control", "no-store")
		status, err := a.cloudflareStatus()
		if err != nil {
			a.jsonErr(w, http.StatusInternalServerError, "failed to read panel settings")
			return
		}
		a.jsonOK(w, status)
		return
	case http.MethodPost:
	default:
		a.jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	unlock, ok := a.beginPanelConfiguration(w)
	if !ok {
		return
	}
	defer unlock()

	var req struct {
		APIToken string `json:"dns_api_token"`
		Email    string `json:"email"`
	}
	if err := decodeJSONBody(w, r, &req); err != nil {
		a.jsonErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	settings, err := a.db.PanelSettings()
	if err != nil {
		a.jsonErr(w, http.StatusInternalServerError, "failed to read panel settings")
		return
	}
	email := strings.TrimSpace(req.Email)
	if email == "" {
		email = settings.ACMEEmail
	}
	token := strings.TrimSpace(req.APIToken)
	if token == "" {
		// Email-only updates keep the stored token untouched.
		if settings.ACMETokenCiphertext == "" {
			a.jsonErr(w, http.StatusBadRequest, "请填写 Cloudflare DNS API Token")
			return
		}
		if err := validatePanelCertificateEmail(email); err != nil {
			a.jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		provider := settings.ACMEDNSProvider
		if provider == "" {
			provider = "cloudflare"
		}
		if err := a.db.SavePanelACMECredentials(email, provider, settings.ACMETokenCiphertext, settings.ACMEStaging); err != nil {
			a.jsonErr(w, http.StatusInternalServerError, "保存 Cloudflare 凭据失败")
			return
		}
		status, err := a.cloudflareStatus()
		if err != nil {
			a.jsonErr(w, http.StatusInternalServerError, "failed to read panel settings")
			return
		}
		a.jsonOK(w, status)
		return
	}
	if err := validatePanelCertificateRequest(email, token); err != nil {
		a.jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if jwtSecretEphemeral {
		a.jsonErr(w, http.StatusConflict, "当前 JWT_SECRET 不是持久密钥，无法安全保存 Cloudflare 凭据；请先配置稳定密钥")
		return
	}
	ciphertext, err := encryptPanelACMEToken(token)
	if err != nil {
		a.jsonErr(w, http.StatusInternalServerError, "无法加密 Cloudflare DNS API Token")
		return
	}
	provider := settings.ACMEDNSProvider
	if provider == "" {
		provider = "cloudflare"
	}
	if err := a.db.SavePanelACMECredentials(email, provider, ciphertext, settings.ACMEStaging); err != nil {
		a.jsonErr(w, http.StatusInternalServerError, "保存 Cloudflare 凭据失败")
		return
	}
	log.Printf("cloudflare DNS credentials updated (email set: %t)", email != "")
	status, err := a.cloudflareStatus()
	if err != nil {
		a.jsonErr(w, http.StatusInternalServerError, "failed to read panel settings")
		return
	}
	a.jsonOK(w, status)
}

// POST /api/cloudflare/test validates a token (provided or stored) against the
// Cloudflare API and returns the visible zones. Read-only: nothing is persisted.
func (a *App) handleCloudflareTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		APIToken string `json:"dns_api_token"`
	}
	if err := decodeJSONBody(w, r, &req); err != nil {
		a.jsonErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	settings, err := a.db.PanelSettings()
	if err != nil {
		a.jsonErr(w, http.StatusInternalServerError, "failed to read panel settings")
		return
	}
	token := strings.TrimSpace(req.APIToken)
	if token == "" {
		if settings.ACMETokenCiphertext == "" {
			a.jsonErr(w, http.StatusBadRequest, "尚未保存 Cloudflare DNS API Token")
			return
		}
		token, err = decryptPanelACMEToken(settings.ACMETokenCiphertext)
		if err != nil {
			a.jsonErr(w, http.StatusConflict, "已保存的 Token 无法解密，请重新填写")
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	client := &cloudflareClient{token: token, httpClient: &http.Client{Timeout: 15 * time.Second}, apiBase: "https://api.cloudflare.com/client/v4"}
	zones, err := client.listZones(ctx)
	if err != nil {
		message := strings.ReplaceAll(err.Error(), token, "[已隐藏]")
		a.jsonOK(w, map[string]interface{}{"success": false, "message": message})
		return
	}
	a.jsonOK(w, map[string]interface{}{
		"success": true,
		"zones":   zones,
		"message": "连接正常",
	})
}

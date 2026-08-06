// Package apix contains the HTTP clients the auto-signer uses to talk to APIX over its two
// channels: provisioning (account-scoped, ApiKeyV2) and signing (signer-scoped, P-256 ECDSA).
package apix

import (
	"net/http"
	"time"
)

const apiVersion = "/api/v2"

// Client is the shared HTTP base for both channels.
type Client struct {
	BaseURL string       // APIX origin + "/api/v2"
	APIKey  string       // AutoFin-Api-Key (provisioning channel)
	HTTP    *http.Client
}

// New builds a client. baseURL is the APIX origin (e.g. https://app.automated.finance).
func New(baseURL, apiKey string, timeout time.Duration) *Client {
	return &Client{
		BaseURL: baseURL + apiVersion,
		APIKey:  apiKey,
		HTTP:    &http.Client{Timeout: timeout},
	}
}

package apix

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// PendingSigner is a delegated-candidate system signer awaiting provisioning.
type PendingSigner struct {
	ID        string `json:"id"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"p256_public_key"`
	Status    string `json:"status"`
}

// ListPendingProvisioning returns the account's pending delegated-candidate signers (provisioning
// channel: ApiKeyV2 auth).
func (c *Client) ListPendingProvisioning(ctx context.Context) ([]PendingSigner, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/system_signer_provisioning", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("AutoFin-Api-Key", c.APIKey)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list pending provisioning: %s", resp.Status)
	}

	var envelope struct {
		Data []PendingSigner `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode pending provisioning: %w", err)
	}
	return envelope.Data, nil
}

// FulfillProvisioning posts the generated public key (DER base64) + key_id for a pending signer.
func (c *Client) FulfillProvisioning(ctx context.Context, signerID, publicKeyB64, keyID string) error {
	body, err := json.Marshal(map[string]string{
		"p256_public_key": publicKeyB64,
		"key_id":          keyID,
	})
	if err != nil {
		return fmt.Errorf("marshal provisioning body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/system_signer_provisioning/"+signerID+"/fulfill", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("AutoFin-Api-Key", c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("fulfill provisioning %s: %s", signerID, resp.Status)
	}
	return nil
}

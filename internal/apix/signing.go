package apix

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/0x-Systems-ltda/auto-signer/internal/signer"
)

// PendingSignature is an OperationSignature awaiting fulfillment.
type PendingSignature struct {
	ID      string `json:"id"`
	Payload string `json:"payload"` // the canonical string to sign verbatim (Fulfill verifies over this)
}

// ListPendingSignatures returns the pending OperationSignatures for a signer (signing channel:
// P-256 ECDSA auth via the signer itself).
func (c *Client) ListPendingSignatures(ctx context.Context, keyID string, s signer.Signer) ([]PendingSignature, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/external/"+keyID+"/signatures", nil)
	if err != nil {
		return nil, err
	}
	if err := c.signRequest(ctx, req, nil, s); err != nil {
		return nil, err
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list pending signatures: %s", resp.Status)
	}

	var envelope struct {
		Data []PendingSignature `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode pending signatures: %w", err)
	}
	return envelope.Data, nil
}

// FulfillSignature posts the DER (base64) signature for an OperationSignature. The same signer signs
// the request's X-Signature header, proving the caller holds the matching private key.
func (c *Client) FulfillSignature(ctx context.Context, keyID, opSigID, signatureB64 string, s signer.Signer) error {
	body, err := json.Marshal(map[string]string{"signature": signatureB64})
	if err != nil {
		return fmt.Errorf("marshal signature body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/external/"+keyID+"/signatures/"+opSigID+"/fulfill", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := c.signRequest(ctx, req, body, s); err != nil {
		return err
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("fulfill signature %s: %s", opSigID, resp.Status)
	}
	return nil
}

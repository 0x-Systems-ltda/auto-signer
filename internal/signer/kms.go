package signer

import (
	"context"
	"errors"
)

// ErrAdapterNotWired is returned by scaffold adapters that are documented but not yet implemented.
var ErrAdapterNotWired = errors.New("signer adapter not wired: implement and test before enabling")

// KMSSigner is the non-exportable-custody adapter: the P-256 key lives inside AWS KMS and signing
// happens via the KMS Sign API (MessageType=DIGEST, SigningAlgorithm=ECC_NIST_P256), so the private
// key never leaves KMS. It satisfies Signer exactly like LocalSigner — APIX sees no difference.
//
// SCAFFOLD — not wired this cycle (no config selects it). To enable:
//  1. Add github.com/aws/aws-sdk-go-v2/service/kms.
//  2. Sign(ctx, msg): KMS Sign with KeyID, SigningAlgorithm ECC_NIST_P256, MessageType DIGEST,
//     input = sha256(msg); base64 the DER Signature in the response.
//  3. PublicKeyDERBase64(ctx): KMS GetPublicKey returns DER directly (PublicKey field) — base64 it.
//  4. Add a config selector (CUSTODY=kms + a key ARN map) in config + main to build KMSSigners.
//
// Provisioning under KMS differs too: instead of generating locally, call KMS CreateKey
// (Origin=AWS_KMS, KeySpec=ECC_NIST_P256) + GetPublicKey, and POST that public key to APIX.
type KMSSigner struct {
	KeyID string // KMS key ARN or alias
}

// NewKMSSigner builds the scaffold adapter.
func NewKMSSigner(keyID string) *KMSSigner { return &KMSSigner{KeyID: keyID} }

func (k *KMSSigner) Sign(context.Context, []byte) (string, error) {
	return "", ErrAdapterNotWired
}

func (k *KMSSigner) PublicKeyDERBase64(context.Context) (string, error) {
	return "", ErrAdapterNotWired
}

var _ Signer = (*KMSSigner)(nil)

// Package signer abstracts HOW the auto-signer signs. Two flavors share one interface:
//
//   - LocalSigner: the private key lives in a secretstore.Store and is retrieved to memory to sign
//     (AWS Secrets Manager now; Passbolt / HashiCorp Vault KV later).
//   - KMSSigner (adapter scaffold): the key is non-exportable inside AWS KMS and signing happens via
//     the KMS Sign API — the private key never leaves KMS.
//
// APIX is agnostic to which flavor backs a signer: it only ever sees the public key + the fulfilled
// signatures, so swapping custody is a local concern of the auto-signer ("tudo é interface").
package signer

import "context"

// Signer produces ECDSA-P256 (DER, base64) signatures and exposes its public key in the format
// APIX/Privy register (base64 PKIX DER).
type Signer interface {
	// Sign returns base64(ECDSA-DER over SHA256(message)).
	Sign(ctx context.Context, message []byte) (string, error)
	// PublicKeyDERBase64 returns base64(PKIX DER) of the P-256 public key.
	PublicKeyDERBase64(ctx context.Context) (string, error)
}

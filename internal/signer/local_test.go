package signer

import (
	"context"
	"strings"
	"testing"

	"github.com/0x-Systems-ltda/auto-signer/internal/p256"
	"github.com/0x-Systems-ltda/auto-signer/internal/secretstore"
)

// TestLocalSigner_RoundTrip is the cross-language correctness gate: a signature produced by the
// Go signer must verify against the public key in APIX's wire format (base64 PKIX DER). Ruby's
// ExternalSigner::P256.valid_signature? does the exact same verify, so passing here means the Go
// signature will be accepted by APIX.
func TestLocalSigner_RoundTrip(t *testing.T) {
	store := secretstore.NewMemoryStore()
	ctx := context.Background()

	kp, err := p256.Generate()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	const keyID = "del_test_key"
	if err := store.Put(ctx, keyID, []byte(kp.PrivateKeyDERBase64)); err != nil {
		t.Fatalf("store private key: %v", err)
	}

	s := NewLocalSigner(store, keyID)

	// The public key reconstructed from the custody backend must equal the one we'd return to APIX.
	gotPub, err := s.PublicKeyDERBase64(ctx)
	if err != nil {
		t.Fatalf("PublicKeyDERBase64: %v", err)
	}
	if gotPub != kp.PublicKeyDERBase64 {
		t.Fatalf("public key mismatch: custody-derived %q != generated %q", gotPub, kp.PublicKeyDERBase64)
	}

	for _, msg := range []string{
		"",
		"hello",
		"GET\n/external/del_test_key/signatures\n1700000000\n" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	} {
		sig, err := s.Sign(ctx, []byte(msg))
		if err != nil {
			t.Fatalf("sign %q: %v", msg, err)
		}
		if !p256.Verify(kp.PublicKeyDERBase64, sig, []byte(msg)) {
			t.Fatalf("verify failed for message %q", msg)
		}
	}
}

// TestLocalSigner_MissingKey ensures a missing custody secret surfaces as an error, not a panic.
func TestLocalSigner_MissingKey(t *testing.T) {
	s := NewLocalSigner(secretstore.NewMemoryStore(), "nope")
	_, err := s.Sign(context.Background(), []byte("anything"))
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not-found error, got %v", err)
	}
}

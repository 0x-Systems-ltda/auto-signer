package p256

import (
	"strings"
	"testing"
)

// TestSignVerify_RoundTrip proves Sign then Verify over the wire formats (base64 PKIX public +
// base64 DER signature over SHA256) succeeds, and that a tampered message fails. This is the exact
// pair Ruby ExternalSigner::P256 relies on.
func TestSignVerify_RoundTrip(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	priv, err := ParsePrivate(kp.PrivateKeyDERBase64)
	if err != nil {
		t.Fatalf("parse private: %v", err)
	}

	msg := []byte("the quick brown fox")
	sig, err := Sign(priv, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if !Verify(kp.PublicKeyDERBase64, sig, msg) {
		t.Fatal("Verify rejected a valid signature")
	}
	// Tampered message must fail.
	if Verify(kp.PublicKeyDERBase64, sig, []byte("the quick brown FOX")) {
		t.Fatal("Verify accepted a signature over a different message")
	}

	// Each signature is non-deterministic (random k) yet still verifies.
	sig2, _ := Sign(priv, msg)
	if sig == sig2 {
		t.Fatal("two signatures over the same message were identical (expected randomized k)")
	}
	if !Verify(kp.PublicKeyDERBase64, sig2, msg) {
		t.Fatal("Verify rejected the second valid signature")
	}
}

func TestParsePublic_Invalid(t *testing.T) {
	if _, err := ParsePublic("not-base64!!!"); err == nil {
		t.Fatal("expected error for invalid base64")
	}
	if _, err := ParsePublic("YWJjZA=="); err == nil || !strings.Contains(err.Error(), "parse public key DER") {
		t.Fatalf("expected DER parse error, got %v", err)
	}
}

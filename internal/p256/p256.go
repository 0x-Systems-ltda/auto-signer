// Package p256 provides P-256 (prime256v1 / secp256r1) keypair and signing helpers for the
// auto-signer. Wire formats are chosen to match APIX byte-for-byte:
//
//   - public key:  base64(x509 PKIX DER) — same as Ruby OpenSSL::PKey::EC#public_to_der, which is
//     what SystemSigner#p256_public_key and Privy key_quorum registration expect.
//   - private key: base64(x509 PKCS#8 DER) — the form stored in the custody backend.
//   - signature:   base64(ECDSA DER (ASN.1 r||s) over SHA256) — same as Ruby EC#sign("SHA256", msg)
//     and what ExternalSigner::P256.valid_signature? verifies.
//
// Ruby's Base64.strict_encode64 is standard base64 with no line breaks == Go's base64.StdEncoding.
package p256

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
)

// Keypair holds a generated P-256 keypair in the APIX wire formats.
type Keypair struct {
	PublicKeyDERBase64  string // base64(PKIX DER) — sent to APIX; APIX/Privy register this
	PrivateKeyDERBase64 string // base64(PKCS#8 DER) — stored in the custody backend; never sent
}

// Generate creates a new P-256 keypair.
func Generate() (Keypair, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Keypair{}, fmt.Errorf("generate p256 key: %w", err)
	}
	return encode(priv)
}

// ParsePublic decodes a base64(PKIX DER) P-256 public key.
func ParsePublic(b64 string) (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode public key base64: %w", err)
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse public key DER: %w", err)
	}
	ec, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not ECDSA")
	}
	return ec, nil
}

// ParsePrivate decodes a base64(PKCS#8 DER) P-256 private key.
func ParsePrivate(b64 string) (*ecdsa.PrivateKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode private key base64: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse private key DER: %w", err)
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not ECDSA P-256")
	}
	return ec, nil
}

// Sign returns base64(ECDSA-DER over SHA256(message)) with the given private key.
func Sign(priv *ecdsa.PrivateKey, message []byte) (string, error) {
	digest := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// Verify checks a base64(ECDSA-DER) signature over message against a base64(PKIX DER) public key.
// Mirrors Ruby ExternalSigner::P256.valid_signature? — the cross-language correctness gate.
func Verify(publicKeyDERBase64, signatureBase64 string, message []byte) bool {
	pub, err := ParsePublic(publicKeyDERBase64)
	if err != nil {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(message)
	return ecdsa.VerifyASN1(pub, digest[:], sig)
}

// PublicDERBase64 derives base64(PKIX DER) public key from a base64(PKCS#8 DER) private key.
func PublicDERBase64(privateKeyDERBase64 string) (string, error) {
	priv, err := ParsePrivate(privateKeyDERBase64)
	if err != nil {
		return "", err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pubDER), nil
}

func encode(priv *ecdsa.PrivateKey) (Keypair, error) {
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return Keypair{}, fmt.Errorf("marshal public key: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return Keypair{}, fmt.Errorf("marshal private key: %w", err)
	}
	return Keypair{
		PublicKeyDERBase64:  base64.StdEncoding.EncodeToString(pubDER),
		PrivateKeyDERBase64: base64.StdEncoding.EncodeToString(privDER),
	}, nil
}

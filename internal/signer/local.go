package signer

import (
	"context"
	"fmt"

	"github.com/0x-Systems-ltda/auto-signer/internal/p256"
	"github.com/0x-Systems-ltda/auto-signer/internal/secretstore"
)

// LocalSigner retrieves the P-256 private key from a secretstore.Store and signs in-process. The key
// is fetched per call (never cached on disk) so it is only transiently in memory.
type LocalSigner struct {
	store secretstore.Store
	keyID string // the APIX key_id; also used as the secret name
}

// NewLocalSigner builds a retrieve-and-sign signer backed by store.
func NewLocalSigner(store secretstore.Store, keyID string) *LocalSigner {
	return &LocalSigner{store: store, keyID: keyID}
}

func (l *LocalSigner) Sign(ctx context.Context, message []byte) (string, error) {
	raw, err := l.store.Get(ctx, l.keyID)
	if err != nil {
		return "", fmt.Errorf("retrieve key %s: %w", l.keyID, err)
	}
	priv, err := p256.ParsePrivate(string(raw))
	if err != nil {
		return "", err
	}
	return p256.Sign(priv, message)
}

func (l *LocalSigner) PublicKeyDERBase64(ctx context.Context) (string, error) {
	raw, err := l.store.Get(ctx, l.keyID)
	if err != nil {
		return "", fmt.Errorf("retrieve key %s: %w", l.keyID, err)
	}
	return p256.PublicDERBase64(string(raw))
}

var _ Signer = (*LocalSigner)(nil)

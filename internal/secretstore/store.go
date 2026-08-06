// Package secretstore abstracts WHERE the auto-signer's private keys live. The default backend is
// AWS Secrets Manager (retrieve-and-sign-locally); Passbolt / HashiCorp Vault KV are future
// adapters behind the same interface. The key is fetched to the auto-signer's memory at sign time
// and never persisted to disk by the auto-signer itself.
package secretstore

import (
	"context"
	"errors"
	"fmt"
)

// ErrNotFound is returned by Get when no secret exists for the given name.
var ErrNotFound = errors.New("secret not found")

// Store is the pluggable custody backend for P-256 private keys (base64 PKCS#8 DER values).
// The secret name is the APIX key_id (prefixed by the backend implementation, e.g. "apix/signers/").
type Store interface {
	// Get returns the secret value for name, or ErrNotFound if none exists.
	Get(ctx context.Context, name string) ([]byte, error)
	// Put stores value under name, creating or replacing it (idempotent).
	Put(ctx context.Context, name string, value []byte) error
	// Delete removes the secret for name. Idempotent: a missing secret is not an error. Used by the
	// poller to clean up an orphaned custody secret when provisioning fails after the Put.
	Delete(ctx context.Context, name string) error
}

// MemoryStore is an in-process Store for tests and local runs.
type MemoryStore struct {
	data map[string][]byte
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore { return &MemoryStore{data: make(map[string][]byte)} }

func (m *MemoryStore) Get(_ context.Context, name string) ([]byte, error) {
	v, ok := m.data[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNotFound, name)
	}
	return v, nil
}

func (m *MemoryStore) Put(_ context.Context, name string, value []byte) error {
	m.data[name] = append([]byte(nil), value...)
	return nil
}

func (m *MemoryStore) Delete(_ context.Context, name string) error {
	delete(m.data, name)
	return nil
}

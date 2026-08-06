package secretstore

import (
	"context"
	"errors"
	"testing"
)

// Exercise the Store contract on MemoryStore (the in-process backend). The contract backs the
// poller's custody-first provisioning: Put the private key, Get it at sign time, and Delete it when
// provisioning fails so orphan secrets don't accumulate. SecretsManagerStore is the same contract
// against the real SDK (exercised via Localstack in the compose smoke), not unit-tested here.
func TestMemoryStoreContract(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	const name = "apix/signers/del_deadbeef"

	// Get before Put → ErrNotFound (wrapped, detectable via errors.Is).
	if _, err := s.Get(ctx, name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get on missing secret: want ErrNotFound, got %v", err)
	}

	// Put → Get round-trips the exact bytes.
	want := []byte("base64-private-key-material")
	if err := s.Put(ctx, name, want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(ctx, name)
	if err != nil {
		t.Fatalf("Get after Put: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("Get round-trip: got %q, want %q", got, want)
	}

	// Put is idempotent (replace).
	if err := s.Put(ctx, name, []byte("rotated")); err != nil {
		t.Fatalf("Put replace: %v", err)
	}
	got, _ = s.Get(ctx, name)
	if string(got) != "rotated" {
		t.Fatalf("Put replace: got %q, want %q", got, "rotated")
	}

	// Delete removes the secret.
	if err := s.Delete(ctx, name); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete: want ErrNotFound, got %v", err)
	}

	// Delete is idempotent — a missing secret is NOT an error (the poller relies on this to clean up
	// an orphan without racing a concurrent delete).
	if err := s.Delete(ctx, name); err != nil {
		t.Fatalf("Delete on missing secret: want nil (idempotent), got %v", err)
	}
}

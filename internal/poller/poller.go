// Package poller drives the two auto-signer jobs on independent tickers: provisioning (generate +
// store + return public key for pending delegated signers) and signing (fulfill pending
// OperationSignatures for signers this instance backs). Both are idempotent and poll-only (no push).
package poller

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"sync"
	"time"

	"github.com/0x-Systems-ltda/auto-signer/internal/apix"
	"github.com/0x-Systems-ltda/auto-signer/internal/p256"
	"github.com/0x-Systems-ltda/auto-signer/internal/secretstore"
	"github.com/0x-Systems-ltda/auto-signer/internal/signer"
)

// Poller runs the provisioning and signing loops until ctx is cancelled.
type Poller struct {
	client          *apix.Client
	store           secretstore.Store
	log             *slog.Logger
	provisionEvery  time.Duration
	signEvery       time.Duration

	mu      sync.Mutex
	watched map[string]struct{} // key_ids this instance backs (provisioned + config-supplied)
}

// New builds a poller. watched seeds the sign loop with pre-existing key_ids.
func New(client *apix.Client, store secretstore.Store, provisionEvery, signEvery time.Duration, watched []string, log *slog.Logger) *Poller {
	m := make(map[string]struct{}, len(watched))
	for _, k := range watched {
		m[k] = struct{}{}
	}
	return &Poller{
		client:         client,
		store:          store,
		log:            log,
		provisionEvery: provisionEvery,
		signEvery:      signEvery,
		watched:        m,
	}
}

// Run blocks until ctx is cancelled, running both loops concurrently.
func (p *Poller) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); p.loop(ctx, p.provisionEvery, p.provision) }()
	go func() { defer wg.Done(); p.loop(ctx, p.signEvery, p.sign) }()
	wg.Wait()
}

func (p *Poller) loop(ctx context.Context, every time.Duration, job func(context.Context)) {
	t := time.NewTicker(every)
	defer t.Stop()
	job(ctx) // run once immediately
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			job(ctx)
		}
	}
}

// provision: list pending delegated candidates → generate key, store private (custody FIRST), return
// public only. Custody-before-register preserves the signing contract — APIX never sees an active
// signer the auto-signer can't yet fulfill. If fulfill then fails, the just-stored private key is
// deleted so random orphan secrets don't accumulate: this key_id was never returned to any caller, so
// the material is safe to drop and a fresh keypair is generated on the next poll.
func (p *Poller) provision(ctx context.Context) {
	pending, err := p.client.ListPendingProvisioning(ctx)
	if err != nil {
		p.log.Warn("provisioning poll failed", "error", err)
		return
	}
	for _, ps := range pending {
		if err := ctx.Err(); err != nil {
			p.log.Info("provisioning cancelled mid-batch", "error", err)
			return
		}
		kp, err := p256.Generate()
		if err != nil {
			p.log.Error("generate keypair", "signer_id", ps.ID, "error", err)
			continue
		}
		keyID := newKeyID()
		if err := p.store.Put(ctx, keyID, []byte(kp.PrivateKeyDERBase64)); err != nil {
			p.log.Error("store private key", "key_id", keyID, "error", err)
			continue
		}
		if err := p.client.FulfillProvisioning(ctx, ps.ID, kp.PublicKeyDERBase64, keyID); err != nil {
			// The public key was never registered at APIX (the common 4xx/5xx/network case). Remove the
			// custody secret so it doesn't leak as an unreferenced orphan — the random key_id was never
			// handed to any caller, so the private material is safe to delete.
			if delErr := p.store.Delete(ctx, keyID); delErr != nil {
				p.log.Warn("cleanup orphaned custody secret after failed fulfill", "key_id", keyID, "error", delErr)
			}
			p.log.Error("fulfill provisioning", "signer_id", ps.ID, "error", err)
			continue
		}
		p.watch(keyID)
		p.log.Info("provisioned delegated signer", "signer_id", ps.ID, "key_id", keyID)
	}
}

// sign: for each watched signer, fulfill pending OperationSignatures.
func (p *Poller) sign(ctx context.Context) {
	for _, keyID := range p.watchedSnapshot() {
		if err := ctx.Err(); err != nil {
			p.log.Info("signing cancelled mid-batch", "error", err)
			return
		}
		s := signer.NewLocalSigner(p.store, keyID)

		pending, err := p.client.ListPendingSignatures(ctx, keyID, s)
		if err != nil {
			p.log.Warn("signing poll failed", "key_id", keyID, "error", err)
			continue
		}
		for _, os := range pending {
			if err := ctx.Err(); err != nil {
				p.log.Info("signing cancelled mid-batch", "error", err)
				return
			}
			// The payload is signed verbatim — ExternalSigner::Fulfill verifies over this exact string.
			sig, err := s.Sign(ctx, []byte(os.Payload))
			if err != nil {
				p.log.Error("sign payload", "key_id", keyID, "opsig_id", os.ID, "error", err)
				continue
			}
			if err := p.client.FulfillSignature(ctx, keyID, os.ID, sig, s); err != nil {
				p.log.Error("fulfill signature", "opsig_id", os.ID, "error", err)
				continue
			}
			p.log.Info("fulfilled signature", "key_id", keyID, "opsig_id", os.ID)
		}
	}
}

func (p *Poller) watch(keyID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.watched[keyID] = struct{}{}
}

func (p *Poller) watchedSnapshot() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.watched))
	for k := range p.watched {
		out = append(out, k)
	}
	return out
}

func newKeyID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "del_" + hex.EncodeToString(b)
}

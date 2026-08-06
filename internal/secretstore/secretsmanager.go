package secretstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

// SecretsManagerStore backs keys in AWS Secrets Manager. Point it at Localstack in dev by setting
// AWS_ENDPOINT_URL (resolved by the SDK config loader in main).
type SecretsManagerStore struct {
	client       *secretsmanager.Client
	secretPrefix string // e.g. "apix/signers/" — the full secret id is prefix + key_id
}

// NewSecretsManagerStore builds a store. secretPrefix defaults to "apix/signers/".
func NewSecretsManagerStore(client *secretsmanager.Client, secretPrefix string) *SecretsManagerStore {
	return &SecretsManagerStore{client: client, secretPrefix: secretPrefix}
}

func (s *SecretsManagerStore) Get(ctx context.Context, name string) ([]byte, error) {
	out, err := s.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(s.secretPrefix + name),
	})
	if err != nil {
		var nf *types.ResourceNotFoundException
		if errors.As(err, &nf) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
		}
		return nil, fmt.Errorf("get secret %s: %w", name, err)
	}
	if out.SecretString == nil {
		return nil, fmt.Errorf("secret %s has no string value", name)
	}
	return []byte(*out.SecretString), nil
}

// Put is idempotent: it updates an existing secret, or creates it if absent.
//
// NOTE: under concurrent callers for the SAME name — only possible in an HA multi-instance
// deployment; the README prescribes one auto-signer instance per customer — the Update→Create
// fallback has a TOCTOU race: two callers can both see ResourceNotFound and both Create, one losing
// with ResourceExistsException. The single-instance deployment model is safe; revisit if HA is ever
// enabled (e.g. create-or-update with a retry on ResourceExists).
func (s *SecretsManagerStore) Put(ctx context.Context, name string, value []byte) error {
	id := s.secretPrefix + name
	val := aws.String(string(value))

	if _, err := s.client.UpdateSecret(ctx, &secretsmanager.UpdateSecretInput{
		SecretId:     aws.String(id),
		SecretString: val,
	}); err == nil {
		return nil
	} else {
		var nf *types.ResourceNotFoundException
		if !errors.As(err, &nf) {
			return fmt.Errorf("update secret %s: %w", name, err)
		}
	}

	if _, err := s.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
		Name:         aws.String(id),
		SecretString: val,
	}); err != nil {
		return fmt.Errorf("create secret %s: %w", name, err)
	}
	return nil
}

// Delete removes a secret. Idempotent: a missing secret is not an error. ForceDeleteWithoutRecovery
// is set because auto-signer secrets are disposable random key material, not audit-relevant state.
func (s *SecretsManagerStore) Delete(ctx context.Context, name string) error {
	_, err := s.client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{
		SecretId:                   aws.String(s.secretPrefix + name),
		ForceDeleteWithoutRecovery: aws.Bool(true),
	})
	if err != nil {
		var nf *types.ResourceNotFoundException
		if errors.As(err, &nf) {
			return nil // already gone — idempotent
		}
		return fmt.Errorf("delete secret %s: %w", name, err)
	}
	return nil
}

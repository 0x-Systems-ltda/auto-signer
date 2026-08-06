// auto-signer is the reference implementation of an APIX external signer, automated and backed by
// a custody backend (AWS Secrets Manager by default). It owns the P-256 private keys APIX never
// sees, fulfills provisioning requests (returns only the public key) and signing requests (signs
// inside this process), over APIX's two HTTP channels. Poll-only — no push/webhook.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/0x-Systems-ltda/auto-signer/internal/apix"
	"github.com/0x-Systems-ltda/auto-signer/internal/config"
	"github.com/0x-Systems-ltda/auto-signer/internal/poller"
	"github.com/0x-Systems-ltda/auto-signer/internal/secretstore"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		log.Error("invalid config", "error", err)
		os.Exit(1)
	}

	awsCfg, err := buildAWSConfig(ctx, cfg)
	if err != nil {
		log.Error("aws config", "error", err)
		os.Exit(1)
	}
	store := secretstore.NewSecretsManagerStore(secretsmanager.NewFromConfig(awsCfg), cfg.SecretPrefix)
	client := apix.New(cfg.APIXBaseURL, cfg.APIKey, cfg.HTTPTimeout)
	p := poller.New(client, store, cfg.ProvisionInterval, cfg.SignInterval, cfg.WatchedKeyIDs, log)

	log.Info("auto-signer started",
		"apix", cfg.APIXBaseURL, "prefix", cfg.SecretPrefix,
		"endpoint", cfg.AWSEndpointURL, "watched", cfg.WatchedKeyIDs)
	p.Run(ctx)
	log.Info("auto-signer stopped")
}

// buildAWSConfig returns real AWS config in production, or a Localstack-pointed config in dev
// (AWS_ENDPOINT_URL set → static test creds + base endpoint override).
func buildAWSConfig(ctx context.Context, cfg config.Config) (aws.Config, error) {
	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(cfg.AWSRegion),
	}
	if cfg.AWSEndpointURL != "" {
		opts = append(opts,
			awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
			awsconfig.WithBaseEndpoint(cfg.AWSEndpointURL),
		)
	}
	return awsconfig.LoadDefaultConfig(ctx, opts...)
}

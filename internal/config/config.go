// Package config loads auto-signer configuration from the environment.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all runtime configuration.
type Config struct {
	APIXBaseURL    string
	APIKey         string // AutoFin-Api-Key (provisioning channel)
	SecretPrefix   string // Secrets Manager secret prefix (default apix/signers/)
	AWSRegion      string
	AWSEndpointURL string // Localstack in dev; empty for real AWS

	ProvisionInterval time.Duration
	SignInterval      time.Duration
	HTTPTimeout       time.Duration

	// WatchedKeyIDs are signer key_ids to sign for (config-supplied), in addition to any this
	// instance provisions itself.
	WatchedKeyIDs []string
}

// Load reads and validates configuration from the environment.
func Load() (Config, error) {
	c := Config{
		SecretPrefix:      envOr("SECRET_PREFIX", "apix/signers/"),
		AWSRegion:         envOr("AWS_REGION", "us-east-1"),
		AWSEndpointURL:    strings.TrimSpace(os.Getenv("AWS_ENDPOINT_URL")),
		ProvisionInterval: envDur("PROVISION_INTERVAL", 5*time.Second),
		SignInterval:      envDur("SIGN_INTERVAL", 2*time.Second),
		HTTPTimeout:       envDur("HTTP_TIMEOUT", 15*time.Second),
		WatchedKeyIDs:     parseList(os.Getenv("WATCHED_KEY_IDS")),
	}

	baseURL, err := require("APIX_BASE_URL")
	if err != nil {
		return c, err
	}
	c.APIXBaseURL = baseURL

	apiKey, err := require("AUTOFIN_API_KEY")
	if err != nil {
		return c, err
	}
	c.APIKey = apiKey

	// Durations feed time.NewTicker, which PANICS on a non-positive interval. A benign config typo
	// (PROVISION_INTERVAL=0, a negative value, or a unit-less "200" read as seconds) must fail fast
	// here with a clear message rather than crash-looping the pod at startup.
	for _, d := range []struct{ name string; val time.Duration }{
		{"PROVISION_INTERVAL", c.ProvisionInterval},
		{"SIGN_INTERVAL", c.SignInterval},
		{"HTTP_TIMEOUT", c.HTTPTimeout},
	} {
		if d.val <= 0 {
			return c, fmt.Errorf("env %s must be a positive duration, got %v", d.name, d.val)
		}
	}

	return c, nil
}

func require(key string) (string, error) {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("env %s is required", key)
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// envDur accepts a plain number (seconds) or a Go duration string (e.g. "5s", "200ms").
func envDur(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	if sec, err := strconv.ParseFloat(v, 64); err == nil {
		return time.Duration(sec * float64(time.Second))
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	return def
}

func parseList(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

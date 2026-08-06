package apix

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/0x-Systems-ltda/auto-signer/internal/signer"
)

// signRequest attaches the P-256 ECDSA request signature for the external-signer (signing) channel.
// CANONICAL = "METHOD\nPATH\nTIMESTAMP\nHEX(SHA256(body))" — matches ExternalSignerAuth exactly.
// X-Timestamp = unix seconds; X-Signature = base64(ECDSA-DER over SHA256(canonical)).
//
// For GET requests body is nil → SHA256("") (Ruby request.raw_post is "" for a bodyless GET).
func (c *Client) signRequest(ctx context.Context, req *http.Request, body []byte, s signer.Signer) error {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	digest := sha256.Sum256(body)
	canonical := fmt.Sprintf("%s\n%s\n%s\n%s", req.Method, req.URL.Path, ts, hex.EncodeToString(digest[:]))

	sig, err := s.Sign(ctx, []byte(canonical))
	if err != nil {
		return fmt.Errorf("sign request: %w", err)
	}
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Signature", sig)
	return nil
}

# auto-signer

Reference implementation of an **APIX external signer, automated and self-hosted**, backed by a
custody backend (AWS Secrets Manager by default).

APIX never sees a system signer's private key. Instead, this service **owns** the keys, fulfills
two kinds of requests over APIX's existing HTTP channels, and signs in-process:

1. **Provisioning** — APIX creates a *pending* system signer (no key); the auto-signer generates the
   P-256 keypair, stores the **private** key in custody, and returns **only the public key** to APIX.
2. **Signing** — APIX records a pending `OperationSignature` for an automation; the auto-signer polls
   it, signs the payload with the custody-backed key, and posts the signature back.

It is **poll-only** — no webhooks, no push, no inbound port. Just two outbound HTTP loops.

> This is *our* external signer. APIX treats it exactly like a user-supplied external signer (same
> `OperationSignature` fulfill path, same P-256 ECDSA request auth) — the only difference is that the
> key was generated here during provisioning instead of supplied by a human.

---

## Architecture

```
                ┌─────────────────────── APIX (Rails) ───────────────────────┐
                │                                                            │
   provision    │  SystemSigner (delegated candidate, status: pending)        │
   channel ─────┼─▶ GET  /system_signer_provisioning          (AutoFin-Api-Key)│
   (ApiKeyV2)   │  POST /system_signer_provisioning/:id/fulfill               │
                │       { p256_public_key, key_id }  ◀── public key only      │
                │                                                            │
   signing      │  OperationSignature (pending)                              │
   channel ─────┼─▶ GET  /external/:key_id/signatures        (P-256 ECDSA)    │
   (P-256)      │  POST /external/:key_id/signatures/:id/fulfill              │
                │       { signature }                                          │
                └────────────────────────────────────────────────────────────┘
                                         ▲ HTTP poll
                                         │
                ┌──────────────────── auto-signer (this service) ────────────┐
                │  provision loop:  list pending → generate → store → fulfill │
                │  signing loop:    per watched key_id → list → sign → fulfill│
                │                                                            │
                │  Signer interface ──┬── LocalSigner (retrieve + sign here)  │
                │                     └── KMSSigner   (sign-inside, future)   │
                │  SecretStore iface ─┬── SecretsManagerStore (default)       │
                │                     └── MemoryStore (tests)                 │
                └────────────────────────────┬───────────────────────────────┘
                                             │ Get/Put (private key, base64 PKCS#8)
                                             ▼
                                  AWS Secrets Manager  (Passbolt/KMS: future)
```

### Two interfaces, by design

The custody side is pluggable so other backends drop in without touching the poller or APIX:

- **`secretstore.Store`** — `Get(ctx, name) ([]byte, error)` / `Put(ctx, name, value) error`.
  Default: `SecretsManagerStore`. `MemoryStore` for tests. Future: Passbolt, Vault KV.
- **`signer.Signer`** — `Sign(ctx, message) (string, error)` / `PublicKeyDERBase64(ctx) (string, error)`.
  Default: `LocalSigner` (retrieve key from store, sign in-process). `KMSSigner` is a scaffold for a
  future **AWS KMS asymmetric** adapter that signs *inside* KMS (non-exportable key) — it would
  implement `Signer` and be selected at config time, with no changes to the poller or APIX.

> The retrieve-and-sign-locally model (Secrets Manager) means the private key is transiently in this
> process's memory at sign time. A KMS asymmetric adapter would avoid even that by signing inside KMS.

### Wire formats (byte-compatible with Ruby APIX)

| Value        | Format                                            | Ruby equivalent                       |
|--------------|---------------------------------------------------|---------------------------------------|
| public key   | base64(x509 PKIX DER)                             | `EC#public_to_der` → `strict_encode64`|
| private key  | base64(x509 PKCS#8 DER)                           | stored in custody backend             |
| signature    | base64(ECDSA-DER over SHA256(message))            | `EC#sign("SHA256", msg)`              |
| request auth | `X-Signature` = base64(ECDSA-DER over SHA256(canonical)) over `METHOD\nPATH\nTIMESTAMP\nHEX(SHA256(body))` | `ExternalSignerAuth` |

Go `base64.StdEncoding` == Ruby `Base64.strict_encode64`; `ecdsa.SignASN1` over `sha256` == Ruby
`EC#sign("SHA256", …)`. The `p256` + `signer` tests assert the round-trip that proves it.

---

## Run locally (Localstack)

```bash
cp .env.example .env
# edit .env: APIX_BASE_URL (your APIX), AUTOFIN_API_KEY (account-scoped API Key V2)

docker compose up --build      # auto-signer + Localstack (Secrets Manager mock)
```

Logs are JSON to stdout. On first provisioned signer you'll see
`provisioned delegated signer signer_id=… key_id=del_…`; on each fulfilled signature
`fulfilled signature key_id=… opsig_id=…`.

> On the APIX side, the account must have the `auto_signer_custody` Flipper feature enabled so that
> `Steps::SystemSigner::FindOrCreate` creates **delegated candidates** (pending, no key) instead of
> the legacy server-side-generated signers.

## Run in production (real AWS)

```bash
export APIX_BASE_URL=https://app.automated.finance
export AUTOFIN_API_KEY=af_live_…
export AWS_REGION=us-east-1
# AWS_ENDPOINT_URL must be UNSET for real AWS; auth via the SDK's default chain
# (IAM role / env AWS_ACCESS_KEY_ID+AWS_SECRET_ACCESS_KEY / etc.)
unset AWS_ENDPOINT_URL

docker compose run --rm auto-signer   # or deploy the image + env your usual way
```

### IAM

The role the auto-signer assumes needs, scoped to `SECRET_PREFIX`:

```json
{ "Version": "2012-10-17", "Statement": [{
  "Effect": "Allow",
  "Action": ["secretsmanager:CreateSecret","secretsmanager:UpdateSecret","secretsmanager:GetSecretValue"],
  "Resource": "arn:aws:secretsmanager:*:*:secret:apix/signers/*"
}] }
```

---

## Build & test (no Docker)

```bash
go build ./...
go test  ./...      # p256 + signer round-trip (the cross-language correctness gate)
go vet   ./...
```

---

## Layout

```
auto-signer/
├── cmd/auto-signer/        # entrypoint: load config, wire AWS + store + client + poller, run
└── internal/
    ├── p256/               # P-256 keypair/sign/verify in APIX wire formats
    ├── signer/             # Signer interface + LocalSigner (now), KMSSigner (scaffold)
    ├── secretstore/        # Store interface + SecretsManagerStore (default), MemoryStore
    ├── apix/               # HTTP clients: provisioning (ApiKeyV2) + signing (P-256 ECDSA)
    ├── poller/             # the two tick loops (idempotent, poll-only)
    └── config/             # env config
```

## What APIX sees (and doesn't)

APIX only ever observes: a pending delegated candidate → `p256_public_key` + `key_id` appear → the
signer goes `active` → subsequent `OperationSignature`s get fulfilled with valid P-256 signatures.
The private key, the custody backend, and this service's existence are all outside APIX's trust
boundary. The `delegated?` discriminator on `SystemSigner` (public key + key_id present, private key
absent) is what routes signing through this service instead of the legacy server-side path.

---

## Submodule setup (one-time, in the APIX repo)

```bash
# from APIX repo root
git submodule add git@github.com:0x-Systems-ltda/auto-signer.git auto-signer
git commit -m "chore: add auto-signer submodule"
```

This scaffold lives at `auto-signer/` in the APIX working tree; `git push` from within `auto-signer/`
publishes the service to its own repository.

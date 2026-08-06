# syntax=docker/dockerfile:1
# Multi-stage build for the auto-signer. The runtime image is distroless static (no shell, no
# package manager) — the auto-signer holds private keys in memory at sign time, so a minimal
# attack surface matters.

# ---- build stage ----
FROM golang:1.25-alpine AS build
WORKDIR /src
# Cache deps before copying source.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Static binary (pure-Go AWS SDK → no CGO). Trimpath strips local paths from the binary.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath -ldflags="-s -w" \
    -o /out/auto-signer ./cmd/auto-signer

# ---- runtime stage ----
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/auto-signer /auto-signer
# nonroot uid 65532; the binary reads only env + outbound HTTP.
USER nonroot:nonroot
ENTRYPOINT ["/auto-signer"]

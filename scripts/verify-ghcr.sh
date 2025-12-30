#!/usr/bin/env bash
set -euo pipefail

# Verify a GHCR image signature and CycloneDX attestation using cosign
# Usage:
#   scripts/verify-ghcr.sh ghcr.io/<owner>/infamous-freight-enterprises-<service>@<digest>
# Example:
#   scripts/verify-ghcr.sh ghcr.io/mrmiless44/infamous-freight-enterprises-api@sha256:abcd...

IMAGE_REF=${1:-}

if [[ -z "$IMAGE_REF" ]]; then
  echo "Usage: $0 ghcr.io/<owner>/infamous-freight-enterprises-<service>@<digest>" >&2
  exit 1
fi

if ! command -v cosign >/dev/null 2>&1; then
  echo "cosign not found. Install from https://github.com/sigstore/cosign/releases" >&2
  exit 2
fi

export COSIGN_EXPERIMENTAL=true

ISSUER=${COSIGN_OIDC_ISSUER:-"https://token.actions.githubusercontent.com"}
IDENTITY=${COSIGN_IDENTITY:-"https://github.com/${GITHUB_REPOSITORY:-MrMiless44/Infamous-freight-enterprises}/.github/workflows/docker-ghcr.yml@refs/heads/main"}

echo "Verifying signature for $IMAGE_REF"
cosign verify \
  --certificate-oidc-issuer "$ISSUER" \
  --certificate-identity "$IDENTITY" \
  "$IMAGE_REF"

echo "Verifying CycloneDX attestation for $IMAGE_REF"
cosign verify-attestation \
  --type cyclonedx \
  --certificate-oidc-issuer "$ISSUER" \
  --certificate-identity "$IDENTITY" \
  "$IMAGE_REF"

echo "✔ Verification successful"
